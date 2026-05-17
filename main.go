//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"syscall/js"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/vtun"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/wgo/device"
	"golang.org/x/crypto/curve25519"
)

type app struct {
	mu sync.Mutex

	vt       *vtun.VTun
	dev      *device.Device
	httpc    *http.Client
	server   *http.Server
	serverLn net.Listener

	localAddr netip.Addr
	proxyURL  string
	network   *recordingNetwork
}

type connectConfig struct {
	ProxyURL         string `json:"proxyUrl"`
	LocalTunnelAddr  string `json:"localTunnelAddr"`
	LocalPrivateKey  string `json:"localPrivateKey"`
	ListenPort       uint16 `json:"listenPort"`
	PeerPublicKey    string `json:"peerPublicKey"`
	PeerPresharedKey string `json:"peerPresharedKey"`
	PeerEndpoint     string `json:"peerEndpoint"`
	PeerAllowedIPs   string `json:"peerAllowedIPs"`
	PeerKeepalive    uint16 `json:"peerKeepalive"`
}

type responseState struct {
	Message           string   `json:"message"`
	LocalTunnelAddr   string   `json:"localTunnelAddr"`
	LocalPrivateKey   string   `json:"localPrivateKey"`
	LocalPublicKey    string   `json:"localPublicKey"`
	ListenPort        uint16   `json:"listenPort"`
	AdvertisedUDP     string   `json:"advertisedUdp"`
	SuggestedEndpoint string   `json:"suggestedEndpoint"`
	ProxyURL          string   `json:"proxyUrl"`
	PeerConfigured    bool     `json:"peerConfigured"`
	PeerEndpoint      string   `json:"peerEndpoint"`
	PeerAllowedIPs    []string `json:"peerAllowedIps"`
	ServerURL         string   `json:"serverUrl"`
}

type noisePrivateKey [32]byte
type noisePublicKey [32]byte
type noisePresharedKey [32]byte

func main() {
	instance := &app{}
	logLine("wasm", "initializing bindings")
	js.Global().Set("wgDemoConnect", promiseFunc(instance.connect))
	js.Global().Set("wgDemoDisconnect", promiseFunc(instance.disconnectJS))
	js.Global().Set("wgDemoGenerateKeys", promiseFunc(instance.generateKeys))
	js.Global().Set("wgDemoDerivePublicKey", promiseFunc(instance.derivePublicKey))
	js.Global().Set("wgDemoRequest", promiseFunc(instance.request))
	js.Global().Set("wgDemoStartServer", promiseFunc(instance.startServer))
	js.Global().Set("wgDemoStopServer", promiseFunc(instance.stopServerJS))
	js.Global().Set("wgDemoGetState", promiseFunc(instance.getState))
	logLine("wasm", "bindings ready")
	select {}
}

func promiseFunc(fn func(args []js.Value) (any, error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		handler := js.FuncOf(func(this js.Value, promiseArgs []js.Value) any {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				result, err := fn(args)
				if err != nil {
					logLine("error", err.Error())
					reject.Invoke(err.Error())
					return
				}
				resolve.Invoke(result)
			}()

			return nil
		})

		promise := js.Global().Get("Promise").New(handler)
		handler.Release()
		return promise
	})
}

func (a *app) connect(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("expected single JSON config argument")
	}

	var cfg connectConfig
	if err := json.Unmarshal([]byte(args[0].String()), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.ProxyURL) == "" {
		return nil, fmt.Errorf("proxy url is required")
	}
	cfg.ProxyURL = normalizeProxyURL(strings.TrimSpace(cfg.ProxyURL))

	localAddr, err := parseAddrDefault(strings.TrimSpace(cfg.LocalTunnelAddr), "10.44.0.1")
	if err != nil {
		return nil, fmt.Errorf("parse local tunnel addr: %w", err)
	}

	privateKey, generated, err := parseOrGeneratePrivateKey(strings.TrimSpace(cfg.LocalPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse local private key: %w", err)
	}
	publicKey, err := privateKey.publicKey()
	if err != nil {
		return nil, fmt.Errorf("derive local public key: %w", err)
	}

	allowedIPs, err := parseAllowedIPs(cfg.PeerAllowedIPs)
	if err != nil {
		return nil, err
	}

	var peerPublic noisePublicKey
	peerConfigured := strings.TrimSpace(cfg.PeerPublicKey) != ""
	if peerConfigured {
		peerPublic, err = parsePublicKey(strings.TrimSpace(cfg.PeerPublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse peer public key: %w", err)
		}
	}

	var peerPSK noisePresharedKey
	hasPSK := strings.TrimSpace(cfg.PeerPresharedKey) != ""
	if hasPSK {
		peerPSK, err = parsePresharedKey(strings.TrimSpace(cfg.PeerPresharedKey))
		if err != nil {
			return nil, fmt.Errorf("parse peer preshared key: %w", err)
		}
	}

	logLine("app", "restarting node")
	a.disconnectLocked()

	client, err := socksgo.ClientFromURL(cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("build socks client: %w", err)
	}
	client.Filter = nil

	network := newRecordingNetwork(client)

	vt, err := (&vtun.Opts{
		LocalAddrs:     []netip.Addr{localAddr},
		NoLoopbackAddr: true,
		Name:           "wg-web-demo",
	}).Build()
	if err != nil {
		return nil, fmt.Errorf("build vtun: %w", err)
	}
	select {
	case event := <-vt.Events():
		logLine("vtun", fmt.Sprintf("event=%d", event))
	case <-time.After(3 * time.Second):
		_ = vt.Close()
		return nil, fmt.Errorf("timed out waiting for vtun readiness")
	}

	bind := newLoggingBind("socks-bind", conn.NewDefaultBind(network))
	tunDev := newLoggingTUN("vtun", vt)
	logger := &deviceLogSink{prefix: "wg"}
	dev := device.NewDevice(tunDev, bind, logger)

	if err := dev.SetPrivateKey(privateKey.toDevice()); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("set private key: %w", err)
	}
	if err := dev.SetListenPort(cfg.ListenPort); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("set listen port: %w", err)
	}
	dev.RemoveAllPeers()
	if peerConfigured {
		if _, err := dev.NewPeer(peerPublic.toDevice()); err != nil {
			dev.Close()
			_ = vt.Close()
			return nil, fmt.Errorf("add peer: %w", err)
		}
		if err := dev.SetPeerProtocolVersion(peerPublic.toDevice(), 1); err != nil {
			dev.Close()
			_ = vt.Close()
			return nil, fmt.Errorf("set peer protocol version: %w", err)
		}
		if hasPSK {
			if err := dev.SetPeerPresharedKey(peerPublic.toDevice(), peerPSK.toDevice()); err != nil {
				dev.Close()
				_ = vt.Close()
				return nil, fmt.Errorf("set peer preshared key: %w", err)
			}
		}
		if len(allowedIPs) > 0 {
			if err := dev.ReplacePeerAllowedIPs(peerPublic.toDevice(), allowedIPs); err != nil {
				dev.Close()
				_ = vt.Close()
				return nil, fmt.Errorf("set peer allowed ips: %w", err)
			}
		}
		if strings.TrimSpace(cfg.PeerEndpoint) != "" {
			if err := dev.SetPeerEndpoint(peerPublic.toDevice(), strings.TrimSpace(cfg.PeerEndpoint)); err != nil {
				dev.Close()
				_ = vt.Close()
				return nil, fmt.Errorf("set peer endpoint: %w", err)
			}
		}
		if cfg.PeerKeepalive > 0 {
			if err := dev.SetPeerPersistentKeepaliveInterval(peerPublic.toDevice(), cfg.PeerKeepalive); err != nil {
				dev.Close()
				_ = vt.Close()
				return nil, fmt.Errorf("set peer keepalive: %w", err)
			}
		}
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}

	httpc := &http.Client{
		Transport: &http.Transport{
			DialContext:       vt.Dial,
			DisableKeepAlives: true,
		},
		Timeout: 30 * time.Second,
	}

	a.mu.Lock()
	a.vt = vt
	a.dev = dev
	a.httpc = httpc
	a.localAddr = localAddr
	a.proxyURL = cfg.ProxyURL
	a.network = network
	a.mu.Unlock()

	state := a.currentStateLocked(privateKey, publicKey, cfg.PeerEndpoint, allowedIPs)
	if generated {
		state.Message = "WireGuard node started with generated keypair"
	} else {
		state.Message = "WireGuard node started"
	}
	logLine(
		"app",
		fmt.Sprintf(
			"node up local_ip=%s listen_port=%d advertised_udp=%q peer_configured=%t",
			localAddr,
			state.ListenPort,
			state.AdvertisedUDP,
			peerConfigured,
		),
	)
	return mustJSON(state), nil
}

func (a *app) disconnectJS(args []js.Value) (any, error) {
	a.disconnectLocked()
	return mustJSON(map[string]string{"message": "Disconnected"}), nil
}

func (a *app) disconnectLocked() {
	a.mu.Lock()
	server := a.server
	serverLn := a.serverLn
	dev := a.dev
	vt := a.vt
	a.server = nil
	a.serverLn = nil
	a.dev = nil
	a.vt = nil
	a.httpc = nil
	a.network = nil
	a.proxyURL = ""
	a.localAddr = netip.Addr{}
	a.mu.Unlock()

	if server != nil {
		_ = server.Close()
	}
	if serverLn != nil {
		_ = serverLn.Close()
	}
	if dev != nil {
		dev.Close()
	}
	if vt != nil {
		_ = vt.Close()
	}
	logLine("app", "node stopped")
}

func (a *app) generateKeys(args []js.Value) (any, error) {
	sk, err := generatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	pk, err := sk.publicKey()
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	logLine("app", "generated new keypair")
	return mustJSON(map[string]string{
		"privateKey": sk.String(),
		"publicKey":  pk.String(),
	}), nil
}

func (a *app) derivePublicKey(args []js.Value) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("expected private key argument")
	}
	raw := strings.TrimSpace(args[0].String())
	if raw == "" {
		return mustJSON(map[string]string{
			"publicKey": "",
		}), nil
	}
	sk, err := parsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pk, err := sk.publicKey()
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return mustJSON(map[string]string{
		"publicKey": pk.String(),
	}), nil
}

func (a *app) request(args []js.Value) (any, error) {
	if len(args) != 4 {
		return nil, fmt.Errorf("expected method, url, headers, body")
	}

	a.mu.Lock()
	httpc := a.httpc
	a.mu.Unlock()
	if httpc == nil {
		return nil, fmt.Errorf("wireguard node is not running")
	}

	method := strings.TrimSpace(args[0].String())
	targetURL := strings.TrimSpace(args[1].String())
	headersText := args[2].String()
	bodyText := args[3].String()
	if method == "" {
		method = http.MethodGet
	}
	if targetURL == "" {
		return nil, fmt.Errorf("target url is required")
	}

	logLine("http", fmt.Sprintf("request start method=%s url=%s", method, targetURL))
	req, err := http.NewRequestWithContext(
		context.Background(),
		method,
		targetURL,
		strings.NewReader(bodyText),
	)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for _, line := range strings.Split(headersText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header line %q", line)
		}
		req.Header.Add(strings.TrimSpace(key), strings.TrimSpace(value))
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "%s\n", resp.Status)
	resp.Header.Write(&out)
	out.WriteString("\n")
	out.Write(body)
	logLine("http", fmt.Sprintf("request done method=%s url=%s status=%s bytes=%d", method, targetURL, resp.Status, len(body)))
	return out.String(), nil
}

func (a *app) startServer(args []js.Value) (any, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("expected listen address and body")
	}

	a.mu.Lock()
	if a.vt == nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("wireguard node is not running")
	}
	if a.server != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("http server is already running")
	}
	vt := a.vt
	localAddr := a.localAddr
	a.mu.Unlock()

	listenAddr := strings.TrimSpace(args[0].String())
	if listenAddr == "" {
		listenAddr = "0.0.0.0:8000"
	}
	bodyText := args[1].String()

	network := tcpNetworkForAddress(listenAddr)
	ln, err := vt.Listen(context.Background(), network, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on vtun %s %s: %w", network, listenAddr, err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logLine("http-server", fmt.Sprintf("request from=%s method=%s path=%s", r.RemoteAddr, r.Method, r.URL.String()))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, bodyText)
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	a.mu.Lock()
	a.server = server
	a.serverLn = ln
	a.mu.Unlock()

	go func() {
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			logLine("http-server", "serve error: "+err.Error())
		} else {
			logLine("http-server", "serve loop stopped")
		}
	}()

	serverURL := resolveServerURL(localAddr, ln.Addr().String())
	logLine("http-server", fmt.Sprintf("listening bind=%s resolved_url=%s", ln.Addr().String(), serverURL))
	return mustJSON(map[string]string{
		"message":    "HTTP server started",
		"listenAddr": ln.Addr().String(),
		"serverUrl":  serverURL,
	}), nil
}

func (a *app) stopServerJS(args []js.Value) (any, error) {
	a.mu.Lock()
	server := a.server
	serverLn := a.serverLn
	a.server = nil
	a.serverLn = nil
	a.mu.Unlock()

	if serverLn != nil {
		_ = serverLn.Close()
	}
	if server != nil {
		_ = server.Close()
	}
	logLine("http-server", "stopped")
	return mustJSON(map[string]string{"message": "HTTP server stopped"}), nil
}

func (a *app) getState(args []js.Value) (any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev == nil {
		return mustJSON(map[string]any{
			"message": "WireGuard node is not running",
		}), nil
	}
	cfg := a.dev.Config()
	privateKey := noisePrivateKey(cfg.PrivateKey)
	publicKey, err := privateKey.publicKey()
	if err != nil {
		return nil, err
	}
	var allowed []netip.Prefix
	var peerEndpoint string
	if len(cfg.Peers) > 0 {
		peerEndpoint = cfg.Peers[0].Endpoint
		allowed = cfg.Peers[0].AllowedIPs
	}
	return mustJSON(a.currentStateLocked(privateKey, publicKey, peerEndpoint, allowed)), nil
}

func (a *app) currentStateLocked(
	privateKey noisePrivateKey,
	publicKey noisePublicKey,
	peerEndpoint string,
	allowedIPs []netip.Prefix,
) responseState {
	state := responseState{
		LocalTunnelAddr: a.localAddr.String(),
		LocalPrivateKey: privateKey.String(),
		LocalPublicKey:  publicKey.String(),
		ProxyURL:        a.proxyURL,
		PeerConfigured:  peerEndpoint != "" || len(allowedIPs) > 0,
		PeerEndpoint:    peerEndpoint,
	}
	if a.dev != nil {
		state.ListenPort = a.dev.ListenPort()
	}
	state.AdvertisedUDP = advertisedEndpoint(a.network)
	state.SuggestedEndpoint = suggestEndpoint(a.proxyURL, state.AdvertisedUDP)
	for _, prefix := range allowedIPs {
		state.PeerAllowedIPs = append(state.PeerAllowedIPs, prefix.String())
	}
	if a.serverLn != nil {
		state.ServerURL = resolveServerURL(a.localAddr, a.serverLn.Addr().String())
	}
	return state
}

type deviceLogSink struct {
	prefix string
}

func (l *deviceLogSink) log(level, msg string) {
	logLine(level, l.prefix+": "+msg)
}

func (l *deviceLogSink) Debug(args ...any) { l.log("debug", fmt.Sprint(args...)) }
func (l *deviceLogSink) Debugf(format string, args ...any) {
	l.log("debug", fmt.Sprintf(format, args...))
}
func (l *deviceLogSink) Info(args ...any) { l.log("info", fmt.Sprint(args...)) }
func (l *deviceLogSink) Infof(format string, args ...any) {
	l.log("info", fmt.Sprintf(format, args...))
}
func (l *deviceLogSink) Warn(args ...any) { l.log("warn", fmt.Sprint(args...)) }
func (l *deviceLogSink) Warnf(format string, args ...any) {
	l.log("warn", fmt.Sprintf(format, args...))
}
func (l *deviceLogSink) Err(args ...any) { l.log("error", fmt.Sprint(args...)) }
func (l *deviceLogSink) Errf(format string, args ...any) {
	l.log("error", fmt.Sprintf(format, args...))
}
func (l *deviceLogSink) Fatal(args ...any) { l.log("error", fmt.Sprint(args...)) }
func (l *deviceLogSink) Fatalf(format string, args ...any) {
	l.log("error", fmt.Sprintf(format, args...))
}

type loggingTUN struct {
	gtun.Tun
	name string
}

func newLoggingTUN(name string, tun gtun.Tun) gtun.Tun {
	return &loggingTUN{Tun: tun, name: name}
}

func (t *loggingTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Tun.Read(bufs, sizes, offset)
	if n > 0 {
		for i := 0; i < n; i++ {
			logLine("tun", fmt.Sprintf("%s read packet[%d] bytes=%d %s", t.name, i, sizes[i], describeIPPacket(bufs[i], sizes[i], offset)))
		}
	}
	if err != nil {
		logLine("tun", fmt.Sprintf("%s read error=%v", t.name, err))
	}
	return n, err
}

func (t *loggingTUN) Write(bufs [][]byte, offset int) (int, error) {
	n, err := t.Tun.Write(bufs, offset)
	if n > 0 {
		for i := 0; i < n; i++ {
			logLine("tun", fmt.Sprintf("%s write packet[%d] bytes=%d %s", t.name, i, len(bufs[i])-offset, describeIPPacket(bufs[i], len(bufs[i])-offset, offset)))
		}
	}
	if err != nil {
		logLine("tun", fmt.Sprintf("%s write error=%v", t.name, err))
	}
	return n, err
}

type loggingBind struct {
	name string
	bind conn.Bind
}

func newLoggingBind(name string, bind conn.Bind) *loggingBind {
	return &loggingBind{name: name, bind: bind}
}

func (b *loggingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.bind.Open(port)
	if err != nil {
		logLine("bind", fmt.Sprintf("%s open requested_port=%d err=%v", b.name, port, err))
		return nil, 0, err
	}
	logLine("bind", fmt.Sprintf("%s open requested_port=%d actual_port=%d recv=%d", b.name, port, actualPort, len(fns)))
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		index := i
		wrapped[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(bufs, sizes, eps)
			if n > 0 {
				for j := 0; j < n; j++ {
					logLine("bind", fmt.Sprintf("%s recv fn=%d packet[%d] bytes=%d endpoint=%s preview=%s", b.name, index, j, sizes[j], endpointString(eps[j]), previewHex(bufs[j][:sizes[j]])))
				}
			}
			if err != nil {
				logLine("bind", fmt.Sprintf("%s recv fn=%d err=%v", b.name, index, err))
			}
			return n, err
		}
	}
	return wrapped, actualPort, nil
}

func (b *loggingBind) Close() error {
	err := b.bind.Close()
	logLine("bind", fmt.Sprintf("%s close err=%v", b.name, err))
	return err
}

func (b *loggingBind) SetMark(mark uint32) error {
	err := b.bind.SetMark(mark)
	logLine("bind", fmt.Sprintf("%s set_mark=%d err=%v", b.name, mark, err))
	return err
}

func (b *loggingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	err := b.bind.Send(bufs, ep)
	for i, buf := range bufs {
		logLine("bind", fmt.Sprintf("%s send packet[%d] bytes=%d endpoint=%s preview=%s err=%v", b.name, i, len(buf), endpointString(ep), previewHex(buf), err))
	}
	return err
}

func (b *loggingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.bind.ParseEndpoint(s)
	logLine("bind", fmt.Sprintf("%s parse_endpoint=%q err=%v", b.name, s, err))
	return ep, err
}

func (b *loggingBind) BatchSize() int {
	return b.bind.BatchSize()
}

type recordingNetwork struct {
	*gonnect.RejectNetwork
	base gonnect.Network

	mu sync.Mutex

	udp4Addr string
	udp6Addr string

	singleStackUDP bool
}

func newRecordingNetwork(base gonnect.Network) *recordingNetwork {
	rn := &recordingNetwork{
		base:           base,
		singleStackUDP: base != nil && !base.IsNative(),
	}
	return rn
}

func (n *recordingNetwork) shouldRejectUDP6Listen(network string) bool {
	return n.singleStackUDP && network == "udp6"
}

func (n *recordingNetwork) record(network string, conn net.Conn, err error) {
	if err != nil || conn == nil || conn.LocalAddr() == nil {
		logLine("network", fmt.Sprintf("listen %s err=%v", network, err))
		return
	}
	addr := conn.LocalAddr().String()
	n.mu.Lock()
	if strings.Contains(network, "6") {
		n.udp6Addr = addr
	} else {
		n.udp4Addr = addr
	}
	n.mu.Unlock()
	logLine("network", fmt.Sprintf("listen %s local_addr=%s", network, addr))
}

func (n *recordingNetwork) lastAdvertised() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.udp4Addr != "" {
		return n.udp4Addr
	}
	return n.udp6Addr
}

func (n *recordingNetwork) IsNative() bool { return n.base.IsNative() }
func (n *recordingNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	logLine("network", fmt.Sprintf("dial network=%s address=%s", network, address))
	return n.base.Dial(ctx, network, address)
}
func (n *recordingNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	logLine("network", fmt.Sprintf("listen tcp network=%s address=%s", network, address))
	return n.base.Listen(ctx, network, address)
}
func (n *recordingNetwork) PacketDial(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	logLine("network", fmt.Sprintf("packet_dial network=%s address=%s", network, address))
	return n.base.PacketDial(ctx, network, address)
}
func (n *recordingNetwork) ListenPacket(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	logLine("network", fmt.Sprintf("listen_packet network=%s address=%s", network, address))
	pc, err := n.base.ListenPacket(ctx, network, address)
	if conn, ok := pc.(net.Conn); ok {
		n.record(network, conn, err)
	}
	return pc, err
}
func (n *recordingNetwork) DialTCP(ctx context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	logLine("network", fmt.Sprintf("dial_tcp network=%s laddr=%s raddr=%s", network, laddr, raddr))
	return n.base.DialTCP(ctx, network, laddr, raddr)
}
func (n *recordingNetwork) ListenTCP(ctx context.Context, network, laddr string) (gonnect.TCPListener, error) {
	logLine("network", fmt.Sprintf("listen_tcp network=%s laddr=%s", network, laddr))
	return n.base.ListenTCP(ctx, network, laddr)
}
func (n *recordingNetwork) DialUDP(ctx context.Context, network, laddr, raddr string) (gonnect.UDPConn, error) {
	logLine("network", fmt.Sprintf("dial_udp network=%s laddr=%s raddr=%s", network, laddr, raddr))
	return n.base.DialUDP(ctx, network, laddr, raddr)
}
func (n *recordingNetwork) ListenUDP(ctx context.Context, network, laddr string) (gonnect.UDPConn, error) {
	logLine("network", fmt.Sprintf("listen_udp network=%s laddr=%s", network, laddr))
	if n.shouldRejectUDP6Listen(network) {
		err := syscall.EAFNOSUPPORT
		logLine("network", fmt.Sprintf("listen_udp network=%s forced_single_stack err=%v", network, err))
		return nil, err
	}
	conn, err := n.base.ListenUDP(ctx, network, laddr)
	n.record(network, conn, err)
	return conn, err
}
func (n *recordingNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	logLine("network", fmt.Sprintf("listen_packet_config network=%s address=%s", network, address))
	pc, err := n.base.ListenPacketConfig(ctx, lc, network, address)
	if conn, ok := pc.(net.Conn); ok {
		n.record(network, conn, err)
	}
	return pc, err
}
func (n *recordingNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	if n.shouldRejectUDP6Listen(network) {
		err := syscall.EAFNOSUPPORT
		logLine("network", fmt.Sprintf("listen_udp_config network=%s forced_single_stack err=%v", network, err))
		return nil, err
	}
	logLine("network", fmt.Sprintf("listen_udp_config network=%s laddr=%s", network, laddr))
	conn, err := n.base.ListenUDPConfig(ctx, lc, network, laddr)
	n.record(network, conn, err)
	return conn, err
}

func parseAddrDefault(raw, fallback string) (netip.Addr, error) {
	if raw == "" {
		raw = fallback
	}
	return netip.ParseAddr(raw)
}

func parseAllowedIPs(raw string) ([]netip.Prefix, error) {
	raw = strings.ReplaceAll(raw, ",", "\n")
	var out []netip.Prefix
	for _, item := range strings.Split(raw, "\n") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("parse allowed ip %q: %w", item, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func generatePrivateKey() (noisePrivateKey, error) {
	var key noisePrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return noisePrivateKey{}, err
	}
	key.clamp()
	return key, nil
}

func parseOrGeneratePrivateKey(raw string) (noisePrivateKey, bool, error) {
	if raw == "" {
		key, err := generatePrivateKey()
		return key, true, err
	}
	key, err := parsePrivateKey(raw)
	return key, false, err
}

func parsePrivateKey(raw string) (noisePrivateKey, error) {
	var key noisePrivateKey
	if err := decodeFlexible32(key[:], raw); err != nil {
		return noisePrivateKey{}, err
	}
	key.clamp()
	return key, nil
}

func parsePublicKey(raw string) (noisePublicKey, error) {
	var key noisePublicKey
	if err := decodeFlexible32(key[:], raw); err != nil {
		return noisePublicKey{}, err
	}
	return key, nil
}

func parsePresharedKey(raw string) (noisePresharedKey, error) {
	var key noisePresharedKey
	if err := decodeFlexible32(key[:], raw); err != nil {
		return noisePresharedKey{}, err
	}
	return key, nil
}

func decodeFlexible32(dst []byte, raw string) error {
	raw = strings.TrimSpace(raw)
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == len(dst) {
		copy(dst, decoded)
		return nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == len(dst) {
		copy(dst, decoded)
		return nil
	}
	return fmt.Errorf("expected 32-byte key in base64 or hex encoding")
}

func (k *noisePrivateKey) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

func (k noisePrivateKey) publicKey() (noisePublicKey, error) {
	var pk noisePublicKey
	out, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return noisePublicKey{}, err
	}
	copy(pk[:], out)
	return pk, nil
}

func (k noisePrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k noisePublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k noisePrivateKey) toDevice() device.NoisePrivateKey {
	return device.NoisePrivateKey(k)
}

func (k noisePublicKey) toDevice() device.NoisePublicKey {
	return device.NoisePublicKey(k)
}

func (k noisePresharedKey) toDevice() device.NoisePresharedKey {
	return device.NoisePresharedKey(k)
}

func advertisedEndpoint(network *recordingNetwork) string {
	if network == nil {
		return ""
	}
	return network.lastAdvertised()
}

func suggestEndpoint(proxyURL, advertised string) string {
	if advertised == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(advertised)
	if err != nil {
		return advertised
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		u, parseErr := url.Parse(proxyURL)
		if parseErr == nil && u.Hostname() != "" {
			return net.JoinHostPort(u.Hostname(), port)
		}
	}
	return advertised
}

func normalizeProxyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if !q.Has("gost") || q.Has("bind") {
		return raw
	}
	q.Set("bind", "true")
	u.RawQuery = q.Encode()
	return u.String()
}

func resolveServerURL(localAddr netip.Addr, listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = localAddr.String()
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

func tcpNetworkForAddress(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return "tcp"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "tcp"
	}
	if ip.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

func endpointString(ep conn.Endpoint) string {
	if ep == nil {
		return "<nil>"
	}
	return ep.DstToString()
}

func previewHex(buf []byte) string {
	if len(buf) == 0 {
		return "empty"
	}
	if len(buf) > 24 {
		buf = buf[:24]
	}
	return hex.EncodeToString(buf)
}

func describeIPPacket(buf []byte, size, offset int) string {
	if size <= 0 || len(buf) < offset+size || offset < 0 {
		return "packet=empty"
	}
	packet := buf[offset : offset+size]
	if len(packet) == 0 {
		return "packet=empty"
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < 20 {
			return "ip=ipv4 truncated preview=" + previewHex(packet)
		}
		src := net.IP(packet[12:16]).String()
		dst := net.IP(packet[16:20]).String()
		return fmt.Sprintf("ip=ipv4 proto=%d src=%s dst=%s preview=%s", packet[9], src, dst, previewHex(packet))
	case 6:
		if len(packet) < 40 {
			return "ip=ipv6 truncated preview=" + previewHex(packet)
		}
		src := net.IP(packet[8:24]).String()
		dst := net.IP(packet[24:40]).String()
		return fmt.Sprintf("ip=ipv6 next=%d src=%s dst=%s preview=%s", packet[6], src, dst, previewHex(packet))
	default:
		return fmt.Sprintf("ip=unknown version=%d preview=%s", version, previewHex(packet))
	}
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return `{"message":"json marshal failed"}`
	}
	return string(data)
}

func logLine(kind, message string) {
	line := fmt.Sprintf("[%s] %s", strings.ToUpper(kind), message)
	fmt.Println(line)
	appendFn := js.Global().Get("wgDemoAppendLog")
	if appendFn.Type() == js.TypeFunction {
		appendFn.Invoke(time.Now().Format("15:04:05.000") + " " + line)
	}
}
