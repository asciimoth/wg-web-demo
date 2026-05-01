# wg-web-demo

Browser WASM demonstration of HTTP over VTun over WireGuard over SOCKS-over-WebSocket.

It uses:
- `github.com/asciimoth/socksgo` for SOCKS-over-WebSocket transport
- `github.com/asciimoth/wgo` + `github.com/asciimoth/batchudp` for the WireGuard node
- `github.com/asciimoth/gonnect-netstack/vtun` for the userspace TCP/IP stack

The demo runs one WireGuard node per browser tab. You can:
- connect the tab to an external WireGuard peer
- open two tabs and pair them with each other by exchanging the displayed public key and advertised endpoint

For both cases you need SOCKS-over-WebSocket relay like [gost](https://gost.run/en/tutorials/protocols/socks/).

## Build

```bash
just build
```

## Serve

```bash
just serve
```

Then open `http://127.0.0.1:8000/`.

## Test Flow

1. Start a SOCKS-over-WebSocket server with UDP enabled, for example:

```bash
gost -L "socks5+ws://:1080?udp=true&udpBufferSize=4096&bind=true"
```

2. Open one or two tabs with the demo.
3. Use a proxy URL with the gost extension flag, for example `socks5+ws://127.0.0.1:1080?bind=true&gost=true`.
4. Start each node with a distinct tunnel IP such as `10.44.0.1` and `10.44.0.2`.
5. Copy each tab's public key and suggested endpoint into the other tab's peer settings.
6. Set the remote tab's tunnel IP in `Peer allowed IPs`, for example `10.44.0.2/32`.
7. Start the in-tunnel HTTP server on one side and request `http://<peer-tunnel-ip>:8000/` from the other side.

## Notes

The proxy may report a wildcard UDP bind address such as `0.0.0.0`. In that case the demo also shows a suggested endpoint derived from the SOCKS relay host, but you may still need to replace it with a routable host manually depending on your proxy topology.

