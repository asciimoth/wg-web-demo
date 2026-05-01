let wasmReady = false;
let nodeRunning = false;
let serverRunning = false;
let configDirty = false;
let lastSuggestedPeerAllowedIPs = '';
let lastSuggestedRequestUrl = '';
const DEFAULT_PROXY_URL = 'socks5+ws://127.0.0.1:1080?bind=true&gost=true';
const sharePayloadSchema = 'wg-web-demo/share-v1';

function appendLog(line) {
    const logs = document.getElementById('logs');
    if (!logs) {
        return;
    }

    const atBottom = logs.scrollTop + logs.clientHeight >= logs.scrollHeight - 8;
    logs.textContent += `${line}\n`;
    if (atBottom) {
        logs.scrollTop = logs.scrollHeight;
    }
}

window.wgDemoAppendLog = appendLog;

function setStatus(kind, text) {
    const nodeStatus = document.getElementById('nodeStatus');
    nodeStatus.className = `status ${kind}`;
    nodeStatus.textContent = text;
}

function setRequestStatus(kind, text) {
    const requestStatus = document.getElementById('requestStatus');
    requestStatus.className = `status ${kind}`;
    requestStatus.textContent = text;
}

function syncButtons() {
    document.getElementById('startNodeButton').disabled = !wasmReady;
    document.getElementById('stopNodeButton').disabled = !wasmReady || !nodeRunning;
    document.getElementById('generateKeysButton').disabled = !wasmReady;
    document.getElementById('startServerButton').disabled = !wasmReady || !nodeRunning || serverRunning;
    document.getElementById('stopServerButton').disabled = !wasmReady || !serverRunning;
    document.getElementById('requestButton').disabled = !wasmReady || !nodeRunning;
    document.getElementById('copyNodeConfigButton').disabled = !wasmReady;
    document.getElementById('pasteNodeConfigButton').disabled = !wasmReady;
    document.getElementById('importNodeConfigButton').disabled = !wasmReady;
}

function nodeConfigFieldIds() {
    return [
        'proxyUrl',
        'localTunnelAddr',
        'listenPort',
        'peerKeepalive',
        'localPrivateKey',
        'peerPublicKey',
        'peerPresharedKey',
        'peerEndpoint',
        'peerAllowedIPs',
    ];
}

function derivePeerTunnelAddr(localAddr) {
    const trimmed = localAddr.trim();
    if (!trimmed) {
        return '';
    }

    const octets = trimmed.split('.');
    if (octets.length !== 4) {
        return '';
    }

    const last = Number(octets[3]);
    if (!Number.isInteger(last)) {
        return '';
    }

    if (last === 1) {
        octets[3] = '2';
        return octets.join('.');
    }
    if (last === 2) {
        octets[3] = '1';
        return octets.join('.');
    }

    return '';
}

function syncPeerDefaultsFromLocalAddr() {
    const peerAddr = derivePeerTunnelAddr(document.getElementById('localTunnelAddr').value);
    const peerAllowedIPsField = document.getElementById('peerAllowedIPs');
    const requestUrlField = document.getElementById('requestUrl');
    const nextAllowedIPs = peerAddr ? `${peerAddr}/32` : '';
    const nextRequestUrl = peerAddr ? `http://${peerAddr}:8000/` : '';

    if (!peerAllowedIPsField.value.trim() || peerAllowedIPsField.value.trim() === lastSuggestedPeerAllowedIPs) {
        peerAllowedIPsField.value = nextAllowedIPs;
    }
    if (!requestUrlField.value.trim() || requestUrlField.value.trim() === lastSuggestedRequestUrl) {
        requestUrlField.value = nextRequestUrl;
    }

    lastSuggestedPeerAllowedIPs = nextAllowedIPs;
    lastSuggestedRequestUrl = nextRequestUrl;
}

function markConfigDirty() {
    if (!nodeRunning) {
        return;
    }
    configDirty = true;
    setStatus('loading', 'Node config changed. Pending changes will be applied before the next tunnel action.');
}

function clearConfigDirty() {
    configDirty = false;
}

async function syncLocalPublicKeyPreview() {
    if (!wasmReady || typeof wgDemoDerivePublicKey !== 'function') {
        return;
    }

    const privateKey = document.getElementById('localPrivateKey').value.trim();
    const publicKeyField = document.getElementById('localPublicKey');
    if (!privateKey) {
        publicKeyField.value = '';
        return;
    }

    try {
        const raw = await wgDemoDerivePublicKey(privateKey);
        const state = JSON.parse(raw);
        publicKeyField.value = state.publicKey || '';
    } catch (error) {
        publicKeyField.value = '';
    }
}

function installConfigDirtyTracking() {
    for (const id of nodeConfigFieldIds()) {
        const field = document.getElementById(id);
        if (!field) {
            continue;
        }
        field.addEventListener('input', markConfigDirty);
        field.addEventListener('change', markConfigDirty);
    }

    const privateKeyField = document.getElementById('localPrivateKey');
    privateKeyField.addEventListener('input', () => {
        void syncLocalPublicKeyPreview();
    });
    privateKeyField.addEventListener('change', () => {
        void syncLocalPublicKeyPreview();
    });

    const localTunnelAddrField = document.getElementById('localTunnelAddr');
    localTunnelAddrField.addEventListener('input', syncPeerDefaultsFromLocalAddr);
    localTunnelAddrField.addEventListener('change', syncPeerDefaultsFromLocalAddr);
}

function defaultProxyUrl() {
    return DEFAULT_PROXY_URL;
}

async function loadWasm() {
    try {
        setStatus('loading', 'Loading WASM module...');
        setRequestStatus('ready', 'Request path is idle.');

        const go = new Go();
        const response = await fetch('app.wasm');
        const buffer = await response.arrayBuffer();
        const result = await WebAssembly.instantiate(buffer, go.importObject);
        go.run(result.instance);

        wasmReady = true;
        document.getElementById('proxyUrl').value = defaultProxyUrl();
        await syncLocalPublicKeyPreview();
        setStatus('ready', 'Ready. Start one browser node, exchange public key and endpoint with a peer, then run traffic through the tunnel.');
        syncButtons();
        appendLog('UI ready');
    } catch (error) {
        console.error(error);
        setStatus('error', `Failed to load WASM module: ${error.message || error}`);
        syncButtons();
    }
}

function setFieldValue(id, value) {
    const field = document.getElementById(id);
    if (!field) {
        return;
    }
    field.value = value;
}

function collectNodeConfig() {
    return {
        proxyUrl: document.getElementById('proxyUrl').value.trim(),
        localTunnelAddr: document.getElementById('localTunnelAddr').value.trim(),
        localPrivateKey: document.getElementById('localPrivateKey').value.trim(),
        listenPort: Number(document.getElementById('listenPort').value || '0'),
        peerPublicKey: document.getElementById('peerPublicKey').value.trim(),
        peerPresharedKey: document.getElementById('peerPresharedKey').value.trim(),
        peerEndpoint: document.getElementById('peerEndpoint').value.trim(),
        peerAllowedIPs: document.getElementById('peerAllowedIPs').value,
        peerKeepalive: Number(document.getElementById('peerKeepalive').value || '0'),
    };
}

async function fetchRuntimeState() {
    if (!wasmReady || typeof wgDemoGetState !== 'function') {
        return null;
    }

    try {
        const raw = await wgDemoGetState();
        const state = JSON.parse(raw);
        if (!nodeRunning) {
            return null;
        }
        return state;
    } catch (error) {
        console.error(error);
        return null;
    }
}

async function buildSharePayload() {
    const config = collectNodeConfig();
    const runtime = await fetchRuntimeState();

    return {
        schema: sharePayloadSchema,
        exportedAt: new Date().toISOString(),
        config,
        runtime: runtime ? {
            localTunnelAddr: runtime.localTunnelAddr || config.localTunnelAddr,
            localPublicKey: runtime.localPublicKey || document.getElementById('localPublicKey').value.trim(),
            suggestedEndpoint: runtime.suggestedEndpoint || document.getElementById('suggestedEndpoint').value.trim(),
            advertisedUdp: runtime.advertisedUdp || document.getElementById('advertisedUdp').value.trim(),
            serverUrl: runtime.serverUrl || document.getElementById('serverUrl').value.trim(),
            listenPort: runtime.listenPort || 0,
        } : {
            localTunnelAddr: config.localTunnelAddr,
            localPublicKey: document.getElementById('localPublicKey').value.trim(),
            suggestedEndpoint: document.getElementById('suggestedEndpoint').value.trim(),
            advertisedUdp: document.getElementById('advertisedUdp').value.trim(),
            serverUrl: document.getElementById('serverUrl').value.trim(),
            listenPort: Number(document.getElementById('actualListenPort').value || '0'),
        },
        server: {
            running: serverRunning,
            url: document.getElementById('serverUrl').value.trim(),
            listenAddr: document.getElementById('serverListenAddr').value.trim(),
        },
    };
}

async function copyCurrentNodeConfig() {
    if (!wasmReady) {
        return;
    }

    try {
        const payload = await buildSharePayload();
        const text = JSON.stringify(payload, null, 2);
        setFieldValue('sharePayload', text);
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            appendLog('share payload copied to clipboard');
            setStatus('success', 'Current node payload copied. Paste it into the peer tab to import peer settings.');
        } else {
            appendLog('share payload generated in the export box; clipboard API unavailable');
            setStatus('success', 'Current node payload generated in the Share / Import box. Copy it manually into the peer tab.');
        }
    } catch (error) {
        console.error(error);
        setStatus('error', `Failed to copy current node payload: ${error.message || error}`);
    }
}

async function pasteSharedNodeData() {
    if (!wasmReady) {
        return;
    }

    try {
        if (!navigator.clipboard?.readText) {
            throw new Error('clipboard read is unavailable in this browser context');
        }
        const text = await navigator.clipboard.readText();
        setFieldValue('sharePayload', text);
        await importSharedNodeData(text);
    } catch (error) {
        console.error(error);
        setStatus('error', `Failed to read clipboard: ${error.message || error}`);
    }
}

function parseSharePayload(rawText) {
    const payload = JSON.parse(rawText);
    if (!payload || payload.schema !== sharePayloadSchema) {
        throw new Error(`unsupported payload schema; expected ${sharePayloadSchema}`);
    }
    return payload;
}

function remotePeerAllowedIPs(payload) {
    const remoteTunnelAddr = payload.runtime?.localTunnelAddr || payload.config?.localTunnelAddr || '';
    return remoteTunnelAddr ? `${remoteTunnelAddr}/32` : '';
}

function remoteRequestURL(payload) {
    if (payload.server?.url) {
        return payload.server.url;
    }

    const remoteTunnelAddr = payload.runtime?.localTunnelAddr || payload.config?.localTunnelAddr || '';
    if (!remoteTunnelAddr) {
        return '';
    }
    return `http://${remoteTunnelAddr}:8000/`;
}

async function importSharedNodeData(rawText) {
    if (!wasmReady) {
        return;
    }

    const sourceText = rawText ?? document.getElementById('sharePayload').value.trim();
    if (!sourceText) {
        alert('Share payload is required');
        return;
    }

    try {
        const payload = parseSharePayload(sourceText);
        const remoteTunnelAddr = payload.runtime?.localTunnelAddr || payload.config?.localTunnelAddr || '';
        const nextLocalTunnelAddr = derivePeerTunnelAddr(remoteTunnelAddr);
        const nextPeerAllowedIPs = remotePeerAllowedIPs(payload);
        const nextRequestURL = remoteRequestURL(payload);

        if (payload.config?.proxyUrl) {
            setFieldValue('proxyUrl', payload.config.proxyUrl);
        }
        if (nextLocalTunnelAddr) {
            setFieldValue('localTunnelAddr', nextLocalTunnelAddr);
        }
        if (payload.config?.peerKeepalive !== undefined) {
            setFieldValue('peerKeepalive', String(payload.config.peerKeepalive));
        }
        if (payload.runtime?.localPublicKey) {
            setFieldValue('peerPublicKey', payload.runtime.localPublicKey);
        }
        if (payload.config?.peerPresharedKey) {
            setFieldValue('peerPresharedKey', payload.config.peerPresharedKey);
        }
        if (payload.runtime?.suggestedEndpoint) {
            setFieldValue('peerEndpoint', payload.runtime.suggestedEndpoint);
        }
        if (nextPeerAllowedIPs) {
            setFieldValue('peerAllowedIPs', nextPeerAllowedIPs);
            lastSuggestedPeerAllowedIPs = nextPeerAllowedIPs;
        }
        if (nextRequestURL) {
            setFieldValue('requestUrl', nextRequestURL);
            lastSuggestedRequestUrl = nextRequestURL;
        }

        syncPeerDefaultsFromLocalAddr();
        markConfigDirty();
        await syncLocalPublicKeyPreview();

        setStatus('success', 'Peer payload imported. Applying node config for this tab.');

        await startNode();
        if (!nodeRunning) {
            return;
        }

        if (payload.server?.running && nextRequestURL) {
            setFieldValue('requestUrl', nextRequestURL);
            await runRequest();
            setStatus('success', 'Peer payload imported. Node applied and remote HTTP request executed.');
        } else {
            setStatus('success', 'Peer payload imported and node config applied.');
        }
    } catch (error) {
        console.error(error);
        setStatus('error', `Failed to import shared node data: ${error.message || error}`);
    }
}

function updatePairingFields(state) {
    if (state.localPrivateKey) {
        document.getElementById('localPrivateKey').value = state.localPrivateKey;
    }
    if (state.localPublicKey) {
        document.getElementById('localPublicKey').value = state.localPublicKey;
    }
    if (state.listenPort !== undefined) {
        document.getElementById('actualListenPort').value = String(state.listenPort);
    }
    if (state.advertisedUdp !== undefined) {
        document.getElementById('advertisedUdp').value = state.advertisedUdp || '';
    }
    if (state.suggestedEndpoint !== undefined) {
        document.getElementById('suggestedEndpoint').value = state.suggestedEndpoint || '';
    }
    if (state.serverUrl !== undefined) {
        document.getElementById('serverUrl').value = state.serverUrl || '';
    }
}

async function startNode() {
    if (!wasmReady) {
        return;
    }

    const config = collectNodeConfig();
    if (!config.proxyUrl) {
        alert('Proxy URL is required');
        return;
    }

    setStatus('loading', 'Starting WireGuard node over socks-over-websocket...');
    syncButtons();

    try {
        const raw = await wgDemoConnect(JSON.stringify(config));
        const state = JSON.parse(raw);
        nodeRunning = true;
        serverRunning = false;
        clearConfigDirty();
        updatePairingFields(state);
        setStatus('success', `${state.message}. Public key and endpoint are ready to share.`);
    } catch (error) {
        console.error(error);
        nodeRunning = false;
        serverRunning = false;
        setStatus('error', `Failed to start node: ${error.message || error}`);
    }

    syncButtons();
}

async function stopNode() {
    try {
        await wgDemoDisconnect();
    } catch (error) {
        console.error(error);
    } finally {
        nodeRunning = false;
        serverRunning = false;
        clearConfigDirty();
        document.getElementById('serverUrl').value = '';
        setStatus('ready', 'Node stopped.');
        syncButtons();
    }
}

async function generateKeys() {
    if (!wasmReady) {
        return;
    }

    try {
        const raw = await wgDemoGenerateKeys();
        const state = JSON.parse(raw);
        document.getElementById('localPrivateKey').value = state.privateKey;
        document.getElementById('localPublicKey').value = state.publicKey;
        markConfigDirty();
    } catch (error) {
        console.error(error);
        alert(`Failed to generate keypair: ${error.message || error}`);
    }
}

async function startServer() {
    const listenAddr = document.getElementById('serverListenAddr').value.trim();
    const body = document.getElementById('serverBody').value;

    try {
        if (configDirty) {
            await startNode();
            if (!nodeRunning) {
                return;
            }
        }
        const raw = await wgDemoStartServer(listenAddr, body);
        const state = JSON.parse(raw);
        serverRunning = true;
        document.getElementById('serverUrl').value = state.serverUrl || '';
        setStatus('success', `${state.message}. Share ${state.serverUrl || state.listenAddr} if the peer should fetch from you.`);
    } catch (error) {
        console.error(error);
        serverRunning = false;
        setStatus('error', `Failed to start HTTP server: ${error.message || error}`);
    }

    syncButtons();
}

async function stopServer() {
    try {
        await wgDemoStopServer();
    } catch (error) {
        console.error(error);
    } finally {
        serverRunning = false;
        document.getElementById('serverUrl').value = '';
        setStatus('ready', 'HTTP server stopped.');
        syncButtons();
    }
}

async function runRequest() {
    const method = document.getElementById('requestMethod').value;
    const targetUrl = document.getElementById('requestUrl').value.trim();
    const headers = document.getElementById('requestHeaders').value;
    const body = document.getElementById('requestBody').value;
    const result = document.getElementById('requestResult');

    if (!targetUrl) {
        alert('Request URL is required');
        return;
    }

    setRequestStatus('loading', `Running ${method} ${targetUrl} through WireGuard...`);
    result.textContent = '';

    try {
        if (configDirty) {
            await startNode();
            if (!nodeRunning) {
                setRequestStatus('error', 'Request aborted because node reconfiguration failed.');
                return;
            }
        }
        const response = await wgDemoRequest(method, targetUrl, headers, body);
        result.textContent = response;
        setRequestStatus('success', `Request completed: ${method} ${targetUrl}`);
    } catch (error) {
        console.error(error);
        result.textContent = `Error: ${error.message || error}`;
        setRequestStatus('error', `Request failed: ${error.message || error}`);
    }
}

window.addEventListener('load', () => {
    document.getElementById('localTunnelAddr').value = '10.44.0.1';
    document.getElementById('listenPort').value = '0';
    document.getElementById('peerKeepalive').value = '25';
    document.getElementById('serverListenAddr').value = '0.0.0.0:8000';
    document.getElementById('serverBody').value = 'hello over http over vtun over wireguard over socks-over-websocket';
    installConfigDirtyTracking();
    syncPeerDefaultsFromLocalAddr();
    syncButtons();
    loadWasm();
});
