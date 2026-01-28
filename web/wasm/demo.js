// Demo JavaScript for Secure Fetch with WASM
let wasmInitialized = false;
let authConfig = null;

// Activity log management
function addLog(message, type = 'info') {
    const log = document.getElementById('activityLog');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;

    const timestamp = document.createElement('div');
    timestamp.className = 'timestamp';
    timestamp.textContent = `[${new Date().toLocaleTimeString()}]`;

    const msg = document.createElement('div');
    msg.className = 'message';
    msg.textContent = message;

    entry.appendChild(timestamp);
    entry.appendChild(msg);

    log.insertBefore(entry, log.firstChild);

    // Keep only last 20 entries
    while (log.children.length > 20) {
        log.removeChild(log.lastChild);
    }
}

function clearLog() {
    const log = document.getElementById('activityLog');
    log.innerHTML = '<div class="log-entry"><div class="timestamp">[System]</div><div class="message">Log cleared.</div></div>';
}

// Check authentication and initialize
async function initializeDemo() {
    addLog('Initializing secure demo...', 'info');

    // Check if user is authenticated
    const configJson = sessionStorage.getItem('auth_config');
    if (!configJson) {
        addLog('No authentication found. Redirecting to login...', 'error');
        setTimeout(() => {
            window.location.href = './login.html';
        }, 1500);
        return;
    }

    try {
        authConfig = JSON.parse(configJson);
        document.getElementById('currentUser').textContent = authConfig.userID;
        addLog(`Authenticated as ${authConfig.userID}`, 'success');

        // Initialize WASM secure fetch
        await initializeWASM();

        // Update session info
        updateSessionInfo();

        addLog('Demo ready! You can now make secure API calls.', 'success');
    } catch (error) {
        addLog(`Initialization error: ${error.message}`, 'error');
        console.error('Init error:', error);
    }
}

async function initializeWASM() {
    if (wasmInitialized) {
        addLog('WASM already initialized', 'info');
        return;
    }

    try {
        addLog('Loading WASM module...', 'info');

        // Load the WASM binary with cache busting
        const go = new Go();
        const cacheBuster = new Date().getTime();
        const response = await fetch(`main.wasm?v=${cacheBuster}`);
        const buffer = await response.arrayBuffer();
        const result = await WebAssembly.instantiate(buffer, go.importObject);

        // Run the WASM module (this sets up the JS functions)
        go.run(result.instance);

        addLog('WASM module loaded successfully', 'success');

        // Wait a bit for WASM to fully initialize
        await new Promise(resolve => setTimeout(resolve, 100));

        // Initialize secure fetch with auth config
        if (typeof secureFetchInit === 'function') {
            addLog('Initializing secure fetch client...', 'info');

            // Use window.location.origin if baseURL is not provided or empty
            const baseURL = authConfig.baseURL && authConfig.baseURL !== ''
                ? authConfig.baseURL
                : window.location.origin;

            const config = {
                baseURL: baseURL,
                deviceID: authConfig.deviceID,
                deviceSecret: authConfig.deviceSecret,
                gateSecrets: authConfig.gateSecrets,
                userToken: authConfig.userToken,
                capabilityToken: authConfig.capabilityToken,
                handshakePath: authConfig.handshakePath || '/handshake',
                autoHandshake: true
            };

            await secureFetchInit(config);
            wasmInitialized = true;
            addLog('Secure fetch client initialized', 'success');
        } else {
            throw new Error('secureFetchInit function not found');
        }
    } catch (error) {
        addLog(`WASM initialization failed: ${error.message}`, 'error');
        throw error;
    }
}

function updateSessionInfo() {
    const sessionInfo = document.getElementById('sessionInfo');
    sessionInfo.innerHTML = `
        <div class="info-row">
            <span class="info-label">User ID:</span>
            <span class="info-value">${authConfig.userID}</span>
        </div>
        <div class="info-row">
            <span class="info-label">Device ID:</span>
            <span class="info-value">${authConfig.deviceID}</span>
        </div>
        <div class="info-row">
            <span class="info-label">Capability Token:</span>
            <span class="info-value">${authConfig.capabilityToken.substring(0, 20)}...</span>
        </div>
        <div class="info-row">
            <span class="info-label">Session Status:</span>
            <span class="info-value">Active & Encrypted</span>
        </div>
        <div class="info-row">
            <span class="info-label">Base URL:</span>
            <span class="info-value">${authConfig.baseURL || 'Same Origin'}</span>
        </div>
    `;
}

async function testAPI() {
    if (!wasmInitialized) {
        addLog('WASM not initialized. Please wait...', 'error');
        return;
    }

    const method = document.getElementById('apiMethod').value;
    const endpoint = document.getElementById('apiEndpoint').value;
    const responseBox = document.getElementById('apiResponse');

    addLog(`Testing ${method} ${endpoint}...`, 'info');
    responseBox.innerHTML = '<div class="loading"></div> Executing secure request...';

    try {
        const options = {
            method: method,
            endpoint: endpoint,
            responseType: 'json'
        };

        // Add body for POST/PUT requests
        if (method === 'POST' || method === 'PUT') {
            options.body = {
                message: 'Secure fetch test',
                timestamp: new Date().toISOString(),
                purpose: 'API testing from demo'
            };
        }

        const result = await secureFetch(options);

        responseBox.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>`;
        addLog(`${method} ${endpoint} - Success`, 'success');
    } catch (error) {
        responseBox.innerHTML = `<pre style="color: var(--error);">Error: ${error.message}</pre>`;
        addLog(`${method} ${endpoint} - Error: ${error.message}`, 'error');
        console.error('API test error:', error);
    }
}

async function loadAssets() {
    if (!wasmInitialized) {
        addLog('WASM not initialized. Please wait...', 'error');
        return;
    }

    const assetsGrid = document.getElementById('assetsGrid');
    assetsGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 2rem;"><div class="loading"></div> Loading protected assets...</div>';

    addLog('Loading secure assets...', 'info');

    const assetFiles = ['data.json', 'config.json', 'report.json'];
    const assets = [];

    try {
        for (const file of assetFiles) {
            try {
                const result = await secureFetch({
                    method: 'GET',
                    endpoint: `/assets/${file}`,
                    responseType: 'json'
                });

                assets.push({
                    name: file,
                    icon: '📄',
                    data: result
                });

                addLog(`Loaded ${file}`, 'success');
            } catch (error) {
                addLog(`Failed to load ${file}: ${error.message}`, 'error');
                assets.push({
                    name: file,
                    icon: '❌',
                    error: error.message
                });
            }
        }

        // Render assets
        renderAssets(assets);

    } catch (error) {
        assetsGrid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: var(--error);">Failed to load assets: ${error.message}</div>`;
        addLog(`Asset loading failed: ${error.message}`, 'error');
    }
}

function renderAssets(assets) {
    const assetsGrid = document.getElementById('assetsGrid');

    if (assets.length === 0) {
        assetsGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: var(--text-secondary);">No assets found</div>';
        return;
    }

    assetsGrid.innerHTML = '';

    assets.forEach(asset => {
        const card = document.createElement('div');
        card.className = 'asset-card';

        const icon = document.createElement('div');
        icon.className = 'asset-icon';
        icon.textContent = asset.icon;

        const name = document.createElement('div');
        name.className = 'asset-name';
        name.textContent = asset.name;

        card.appendChild(icon);
        card.appendChild(name);

        if (asset.data) {
            card.onclick = () => showAssetDetail(asset);
        }

        assetsGrid.appendChild(card);
    });
}

function showAssetDetail(asset) {
    const responseBox = document.getElementById('apiResponse');
    responseBox.innerHTML = `<pre>${JSON.stringify(asset.data, null, 2)}</pre>`;
    addLog(`Viewing asset: ${asset.name}`, 'info');
}

function logout() {
    addLog('Logging out...', 'info');
    sessionStorage.removeItem('auth_config');

    setTimeout(() => {
        window.location.href = './login.html';
    }, 500);
}

// Make functions globally available
window.testAPI = testAPI;
window.loadAssets = loadAssets;
window.clearLog = clearLog;
window.logout = logout;

// Initialize when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDemo);
} else {
    initializeDemo();
}
