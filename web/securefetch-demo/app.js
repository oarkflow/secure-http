
import { SecureClient } from "../client/src/index.js";

let consoleEl;
let statusEl;
let loginForm;
let userIdInput;
let userTokenInput;
let loginBtn;
let resetBtn;
let sessionBtn;
let echoBtn;
let pentestBtn;
let logoutBtn;

let loggedIn = false;
let currentUserID = null;
const protectedButtons = [];

// Initialize SecureClient
const client = new SecureClient({
    wasmUrl: "securefetch.wasm"
});

function log(message, payload) {
    const time = new Date().toISOString();
    let entry = `[${time}] ${message}`;
    if (payload !== undefined) {
        if (payload instanceof Uint8Array) {
            entry += `\nUint8Array(${payload.length}) [${Array.from(payload).join(", ")}]`;
        } else if (typeof payload === "object") {
            entry += `\n${JSON.stringify(payload, null, 2)}`;
        } else {
            entry += `\n${payload}`;
        }
    }
    if (!consoleEl) {
        console.log(entry);
        return;
    }
    consoleEl.textContent = `${entry}\n${consoleEl.textContent}`.slice(0, 5000);
}

function setStatus(text, variant = "idle") {
    if (!statusEl) {
        return;
    }
    statusEl.textContent = text;
    statusEl.dataset.variant = variant;
}

function updateControls() {
    if (!loginBtn) return;

    const isConnected = client.isReady;

    // Login button and form inputs enabled when not logged in
    if (loginBtn) loginBtn.disabled = loggedIn;
    if (userIdInput) userIdInput.disabled = loggedIn;
    if (userTokenInput) userTokenInput.disabled = loggedIn;

    // Reset button enabled when connected
    if (resetBtn) resetBtn.disabled = !isConnected && !loggedIn;

    // Protected buttons enabled only when logged in
    protectedButtons.forEach((button) => {
        button.disabled = !loggedIn;
    });
}

async function handleLogin(event) {
    event.preventDefault();

    const userID = userIdInput.value.trim();
    const userToken = userTokenInput.value.trim();

    if (!userID || !userToken) {
        log("Error: User ID and User Token are required");
        setStatus("Credentials required", "error");
        return;
    }

    try {
        log(`Authenticating user: ${userID}...`);
        setStatus("Authenticating...", "idle");

        // 1. Call /login to authenticate and get session config
        const loginResp = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                user_id: userID,
                user_token: userToken
            })
        });

        if (!loginResp.ok) {
            const err = await loginResp.text();
            throw new Error(`Authentication failed: ${err}`);
        }

        const config = await loginResp.json();
        log("Received session configuration from server", {
            deviceID: config.deviceID,
            hasDeviceSecret: !!config.deviceSecret,
            hasGateSecrets: !!config.gateSecrets
        });

        // 2. Initialize SecureClient with WASM
        await client.init();

        // 3. Configure and perform handshake
        const secureConfig = {
            baseURL: config.baseURL || window.location.origin,
            deviceID: config.deviceID,
            deviceSecret: config.deviceSecret,
            userToken: config.userToken,
            handshakePath: config.handshakePath || "/handshake",
            capabilityToken: config.capabilityToken,
            gateSecrets: config.gateSecrets,
            autoHandshake: true,
        };

        log("Initializing secure channel...");
        await window.secureFetchInit(secureConfig);
        log("Secure channel initialized, performing handshake...");

        // Ensure handshake completes
        await window.secureFetchHandshake(true);
        log("Handshake completed successfully");

        // Update client ready state
        client.isReady = true;

        // 4. Call the secure /api/login endpoint to establish application session
        const appLoginPayload = {
            username: userID,
            purpose: "secure-login",
            nonce: randomNonce(),
        };

        log("Calling /api/login to establish application session...");
        const appLoginResp = await client.fetch("/api/login", appLoginPayload, "json");
        log("Application login successful", appLoginResp);

        currentUserID = userID;
        loggedIn = true;
        saveLoginState(userID, secureConfig);
        updateControls();
        setStatus(`✓ Logged in as ${userID}`, "ok");

    } catch (err) {
        log(`Login error: ${err.message}`);
        // Try to extract more details from the error
        if (err.response) {
            log(`Error response:`, err.response);
        }
        if (err.stack) {
            log(`Error stack:`, err.stack);
        }
        setStatus("Login failed: " + err.message, "error");
        disconnectClient();
    }
}

function disconnectClient(message = "Session reset") {
    client.reset().catch(err => log("Reset error: " + err));
    loggedIn = false;
    currentUserID = null;
    clearLoginState();
    updateControls();
    setStatus("Not connected", "idle");
    log(message);
}

function randomNonce() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function saveLoginState(userID, sessionConfig) {
    // Save session config to sessionStorage (cleared when tab closes)
    const state = {
        userID: userID,
        sessionConfig: sessionConfig,
        timestamp: Date.now(),
    };
    try {
        sessionStorage.setItem("securefetch_session", JSON.stringify(state));
    } catch (err) {
        log("Could not save session state");
    }
}

function clearLoginState() {
    try {
        sessionStorage.removeItem("securefetch_session");
    } catch (err) {}
}

async function restoreLoginState() {
    try {
        const stateJSON = sessionStorage.getItem("securefetch_session");
        if (!stateJSON) return null;

        const state = JSON.parse(stateJSON);

        // Session expired after 1 hour
        if (Date.now() - state.timestamp > 60 * 60 * 1000) {
            clearLoginState();
            log("Session expired - please login again");
            return null;
        }

        if (!state.sessionConfig) {
            clearLoginState();
            return null;
        }

        log(`Restoring session for ${state.userID}...`);

        // Reinitialize with saved config
        await window.secureFetchInit(state.sessionConfig);
        await window.secureFetchHandshake(true);

        client.isReady = true;

        // Verify session is still valid on server
        try {
            await client.fetch("/api/session/state", {}, "json");
            currentUserID = state.userID;
            loggedIn = true;
            setStatus(`✓ Session restored - ${state.userID}`, "ok");
            updateControls();
            log("Session successfully restored");

            // Update form fields
            if (userIdInput) userIdInput.value = state.userID;
            if (userTokenInput) userTokenInput.value = "";

            return true;
        } catch (err) {
            log(`Session verification failed: ${err.message}`);
            clearLoginState();
            return null;
        }
    } catch (err) {
        console.warn("Session restore failed:", err);
        clearLoginState();
        return null;
    }
}

async function callSecureEndpoint(endpoint, body, description) {
    if (!client.isReady) {
        throw new Error("Not authenticated. Please login first.");
    }

    try {
        const response = await client.fetch(endpoint, body, "json");
        log(`${description} → 200`, response);
        return response;
    } catch (err) {
        log(`${description} error:`, err);
        throw err;
    }
}

async function handleSessionState() {
    try {
        await callSecureEndpoint("/api/session/state", {}, "Session state");
    } catch (err) {
        log(`Session state error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handleEcho() {
    try {
        await callSecureEndpoint("/api/echo", {
            user: currentUserID,
            message: "Browser echo test",
            timestamp: new Date().toISOString(),
        }, "Echo");
    } catch (err) {
        log(`Echo error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handlePentest() {
    try {
        await callSecureEndpoint("/api/pentest/probe", {
            vector: "demo-probe",
            payload: {
                user: currentUserID,
                source: "browser-lab"
            },
            notes: "Triggered from browser lab",
        }, "Pentest probe");
    } catch (err) {
        log(`Pentest error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handleLogout() {
    try {
        if (client.isReady) {
            await callSecureEndpoint("/api/logout", {}, "Logout");
        }
        disconnectClient("Logged out successfully");
        setStatus("Logged out", "idle");

        // Clear the form
        if (userIdInput) userIdInput.value = "";
        if (userTokenInput) userTokenInput.value = "";
    } catch (err) {
        log(`Logout error: ${err.message}`);
        // Still disconnect even if API call fails
        disconnectClient("Logged out (with errors)");
        setStatus("Logged out", "idle");
    }
}

function handleReset() {
    disconnectClient("Session reset by user");
    if (userIdInput) userIdInput.value = "";
    if (userTokenInput) userTokenInput.value = "";
}

document.addEventListener("DOMContentLoaded", async () => {
    // Get DOM elements
    consoleEl = document.getElementById("console");
    statusEl = document.getElementById("status-indicator");
    loginForm = document.getElementById("login-form");
    userIdInput = document.getElementById("user-id");
    userTokenInput = document.getElementById("user-token");
    loginBtn = document.getElementById("login-btn");
    resetBtn = document.getElementById("reset-btn");
    sessionBtn = document.getElementById("session-btn");
    echoBtn = document.getElementById("echo-btn");
    pentestBtn = document.getElementById("pentest-btn");
    logoutBtn = document.getElementById("logout-btn");

    // Register protected buttons
    protectedButtons.push(sessionBtn, echoBtn, pentestBtn, logoutBtn);

    // Set initial state
    updateControls();

    // Attach event listeners
    if (loginForm) {
        loginForm.addEventListener("submit", handleLogin);
    }

    if (resetBtn) {
        resetBtn.addEventListener("click", handleReset);
    }

    if (sessionBtn) {
        sessionBtn.addEventListener("click", handleSessionState);
    }

    if (echoBtn) {
        echoBtn.addEventListener("click", handleEcho);
    }

    if (pentestBtn) {
        pentestBtn.addEventListener("click", handlePentest);
    }

    if (logoutBtn) {
        logoutBtn.addEventListener("click", handleLogout);
    }

    // Initialize WASM client
    try {
        await client.init();
        log("SecureClient WASM initialized");

        // Try to restore previous session
        await restoreLoginState();
    } catch (err) {
        log(`Initialization error: ${err.message}`);
    }
});
