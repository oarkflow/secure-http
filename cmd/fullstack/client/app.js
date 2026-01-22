
import { SecureClient } from "../../../web/client/src/index.js";

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
let fileInput;
let fileDescription;
let uploadBtn;
let listFilesBtn;
let getBtn;
let putBtn;
let deleteBtn;
let patchBtn;

let loggedIn = false;
let currentUserID = null;
const protectedButtons = [];

// Initialize SecureClient
const client = new SecureClient({
    wasmUrl: "fetch.wasm"
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

    // File input enabled only when logged in
    if (fileInput) fileInput.disabled = !loggedIn;
    if (fileDescription) fileDescription.disabled = !loggedIn;

    // Reset button enabled when connected
    if (resetBtn) resetBtn.disabled = !isConnected && !loggedIn;

    // Protected buttons enabled only when logged in
    protectedButtons.forEach((button) => {
        if (button) button.disabled = !loggedIn;
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
            hasGateSecrets: !!config.gateSecrets,
            hasAccessToken: !!config.accessToken,
            hasRefreshToken: !!config.refreshToken
        });

        // Store JWT tokens in sessionStorage (cleared on tab close)
        if (config.accessToken) {
            sessionStorage.setItem('accessToken', config.accessToken);
        }
        if (config.refreshToken) {
            sessionStorage.setItem('refreshToken', config.refreshToken);
        }

        // 2. Initialize SecureClient with WASM
        await client.init();

        // 3. Configure and perform handshake (autoHandshake does this automatically)
        const secureConfig = {
            baseURL: config.baseURL || window.location.origin,
            deviceID: config.deviceID,
            deviceSecret: config.deviceSecret,
            userToken: config.userToken,
            accessToken: config.accessToken, // JWT token
            handshakePath: config.handshakePath || "/handshake",
            capabilityToken: config.capabilityToken,
            gateSecrets: config.gateSecrets,
            autoHandshake: true,
        };

        log("Initializing secure channel with auto-handshake...");
        await window.secureFetchInit(secureConfig);
        log("Secure channel initialized and handshake completed");

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
    // Store session config for page refresh restoration
    // JWT tokens are stored separately in sessionStorage
    const state = {
        userID: userID,
        timestamp: Date.now(),
        config: sessionConfig, // Store full config for restoration
    };
    try {
        sessionStorage.setItem("securefetch_user", JSON.stringify(state));
    } catch (err) {
        log("Could not save user state");
    }
}

function clearLoginState() {
    try {
        sessionStorage.removeItem("securefetch_user");
        sessionStorage.removeItem("accessToken");
        sessionStorage.removeItem("refreshToken");
    } catch (err) {}
}

async function restoreLoginState() {
    // Restore session from sessionStorage on page refresh
    // Re-establishes encrypted channel with stored JWT token
    try {
        const stateJSON = sessionStorage.getItem("securefetch_user");
        const accessToken = sessionStorage.getItem("accessToken");

        if (!stateJSON || !accessToken) {
            log("No active session - please login");
            return null;
        }

        const state = JSON.parse(stateJSON);

        // Check if token is likely expired (tokens expire after 15 min by default)
        if (Date.now() - state.timestamp > 15 * 60 * 1000) {
            clearLoginState();
            log("Session expired - please login again");
            setStatus("Session expired", "idle");
            return null;
        }

        if (!state.config) {
            log("Incomplete session data - please login again");
            clearLoginState();
            return null;
        }

        log(`Restoring session for ${state.userID}...`);
        setStatus("Restoring session...", "idle");

        // Re-initialize WASM client
        await client.init();

        // Restore session config with stored access token
        const restoreConfig = {
            ...state.config,
            accessToken: accessToken, // Use stored JWT token
            autoHandshake: true,
        };

        log("Re-establishing secure channel...");
        await window.secureFetchInit(restoreConfig);
        log("Secure channel restored");

        // Update state
        client.isReady = true;
        currentUserID = state.userID;
        loggedIn = true;
        updateControls();
        setStatus(`✓ Session restored for ${state.userID}`, "ok");
        log(`Session restored for user: ${state.userID}`);

        return true;
    } catch (err) {
        console.warn("Session restoration failed:", err);
        log(`Failed to restore session: ${err.message}`);
        clearLoginState();
        setStatus("Please login", "idle");
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

async function handleFileUpload() {
    try {
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            log("Error: No file selected");
            setStatus("No file selected", "error");
            return;
        }

        const file = fileInput.files[0];
        const description = fileDescription ? fileDescription.value.trim() : "";

        log(`Uploading file: ${file.name} (${file.size} bytes)`);
        setStatus("Uploading file...", "idle");

        // Upload file with encryption
        const response = await client.uploadFile(
            "/api/upload",
            file,
            file.name,
            "file",
            {
                description: description || "File uploaded from browser",
                user: currentUserID,
                timestamp: new Date().toISOString()
            },
            "json"
        );

        log(`File upload successful`, response);
        setStatus("✓ File uploaded", "ok");

        // Clear the input
        if (fileInput) fileInput.value = "";
        if (fileDescription) fileDescription.value = "";
    } catch (err) {
        log(`File upload error: ${err.message}`);
        setStatus("Upload failed: " + err.message, "error");
    }
}

async function handleListFiles() {
    try {
        log("Fetching file list...");
        setStatus("Loading files...", "idle");

        const response = await client.get("/api/files", "json");
        log("Files retrieved", response);

        if (response.data && response.data.files) {
            const files = response.data.files;
            log(`Found ${files.length} file(s) in uploads directory:`);

            files.forEach((file, index) => {
                log(`  ${index + 1}. ${file.filename} (${file.size} bytes) - Modified: ${file.modified_at}`);
            });

            if (files.length > 0) {
                log("\nTo download a file, note its filename from the list above");
            }
        }

        setStatus(`✓ Found ${response.data?.total || 0} files`, "ok");
    } catch (err) {
        log(`List files error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handleGetRequest() {
    try {
        log("Sending GET request...");
        const response = await client.get("/api/echo", "json");
        log("GET response received", response);
        setStatus("✓ GET request successful", "ok");
    } catch (err) {
        log(`GET error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handlePutRequest() {
    try {
        log("Sending PUT request...");
        const response = await client.put("/api/echo", {
            action: "update",
            user: currentUserID,
            data: { value: "Updated via PUT" }
        }, "json");
        log("PUT response received", response);
        setStatus("✓ PUT request successful", "ok");
    } catch (err) {
        log(`PUT error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handleDeleteRequest() {
    try {
        log("Sending DELETE request...");
        const response = await client.delete("/api/echo", "json");
        log("DELETE response received", response);
        setStatus("✓ DELETE request successful", "ok");
    } catch (err) {
        log(`DELETE error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
    }
}

async function handlePatchRequest() {
    try {
        log("Sending PATCH request...");
        const response = await client.patch("/api/echo", {
            action: "patch",
            user: currentUserID,
            changes: { status: "patched" }
        }, "json");
        log("PATCH response received", response);
        setStatus("✓ PATCH request successful", "ok");
    } catch (err) {
        log(`PATCH error: ${err.message}`);
        setStatus("Error: " + err.message, "error");
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
    fileInput = document.getElementById("file-input");
    fileDescription = document.getElementById("file-description");
    uploadBtn = document.getElementById("upload-btn");
    listFilesBtn = document.getElementById("list-files-btn");
    getBtn = document.getElementById("get-btn");
    putBtn = document.getElementById("put-btn");
    deleteBtn = document.getElementById("delete-btn");
    patchBtn = document.getElementById("patch-btn");

    // Register protected buttons
    protectedButtons.push(
        sessionBtn,
        echoBtn,
        pentestBtn,
        logoutBtn,
        uploadBtn,
        listFilesBtn,
        patchBtn
    );

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

    if (uploadBtn) {
        uploadBtn.addEventListener("click", handleFileUpload);
    }

    if (listFilesBtn) {
        listFilesBtn.addEventListener("click", handleListFiles);
    }

    if (getBtn) {
        getBtn.addEventListener("click", handleGetRequest);
    }

    if (putBtn) {
        putBtn.addEventListener("click", handlePutRequest);
    }

    if (deleteBtn) {
        deleteBtn.addEventListener("click", handleDeleteRequest);
    }

    if (patchBtn) {
        patchBtn.addEventListener("click", handlePatchRequest);
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
