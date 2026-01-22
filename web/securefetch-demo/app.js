
import { SecureClient } from "../client/src/index.js";

let consoleEl;
let statusEl;
let accountSelect;
let accountDetailsEl;
let resetBtn;
let loginBtn;
let sessionBtn;
let echoBtn;
let pentestBtn;
let logoutBtn;

let loggedIn = false;
let currentAccount = null;
const labConfigPromise = loadLabConfig();
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

async function loadLabConfig() {
    const resp = await fetch("lab-config.json", { cache: "no-cache" });
    if (!resp.ok) {
        throw new Error(`Unable to load lab-config.json (${resp.status})`);
    }
    const cfg = await resp.json();
    cfg.baseURL = cfg.baseURL?.trim() || window.location.origin;
    return cfg;
}

function renderAccounts(config) {
    if (!accountSelect) {
        return;
    }
    accountSelect.innerHTML = "";
    if (!config.accounts?.length) {
        const option = document.createElement("option");
        option.value = "";
        option.textContent = "No demo accounts provisioned";
        accountSelect.appendChild(option);
        accountSelect.disabled = true;
        updateControls();
        return;
    }
    config.accounts.forEach((account, idx) => {
        const option = document.createElement("option");
        option.value = account.id;
        option.textContent = account.label || account.id;
        if (idx === 0) {
            option.selected = true;
            currentAccount = account;
        }
        accountSelect.appendChild(option);
    });
    renderAccountDetails(currentAccount);
    updateControls();
}

function renderAccountDetails(account) {
    if (!accountDetailsEl) {
        return;
    }
    if (!account) {
        accountDetailsEl.textContent = "Select an account to see device and role details.";
        return;
    }
    const roles = account.roles?.length ? account.roles.join(", ") : "—";
    accountDetailsEl.innerHTML = `
        <strong>${account.label}</strong>
        <div>Device: <code>${account.deviceID}</code></div>
        <div>User: <code>${account.userID || "n/a"}</code></div>
        <div>Roles: ${roles}</div>
        ${account.notes ? `<div class="notes">${account.notes}</div>` : ""}
    `;
}

function selectAccountById(config, id) {
    const account = config.accounts.find((entry) => entry.id === id) || config.accounts[0];
    currentAccount = account;
    renderAccountDetails(account);
    updateControls();
}

function requireAccount() {
    if (!currentAccount) {
        throw new Error("Choose a demo account first");
    }
}

function requireLogin() {
    if (!loggedIn) {
        throw new Error("Login first to use secure APIs");
    }
}

function updateControls() {
    if (!loginBtn) {
        return;
    }
    const hasAccount = Boolean(currentAccount);
    loginBtn.disabled = !hasAccount;
    protectedButtons.forEach((button) => {
        button.disabled = !loggedIn;
    });
    if (resetBtn) {
        resetBtn.disabled = !client.isReady && !loggedIn;
    }
}

updateControls();

async function connectSelectedAccount() {
    const lab = await labConfigPromise;
    requireAccount();
    // Let's ensure WASM is loaded first.
    await client.init();

    const cfg = {
        baseURL: lab.baseURL,
        deviceID: currentAccount.deviceID,
        deviceSecret: currentAccount.deviceSecret,
        userToken: currentAccount.userToken,
        handshakePath: lab.handshakePath,
        capabilityToken: lab.capabilityToken,
        gateSecrets: lab.gateSecrets,
        autoHandshake: true,
    };

    // Use the global exposed by WASM (loaded by client)
    await window.secureFetchInit(cfg);

    loggedIn = false;
    saveLoginState();
    updateControls();
    setStatus(`Handshake pinned to ${currentAccount.label}. Login required.`, "idle");
    const redacted = {
        deviceID: cfg.deviceID,
        gateSecrets: cfg.gateSecrets?.map((entry) => ({ id: entry.id, secret: "***" })),
        capabilityToken: "***",
        userToken: "***",
        baseURL: cfg.baseURL,
    };
    log("secureFetchInit completed", redacted);
}

function disconnectClient(message = "Client reset") {
    client.reset().catch(err => log("Reset error: " + err));
    loggedIn = false;
    clearLoginState();
    updateControls();
    setStatus("Not connected");
    log(message);
}

function randomNonce() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function saveLoginState() {
    if (!currentAccount) {
        return;
    }
    const state = {
        accountId: currentAccount.id,
        loggedIn: loggedIn,
        clientReady: client.isReady,
        timestamp: Date.now(),
    };
    try {
        localStorage.setItem("securefetch_login_state", JSON.stringify(state));
    } catch (err) {
        console.warn("Failed to save login state:", err);
    }
}

function clearLoginState() {
    try {
        localStorage.removeItem("securefetch_login_state");
    } catch (err) {
        console.warn("Failed to clear login state:", err);
    }
}

async function restoreLoginState(config) {
    try {
        const stateJSON = localStorage.getItem("securefetch_login_state");
        if (!stateJSON) {
            return null;
        }
        const state = JSON.parse(stateJSON);

        // Check if state is stale (older than 24 hours)
        const maxAge = 24 * 60 * 60 * 1000;
        if (Date.now() - state.timestamp > maxAge) {
            clearLoginState();
            return null;
        }

        // Find matching account
        const account = config.accounts?.find((acc) => acc.id === state.accountId);
        if (!account) {
            clearLoginState();
            return null;
        }

        currentAccount = account;
        loggedIn = state.loggedIn || false;

        if (accountSelect) {
            accountSelect.value = account.id;
        }
        renderAccountDetails(account);
        updateControls();

        return {
            account,
            loggedIn: state.loggedIn || false,
            clientReady: state.clientReady || false,
        };
    } catch (err) {
        console.warn("Failed to restore login state:", err);
        clearLoginState();
        return null;
    }
}

async function callSecureEndpoint(endpoint, body, description, allowAutoInit = false) {
    // If not allowing auto init, we ensure client is loaded, but if we need a specific account config
    // we must have called connectSelectedAccount already.
    if (!allowAutoInit && !client.isReady) {
         throw new Error("Login to establish a secure session first");
    }

    if (allowAutoInit && !client.isReady) {
        await connectSelectedAccount();
    }

    const response = await client.fetch(endpoint, body, "json");
    log(`${description} → 200`, response);
    return response;
}

function accountSummary() {
    return {
        account: currentAccount?.id,
        user: currentAccount?.userID,
        roles: currentAccount?.roles,
    };
}

async function handleLogin() {
    requireAccount();
    if (!client.isReady) {
         await connectSelectedAccount();
    }

    const payload = {
        username: currentAccount.userID,
        purpose: "demo-login",
        nonce: randomNonce(),
    };
    await callSecureEndpoint("/api/login", payload, "Login", true);
    loggedIn = true;
    saveLoginState();
    updateControls();
    setStatus(`Logged in as ${currentAccount.label}`, "ok");
}

async function handleSessionState() {
    requireLogin();
    await callSecureEndpoint("/api/session/state", {}, "Session state");
}

async function handleEcho() {
    requireLogin();
    const payload = {
        name: currentAccount?.label,
        message: "Browser echo",
        timestamp: new Date().toISOString(),
    };
    await callSecureEndpoint("/api/echo", payload, "Echo");
}

async function handlePentest() {
    requireLogin();
    const payload = {
        vector: "demo-probe",
        payload: accountSummary(),
        notes: "Triggered from browser lab",
    };
    await callSecureEndpoint("/api/pentest/probe", payload, "Pentest probe");
}

async function handleLogout() {
    requireLogin();
    await callSecureEndpoint("/api/logout", {}, "Logout");
    disconnectClient("Session closed");
    setStatus("Logged out", "idle");
}

document.addEventListener("DOMContentLoaded", () => {
    consoleEl = document.getElementById("console");
    statusEl = document.getElementById("status-indicator");
    accountSelect = document.getElementById("account-select");
    accountDetailsEl = document.getElementById("account-details");
    resetBtn = document.getElementById("reset-btn");
    loginBtn = document.getElementById("login-btn");
    sessionBtn = document.getElementById("session-btn");
    echoBtn = document.getElementById("echo-btn");
    pentestBtn = document.getElementById("pentest-btn");
    logoutBtn = document.getElementById("logout-btn");
    protectedButtons.splice(0, protectedButtons.length, sessionBtn, echoBtn, pentestBtn, logoutBtn);
    updateControls();

    if (accountSelect) {
        accountSelect.addEventListener("change", async (event) => {
            const lab = await labConfigPromise;
            selectAccountById(lab, event.target.value);
            if (client.isReady || loggedIn) {
                disconnectClient("Account switched; session cleared");
            }
        });
    }

    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            disconnectClient("Session reset by user");
        });
    }

    if (loginBtn) {
        loginBtn.addEventListener("click", () => {
            handleLogin().catch((err) => {
                log(`Login error: ${err.message}`);
                setStatus("Error: " + err.message, "error");
            });
        });
    }

    if (sessionBtn) {
        sessionBtn.addEventListener("click", () => {
            handleSessionState().catch((err) => {
                log(`Session state error: ${err.message}`);
            });
        });
    }

    if (echoBtn) {
        echoBtn.addEventListener("click", () => {
            handleEcho().catch((err) => {
                log(`Echo error: ${err.message}`);
            });
        });
    }

    if (pentestBtn) {
        pentestBtn.addEventListener("click", () => {
            handlePentest().catch((err) => {
                log(`Pentest error: ${err.message}`);
            });
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener("click", () => {
            handleLogout().catch((err) => {
                log(`Logout error: ${err.message}`);
            });
        });
    }

    (async () => {
        try {
            await client.init();
            const lab = await labConfigPromise;
            renderAccounts(lab);

            // Try to restore previous session
            const restoredState = await restoreLoginState(lab);
            if (restoredState && restoredState.clientReady) {
                // Reinitialize the client with restored account
                try {
                    const cfg = {
                        baseURL: lab.baseURL,
                        deviceID: restoredState.account.deviceID,
                        deviceSecret: restoredState.account.deviceSecret,
                        userToken: restoredState.account.userToken,
                        handshakePath: lab.handshakePath,
                        capabilityToken: lab.capabilityToken,
                        gateSecrets: lab.gateSecrets,
                        autoHandshake: false, // Don't auto handshake, try to restore first
                    };
                    await window.secureFetchInit(cfg);

                    // Verify the restored session works by checking session state
                    if (restoredState.loggedIn) {
                        try {
                            await client.fetch("/api/session/state", {}, "json");
                            setStatus(`Session restored - ${restoredState.account.label}`, "ok");
                            log("Session successfully restored and verified", {
                                account: restoredState.account.id,
                                loggedIn: true,
                            });
                        } catch (err) {
                            log(`Session verification failed: ${err.message}`);
                            disconnectClient("Stored session expired");
                        }
                    } else {
                        setStatus(`Handshake restored - ${restoredState.account.label}`, "idle");
                        log("Handshake restored, login required");
                    }
                } catch (err) {
                    log(`Session restore failed: ${err.message}`);
                    disconnectClient("Failed to restore session");
                }
            }

            log("Lab config ready", {
                accounts: lab.accounts?.length || 0,
                baseURL: lab.baseURL,
                gateSecretIDs: lab.gateSecrets?.map((s) => s.id) || [],
                sessionRestored: restoredState?.clientReady || false,
            });
        } catch (err) {
            log(`Bootstrap error: ${err.message}`);
        }
    })();
});
