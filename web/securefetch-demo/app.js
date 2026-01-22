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

let clientReady = false;
let loggedIn = false;
let currentAccount = null;
const wasmReady = bootWasm();
const labConfigPromise = loadLabConfig();
const protectedButtons = [];

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

async function bootWasm() {
    if (typeof Go === "undefined") {
        const msg = "wasm_exec.js not loaded. Copy $(go env GOROOT)/misc/wasm/wasm_exec.js next to app.js.";
        log(msg);
        throw new Error(msg);
    }
    const go = new Go();
    const resp = await fetch("securefetch.wasm");
    if (!resp.ok) {
        throw new Error(`Failed to fetch securefetch.wasm: ${resp.status}`);
    }
    const result = await WebAssembly.instantiateStreaming(resp, go.importObject);
    go.run(result.instance);
    log("securefetch.wasm loaded");
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
        resetBtn.disabled = !clientReady && !loggedIn;
    }
}

updateControls();

async function ensureClientReady(allowAutoInit = false) {
    await wasmReady;
    if (clientReady) {
        return;
    }
    if (!allowAutoInit) {
        throw new Error("Login to establish a secure session first");
    }
    await connectSelectedAccount();
}

async function connectSelectedAccount() {
    const lab = await labConfigPromise;
    requireAccount();
    await wasmReady;
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
    await secureFetchInit(cfg);
    clientReady = true;
    loggedIn = false;
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
    if (typeof secureFetchReset === "function") {
        secureFetchReset();
    }
    clientReady = false;
    loggedIn = false;
    updateControls();
    setStatus("Not connected");
    log(message);
}

function randomNonce() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function callSecureEndpoint(endpoint, body, description, allowAutoInit = false) {
    await ensureClientReady(allowAutoInit);
    const response = await secureFetch({
        endpoint,
        body,
        responseType: "json",
    });
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
    const payload = {
        username: currentAccount.userID,
        purpose: "demo-login",
        nonce: randomNonce(),
    };
    await callSecureEndpoint("/api/login", payload, "Login", true);
    loggedIn = true;
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
            if (clientReady || loggedIn) {
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
            const lab = await labConfigPromise;
            renderAccounts(lab);
            log("Lab config ready", {
                accounts: lab.accounts?.length || 0,
                baseURL: lab.baseURL,
                gateSecretIDs: lab.gateSecrets?.map((s) => s.id) || [],
            });
        } catch (err) {
            log(`Bootstrap error: ${err.message}`);
        }
    })();
});
