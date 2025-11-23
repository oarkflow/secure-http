const consoleEl = document.getElementById("console");
const statusEl = document.getElementById("status-indicator");
const initForm = document.getElementById("init-form");
const requestForm = document.getElementById("request-form");
const handshakeBtn = document.getElementById("handshake-btn");
const resetBtn = document.getElementById("reset-btn");

let clientReady = false;
const wasmReady = bootWasm();

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
    consoleEl.textContent = `${entry}\n${consoleEl.textContent}`.slice(0, 5000);
}

function setStatus(text, variant = "idle") {
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

function buildDeviceSecret(format, value) {
    const trimmed = value.trim();
    if (!trimmed) {
        throw new Error("Device secret is required");
    }
    switch (format) {
        case "text":
            return trimmed;
        case "base64":
            return trimmed.startsWith("base64:") ? trimmed : `base64:${trimmed}`;
        case "bytes": {
            const parts = trimmed
                .split(/[,\s]+/)
                .filter(Boolean)
                .map((part) => {
                    const num = Number(part.trim());
                    if (!Number.isInteger(num) || num < 0 || num > 255) {
                        throw new Error(`Invalid byte value: ${part}`);
                    }
                    return num;
                });
            if (!parts.length) {
                throw new Error("Provide at least one byte value");
            }
            return new Uint8Array(parts);
        }
        default:
            return trimmed;
    }
}

function parseJSON(value) {
    if (!value || !value.trim()) {
        return null;
    }
    try {
        return JSON.parse(value);
    } catch (err) {
        throw new Error(`Body must be valid JSON: ${err.message}`);
    }
}

initForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
        await wasmReady;
        const form = new FormData(initForm);
        const cfg = {
            baseURL: form.get("baseURL").trim(),
            deviceID: form.get("deviceID").trim(),
            deviceSecret: buildDeviceSecret(form.get("secretFormat"), form.get("deviceSecret")),
            userToken: form.get("userToken").trim() || undefined,
            handshakePath: form.get("handshakePath").trim() || undefined,
            autoHandshake: form.get("autoHandshake") !== null,
        };

        await secureFetchInit(cfg);
        clientReady = true;
        setStatus("Client ready", "ok");
        log("secureFetchInit completed", cfg);
    } catch (err) {
        clientReady = false;
        setStatus("Init failed", "error");
        log(`Init error: ${err.message}`);
    }
});

requestForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
        await wasmReady;
        if (!clientReady) {
            throw new Error("Initialize the client first");
        }
        const form = new FormData(requestForm);
        const body = parseJSON(form.get("body"));
        const req = {
            endpoint: form.get("endpoint").trim(),
            body,
            responseType: form.get("responseType"),
            forceHandshake: form.get("forceHandshake") !== null,
        };
        const response = await secureFetch(req);
        log(`secureFetch → ${req.responseType}`, response);
    } catch (err) {
        log(`Request error: ${err.message}`);
    }
});

handshakeBtn.addEventListener("click", async () => {
    try {
        await wasmReady;
        if (!clientReady) {
            throw new Error("Initialize the client first");
        }
        await secureFetchHandshake(true);
        log("Handshake completed");
        setStatus("Client ready", "ok");
    } catch (err) {
        log(`Handshake error: ${err.message}`);
        setStatus("Handshake failed", "error");
    }
});

resetBtn.addEventListener("click", () => {
    if (typeof secureFetchReset === "function") {
        secureFetchReset();
    }
    clientReady = false;
    setStatus("Not initialized");
    log("secureFetch client reset");
});
