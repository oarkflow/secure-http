const DEFAULT_READY_TIMEOUT_MS = 4000;

function isBrowserLikeObject(value) {
    return value !== null && typeof value === "object";
}

function normalizeResponseType(responseType) {
    return responseType || "json";
}

function normalizeMethod(method, fallback = "POST") {
    return String(method || fallback).toUpperCase();
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function readCookieValue(name, source) {
    const cookieSource = typeof source === "string" ? source : "";
    const prefix = `${name}=`;
    const entries = cookieSource ? cookieSource.split("; ") : [];
    for (const entry of entries) {
        if (entry.startsWith(prefix)) {
            return decodeURIComponent(entry.slice(prefix.length));
        }
    }
    return "";
}

function normalizeGateSecrets(gateSecrets) {
    if (!Array.isArray(gateSecrets)) {
        return [];
    }
    const now = Date.now();
    return gateSecrets
        .filter((entry) => isBrowserLikeObject(entry) && entry.id && entry.secret)
        .map((entry) => {
            const notBefore = entry.notBefore || entry.not_before || "";
            const expiresAt = entry.expiresAt || entry.expires_at || "";
            return {
                ...entry,
                id: String(entry.id).trim(),
                notBefore,
                expiresAt,
                _notBeforeMs: notBefore ? Date.parse(notBefore) : Number.NEGATIVE_INFINITY,
                _expiresAtMs: expiresAt ? Date.parse(expiresAt) : Number.POSITIVE_INFINITY,
            };
        })
        .filter((entry) => entry.id && !Number.isNaN(entry._notBeforeMs) && !Number.isNaN(entry._expiresAtMs))
        .filter((entry) => entry._notBeforeMs <= now && now <= entry._expiresAtMs)
        .sort((a, b) => b._notBeforeMs - a._notBeforeMs)
        .map(({ _notBeforeMs, _expiresAtMs, ...entry }) => entry);
}

function normalizeLabConfig(labConfig) {
    if (!labConfig) {
        return null;
    }
    const normalized = { ...labConfig };
    normalized.baseURL = String(labConfig.baseURL || "").trim();
    normalized.deviceID = String(labConfig.deviceID || "").trim();
    normalized.capabilityToken = String(labConfig.capabilityToken || "").trim();
    normalized.handshakePath = String(labConfig.handshakePath || "/handshake").trim();
    normalized.bootstrapPath = String(labConfig.bootstrapPath || "/bootstrap").trim();
    normalized.csrfHeaderName = String(labConfig.csrfHeaderName || "X-CSRF-Token").trim();
    normalized.csrfCookieName = String(labConfig.csrfCookieName || "securehttp_csrf").trim();
    normalized.csrfToken = String(labConfig.csrfToken || "").trim();
    normalized.autoHandshake = labConfig.autoHandshake !== false;
    normalized.gateSecrets = normalizeGateSecrets(labConfig.gateSecrets);
    normalized.accessToken = String(labConfig.accessToken || "").trim();
    if (!normalized.baseURL) {
        throw new Error("labConfig.baseURL is required");
    }
    const hasDirectSecrets = Boolean(normalized.deviceID && normalized.deviceSecret && normalized.capabilityToken && normalized.gateSecrets.length > 0);
    const hasBootstrapFlow = Boolean(normalized.bootstrapPath);
    if (!hasDirectSecrets && !hasBootstrapFlow) {
        throw new Error("labConfig requires direct secrets or bootstrapPath");
    }
    return normalized;
}

async function toUint8Array(fileLike) {
    const hasFileCtor = typeof File !== "undefined";
    const hasBlobCtor = typeof Blob !== "undefined";
    if (hasFileCtor && fileLike instanceof File) {
        return {
            data: new Uint8Array(await fileLike.arrayBuffer()),
            filename: fileLike.name,
            contentType: fileLike.type || "application/octet-stream",
        };
    }
    if (hasBlobCtor && fileLike instanceof Blob) {
        return {
            data: new Uint8Array(await fileLike.arrayBuffer()),
            filename: "blob",
            contentType: fileLike.type || "application/octet-stream",
        };
    }
    if (fileLike instanceof Uint8Array) {
        return {
            data: fileLike,
            filename: "file",
            contentType: "application/octet-stream",
        };
    }
    throw new Error("File must be File, Blob, or Uint8Array");
}

async function sha256Base64(bytes, cryptoRef) {
    if (!cryptoRef?.subtle) {
        throw new Error("SubtleCrypto is unavailable for integrity verification");
    }
    const digest = await cryptoRef.subtle.digest("SHA-256", bytes);
    const view = new Uint8Array(digest);
    let output = "";
    for (const value of view) {
        output += String.fromCharCode(value);
    }
    return btoa(output);
}

export class SecureHttpClient {
    constructor(config) {
        this.config = { ...(config || {}) };
        this.wasmUrl = this.config.wasmUrl;
        this.windowRef = this.config.windowRef || globalThis;
        this.fetchImpl = this.config.fetchImpl || this.windowRef?.fetch?.bind(this.windowRef) || globalThis.fetch?.bind(globalThis);
        this.WebAssemblyRef = this.config.WebAssemblyRef || globalThis.WebAssembly;
        this.cryptoRef = this.config.cryptoRef || globalThis.crypto;
        this.GoClass = this.config.GoClass || globalThis.Go;
        this.readyTimeoutMs = this.config.readyTimeoutMs || DEFAULT_READY_TIMEOUT_MS;
        this.initPromise = null;
        this.state = "idle";
        this.labConfig = normalizeLabConfig(this.config.labConfig);
        this.appliedConfigKey = null;
    }

    get isReady() {
        return this.state === "ready";
    }

    set isReady(value) {
        this.state = value ? "ready" : "idle";
    }

    async init(nextConfig) {
        if (nextConfig) {
            this.configure(nextConfig);
        }
        if (this.initPromise) {
            await this.initPromise;
            if (this.labConfig) {
                await this.applyLabConfig();
            }
            return;
        }
        this.state = "initializing";
        this.initPromise = this.bootstrap();
        try {
            await this.initPromise;
        } catch (error) {
            this.state = "error";
            this.initPromise = null;
            throw error;
        }
    }

    configure(labConfig) {
        this.labConfig = normalizeLabConfig(labConfig);
        return this.labConfig;
    }

    configKey() {
        if (!this.labConfig) {
            return null;
        }
        return JSON.stringify(this.labConfig);
    }

    refreshCSRFToken() {
        if (!this.labConfig) {
            return;
        }
        const cookieName = this.labConfig.csrfCookieName || "securehttp_csrf";
        const nextToken = readCookieValue(cookieName, this.windowRef?.document?.cookie || "");
        if (nextToken) {
            this.labConfig = {
                ...this.labConfig,
                csrfToken: nextToken,
            };
        }
    }

    async applyLabConfig() {
        if (!this.labConfig) {
            return;
        }
        if (!this.hasBridge()) {
            throw new Error("secureFetch bridge is not ready");
        }
        const nextKey = this.configKey();
        if (nextKey === this.appliedConfigKey) {
            return;
        }
        await this.windowRef.secureFetchInit(this.labConfig);
        this.appliedConfigKey = nextKey;
        this.state = "ready";
    }

    async bootstrap() {
        if (!this.wasmUrl) {
            throw new Error("wasmUrl is required");
        }
        if (typeof this.GoClass !== "function") {
            throw new Error("Go WASM loader not found. Ensure wasm_exec.js is loaded.");
        }
        if (typeof this.fetchImpl !== "function") {
            throw new Error("Fetch API not available.");
        }
        if (!this.WebAssemblyRef) {
            throw new Error("WebAssembly is unavailable.");
        }

        const go = new this.GoClass();
        const response = await this.fetchImpl(this.wasmUrl, { integrity: this.config.wasmIntegrity });
        if (!response?.ok) {
            throw new Error(`Failed to fetch WASM from ${this.wasmUrl}: ${response?.status ?? "unknown"}`);
        }

        const bytes = await response.arrayBuffer();
        if (this.config.expectedWasmSha256) {
            const digest = await sha256Base64(bytes, this.cryptoRef);
            if (digest !== this.config.expectedWasmSha256) {
                throw new Error("WASM integrity check failed");
            }
        }

        const instanceResult = await this.WebAssemblyRef.instantiate(bytes, go.importObject);
        Promise.resolve(go.run(instanceResult.instance)).catch(() => {});
        await this.waitForBridge();
        await this.applyLabConfig();
        this.state = "ready";
    }

    async waitForBridge() {
        const start = Date.now();
        while (Date.now() - start < this.readyTimeoutMs) {
            if (this.hasBridge()) {
                return;
            }
            await sleep(25);
        }
        throw new Error("Timeout waiting for secureFetch bridge");
    }

    hasBridge() {
        return (
            typeof this.windowRef?.secureFetchInit === "function" &&
            typeof this.windowRef?.secureFetch === "function" &&
            typeof this.windowRef?.secureFetchHandshake === "function" &&
            typeof this.windowRef?.secureFetchReset === "function"
        );
    }

    async ensureConfigured() {
        await this.init();
        if (!this.labConfig) {
            throw new Error("SecureHttp client is not configured");
        }
    }

    async handshake(force = false) {
        await this.ensureConfigured();
        await this.windowRef.secureFetchHandshake(Boolean(force));
        this.state = "ready";
    }

    isRecoverableSessionError(error) {
        const message = String(error?.message || error || "").toLowerCase();
        return message.includes("session expired or missing") ||
            message.includes("request failed with status 404") ||
            message.includes("request failed with status 401") ||
            message.includes("request failed with status 403") ||
            message.includes("missing authorization token") ||
            message.includes("invalid token") ||
            message.includes("session not found") ||
            message.includes("fingerprint mismatch") ||
            message.includes("missing session");
    }

    async recoverSession() {
        if (!this.labConfig) {
            throw new Error("SecureHttp client is not configured");
        }
        this.refreshCSRFToken();
        if (typeof this.windowRef?.secureFetchReset === "function") {
            this.windowRef.secureFetchReset();
        }
        this.appliedConfigKey = null;
        this.state = "recovering";
        await this.applyLabConfig();
        this.state = "ready";
    }

    async performRequest(payload) {
        try {
            return await this.windowRef.secureFetch(payload);
        } catch (error) {
            if (!this.isRecoverableSessionError(error)) {
                throw error;
            }
            await this.recoverSession();
            return this.windowRef.secureFetch({
                ...payload,
                forceHandshake: true,
            });
        }
    }

    async request(request) {
        await this.ensureConfigured();
        const payload = {
            endpoint: request.endpoint,
            body: request.body ?? null,
            responseType: normalizeResponseType(request.responseType),
            method: normalizeMethod(request.method),
            forceHandshake: Boolean(request.forceHandshake),
        };
        return this.performRequest(payload);
    }

    async fetch(endpoint, body, responseType = "json", method = "POST") {
        return this.request({ endpoint, body, responseType, method });
    }

    async get(endpoint, responseType = "json") {
        return this.request({ endpoint, responseType, method: "GET" });
    }

    async post(endpoint, body, responseType = "json") {
        return this.request({ endpoint, body, responseType, method: "POST" });
    }

    async put(endpoint, body, responseType = "json") {
        return this.request({ endpoint, body, responseType, method: "PUT" });
    }

    async delete(endpoint, responseType = "json") {
        return this.request({ endpoint, responseType, method: "DELETE" });
    }

    async patch(endpoint, body, responseType = "json") {
        return this.request({ endpoint, body, responseType, method: "PATCH" });
    }

    async uploadFile(endpoint, file, filename, fieldName = "file", formData = {}, responseType = "json") {
        await this.ensureConfigured();
        const normalized = await toUint8Array(file);
        return this.performRequest({
            endpoint,
            file: normalized.data,
            filename: filename || normalized.filename,
            fieldName,
            formData: {
                ...formData,
                "__file_content_type__": normalized.contentType,
            },
            responseType: normalizeResponseType(responseType),
            method: "POST",
        });
    }

    async reset() {
        if (typeof this.windowRef?.secureFetchReset === "function") {
            this.windowRef.secureFetchReset();
        }
        this.appliedConfigKey = null;
        this.state = "idle";
        this.initPromise = null;
    }
}

export class SecureClient extends SecureHttpClient {}

export function createSecureHttpClient(config) {
    return new SecureHttpClient(config);
}
