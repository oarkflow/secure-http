import "./wasm_exec.js";

/**
 * Configuration for the SecureClient.
 * @typedef {Object} SecureClientConfig
 * @property {string} wasmUrl - URL to the securefetch.wasm file.
 * @property {object} [labConfig] - Configuration for secureFetchInit (baseURL, deviceID, etc).
 */

export class SecureClient {
    /**
     * @param {SecureClientConfig} config
     */
    constructor(config) {
        this.config = config;
        this.wasmUrl = config.wasmUrl;
        this.initPromise = null;
        this.isReady = false;
    }

    /**
     * Initializes the WASM module.
     * @returns {Promise<void>}
     */
    async init() {
        if (this.initPromise) {
            return this.initPromise;
        }

        this.initPromise = (async () => {
            if (typeof Go === "undefined") {
                throw new Error("Go WASM loader not found. Ensure wasm_exec.js is loaded.");
            }

            const go = new Go();
            let result;

            // Support both Node.js (fs) and Browser (fetch) environments if possible,
            // but primarily this is for browser.
            if (typeof fetch !== "undefined") {
                const resp = await fetch(this.wasmUrl);
                if (!resp.ok) {
                    throw new Error(`Failed to fetch WASM from ${this.wasmUrl}: ${resp.status}`);
                }

                // Try instantiateStreaming first, fall back to arrayBuffer
                if (WebAssembly.instantiateStreaming) {
                    try {
                        result = await WebAssembly.instantiateStreaming(resp, go.importObject);
                    } catch (e) {
                         // Fallback if content-type is wrong or streaming not supported
                         const bytes = await resp.arrayBuffer();
                         result = await WebAssembly.instantiate(bytes, go.importObject);
                    }
                } else {
                    const bytes = await resp.arrayBuffer();
                    result = await WebAssembly.instantiate(bytes, go.importObject);
                }
            } else {
                throw new Error("Fetch API not available. This client is for browser environments.");
            }

            // Run the WASM instance - this blocks recursively, so we don't await it?
            // Actually go.run(instance) usually blocks until the program exits.
            // For a service-like WASM, it likely blocks forever or just sets up callbacks.
            // In our case `func Run() { select {} }` blocks forever.
            // So we should NOT await go.run() if it blocks.
            // But we need to make sure callbacks are registered.
            // The Go side usually registers callbacks before blocking.

            // We'll run it without awaiting, but we might need a small delay or a signal
            // to know it's ready. The Go code registers callbacks then blocks.
            go.run(result.instance);

            // Wait for global functions to be available
            await this._waitForGlobals();

            // Initialize the internal client if config is provided
            if (this.config.labConfig) {
                await window.secureFetchInit(this.config.labConfig);
            }

            this.isReady = true;
        })();

        return this.initPromise;
    }

    async _waitForGlobals() {
        const timeout = 2000;
        const start = Date.now();
        while (Date.now() - start < timeout) {
            if (typeof window.secureFetch === "function") {
                return;
            }
            await new Promise(r => setTimeout(r, 50));
        }
        throw new Error("Timeout waiting for secureFetch globals");
    }

    /**
     * Performs a secure fetch request.
     * @param {string} endpoint
     * @param {object} body
     * @param {string} [responseType="json"]
     * @returns {Promise<any>}
     */
    async fetch(endpoint, body, responseType = "json") {
        await this.init();
        return window.secureFetch({
            endpoint,
            body,
            responseType
        });
    }

    /**
     * Forces a handshake.
     * @param {boolean} force
     * @returns {Promise<void>}
     */
    async handshake(force = false) {
        await this.init();
        return window.secureFetchHandshake(force);
    }

    /**
     * Resets the client session.
     * @returns {Promise<void>}
     */
    async reset() {
        if (typeof window.secureFetchReset === "function") {
            window.secureFetchReset();
        }
        this.isReady = false;
        this.initPromise = null;
    }
}
