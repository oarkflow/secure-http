import test from "node:test";
import assert from "node:assert/strict";

import { SecureHttpClient } from "./secure_http.js";

function createResponse(bytes, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        async arrayBuffer() {
            return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        },
    };
}

test("SecureHttpClient configures and sends requests through the bridge", async () => {
    const calls = [];
    class GoMock {
        constructor() {
            this.importObject = {};
        }
        async run() {}
    }
    const bridge = {
        async secureFetchInit(config) {
            calls.push({ type: "init", config });
        },
        async secureFetch(request) {
            calls.push({ type: "request", request });
            return { ok: true, request };
        },
        async secureFetchHandshake(force) {
            calls.push({ type: "handshake", force });
        },
        secureFetchReset() {
            calls.push({ type: "reset" });
        },
    };

    const client = new SecureHttpClient({
        wasmUrl: "/fetch.wasm",
        windowRef: bridge,
        GoClass: GoMock,
        WebAssemblyRef: {
            async instantiate() {
                return { instance: {} };
            },
        },
        fetchImpl: async () => createResponse(new Uint8Array([1, 2, 3])),
        labConfig: {
            baseURL: "http://localhost:8443",
            deviceID: "device-1",
            deviceSecret: "base64:ZGV2aWNlLXNlY3JldA==",
            capabilityToken: "cap-root",
            gateSecrets: [
                { id: "future", secret: "a", notBefore: "2999-01-01T00:00:00Z" },
                { id: "active", secret: "b", notBefore: "2025-01-01T00:00:00Z", expiresAt: "2999-01-01T00:00:00Z" },
            ],
        },
    });

    await client.init();
    assert.equal(client.isReady, true);
    assert.equal(calls[0].type, "init");
    assert.equal(calls[0].config.gateSecrets.length, 1);
    assert.equal(calls[0].config.gateSecrets[0].id, "active");

    const response = await client.request({ endpoint: "/api/echo", body: { ok: true }, method: "post" });
    assert.equal(response.ok, true);
    assert.equal(calls[1].request.method, "POST");

    await client.handshake(true);
    assert.equal(calls[2].force, true);

    await client.reset();
    assert.equal(client.isReady, false);
    assert.equal(calls[3].type, "reset");
});

test("SecureHttpClient rejects invalid lab config", async () => {
    assert.throws(
        () =>
            new SecureHttpClient({
                wasmUrl: "/fetch.wasm",
                labConfig: {
                    bootstrapPath: "/bootstrap",
                },
            }),
        /baseURL/
    );
});

test("SecureHttpClient applies login config after the runtime was already initialized", async () => {
    const calls = [];
    class GoMock {
        constructor() {
            this.importObject = {};
        }
        async run() {}
    }
    const bridge = {
        async secureFetchInit(config) {
            calls.push({ type: "init", config });
        },
        async secureFetch(request) {
            calls.push({ type: "request", request });
            return { ok: true };
        },
        async secureFetchHandshake(force) {
            calls.push({ type: "handshake", force });
        },
        secureFetchReset() {
            calls.push({ type: "reset" });
        },
    };
    const client = new SecureHttpClient({
        wasmUrl: "/fetch.wasm",
        windowRef: bridge,
        GoClass: GoMock,
        WebAssemblyRef: {
            async instantiate() {
                return { instance: {} };
            },
        },
        fetchImpl: async () => createResponse(new Uint8Array([1, 2, 3])),
    });

    await client.init();
    assert.equal(calls.length, 0);

    await client.init({
        baseURL: "http://localhost:8443",
        deviceID: "device-1",
        deviceSecret: "base64:ZGV2aWNlLXNlY3JldA==",
        capabilityToken: "cap-root",
        gateSecrets: [
            { id: "active", secret: "b", notBefore: "2025-01-01T00:00:00Z", expiresAt: "2999-01-01T00:00:00Z" },
        ],
        autoHandshake: true,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].type, "init");

    await client.fetch("/api/login", { ok: true }, "json");
    assert.equal(calls[1].type, "request");
});

test("SecureHttpClient accepts gate secrets without explicit activation windows", async () => {
    class GoMock {
        constructor() {
            this.importObject = {};
        }
        async run() {}
    }
    const bridge = {
        async secureFetchInit() {},
        async secureFetch() { return { ok: true }; },
        async secureFetchHandshake() {},
        secureFetchReset() {},
    };

    const client = new SecureHttpClient({
        wasmUrl: "/fetch.wasm",
        windowRef: bridge,
        GoClass: GoMock,
        WebAssemblyRef: {
            async instantiate() {
                return { instance: {} };
            },
        },
        fetchImpl: async () => createResponse(new Uint8Array([1, 2, 3])),
        labConfig: {
            baseURL: "http://localhost:8443",
            deviceID: "device-1",
            deviceSecret: "base64:ZGV2aWNlLXNlY3JldA==",
            capabilityToken: "cap-root",
            gateSecrets: [{ id: "active", secret: "b" }],
        },
    });

    await client.init();
    assert.equal(client.isReady, true);
});

test("SecureHttpClient accepts bootstrap-only config without exposing transport secrets to JS", async () => {
    class GoMock {
        constructor() {
            this.importObject = {};
        }
        async run() {}
    }
    const calls = [];
    const bridge = {
        async secureFetchInit(config) {
            calls.push(config);
        },
        async secureFetch() { return { ok: true }; },
        async secureFetchHandshake() {},
        secureFetchReset() {},
    };

    const client = new SecureHttpClient({
        wasmUrl: "/fetch.wasm",
        windowRef: bridge,
        GoClass: GoMock,
        WebAssemblyRef: {
            async instantiate() {
                return { instance: {} };
            },
        },
        fetchImpl: async () => createResponse(new Uint8Array([1, 2, 3])),
        labConfig: {
            baseURL: "http://localhost:8443",
            bootstrapPath: "/bootstrap",
            userToken: "user-token",
        },
    });

    await client.init();
    assert.equal(client.isReady, true);
    assert.equal(calls[0].bootstrapPath, "/bootstrap");
    assert.equal("deviceSecret" in calls[0], false);
});
