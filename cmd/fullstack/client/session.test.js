import test from "node:test";
import assert from "node:assert/strict";

import {
    createSessionStore,
    isSessionAuthError,
    loginWithCredentials,
    logoutSession,
    readCookieValue,
    resolveSessionPayload,
    restoreSession,
} from "./session.js";

test("readCookieValue returns decoded cookie content", () => {
    assert.equal(readCookieValue("token", "a=1; token=hello%20world"), "hello world");
    assert.equal(readCookieValue("missing", "a=1"), "");
});

test("createSessionStore persists and clears sessions", () => {
    const backing = new Map();
    const storage = {
        getItem(key) {
            return backing.has(key) ? backing.get(key) : null;
        },
        setItem(key, value) {
            backing.set(key, value);
        },
        removeItem(key) {
            backing.delete(key);
        },
    };
    const store = createSessionStore({ storage });
    store.save({ identity: "alice" });
    assert.deepEqual(store.load(), { identity: "alice" });
    store.clear();
    assert.equal(store.load(), null);
});

test("isSessionAuthError detects bootstrap auth failures", () => {
    assert.equal(isSessionAuthError(new Error("bootstrap failed with status 401")), true);
    assert.equal(isSessionAuthError(new Error("something else")), false);
});

test("resolveSessionPayload normalizes login payload into secure client config", () => {
    const resolved = resolveSessionPayload(
        {
            userID: "alice",
            baseURL: "http://localhost:9443",
            bootstrapPath: "/auth/bootstrap",
        },
        {
            cookieSource: "securehttp_csrf=csrf-token",
        }
    );

    assert.equal(resolved.identity, "alice");
    assert.equal(resolved.config.csrfToken, "csrf-token");
    assert.equal(resolved.session.identity, "alice");
});

test("resolveSessionPayload prefers explicit baseURL over backend payload baseURL", () => {
    const resolved = resolveSessionPayload(
        {
            userID: "alice",
            baseURL: "http://127.0.0.1:9443",
        },
        {
            baseURL: "http://localhost:9443",
            cookieSource: "securehttp_csrf=csrf-token",
        }
    );

    assert.equal(resolved.config.baseURL, "http://localhost:9443");
});

test("loginWithCredentials initializes the secure client and saves session state", async () => {
    const initCalls = [];
    const store = createSessionStore({
        storage: {
            getItem() { return null; },
            setItem() {},
            removeItem() {},
        },
    });
    const result = await loginWithCredentials({
        client: {
            async init(config) {
                initCalls.push(config);
            },
        },
        credentials: { username: "alice", password: "secret" },
        cookieSource: "securehttp_csrf=test-token",
        fetchImpl: async () => ({
            ok: true,
            async json() {
                return {
                    userID: "alice",
                    baseURL: "http://localhost:9443",
                    bootstrapPath: "/auth/bootstrap",
                };
            },
        }),
        sessionStore: store,
        windowRef: { location: { origin: "http://localhost:9443" } },
    });

    assert.equal(result.identity, "alice");
    assert.equal(initCalls[0].csrfToken, "test-token");
    assert.equal(result.session.identity, "alice");
});

test("restoreSession rehydrates config from storage and cookie state", async () => {
    const initCalls = [];
    const store = createSessionStore({
        storage: {
            getItem() {
                return JSON.stringify({
                    identity: "alice",
                    config: {
                        baseURL: "http://localhost:9443",
                        csrfCookieName: "securehttp_csrf",
                    },
                });
            },
            setItem() {},
            removeItem() {},
        },
    });

    const restored = await restoreSession({
        client: {
            async init(config) {
                initCalls.push(config);
            },
        },
        cookieSource: "securehttp_csrf=restored-token",
        sessionStore: store,
    });

    assert.equal(restored.identity, "alice");
    assert.equal(initCalls[0].csrfToken, "restored-token");
});

test("restoreSession prefers explicit baseURL over saved session config", async () => {
    const initCalls = [];
    const store = createSessionStore({
        storage: {
            getItem() {
                return JSON.stringify({
                    identity: "alice",
                    config: {
                        baseURL: "http://127.0.0.1:9443",
                        csrfCookieName: "securehttp_csrf",
                    },
                });
            },
            setItem() {},
            removeItem() {},
        },
    });

    await restoreSession({
        baseURL: "http://localhost:9443",
        client: {
            async init(config) {
                initCalls.push(config);
            },
        },
        cookieSource: "securehttp_csrf=restored-token",
        sessionStore: store,
    });

    assert.equal(initCalls[0].baseURL, "http://localhost:9443");
});

test("logoutSession clears client and session", async () => {
    const calls = [];
    const store = createSessionStore({
        storage: {
            getItem() { return null; },
            setItem() {},
            removeItem() {
                calls.push("cleared");
            },
        },
    });

    await logoutSession({
        client: {
            isReady: true,
            async reset() {
                calls.push("reset");
            },
        },
        cookieSource: "securehttp_csrf=csrf-token",
        fetchImpl: async (url, options) => {
            calls.push({ url, options });
            return { ok: true };
        },
        logoutUrl: "/auth/logout",
        sessionStore: store,
    });

    assert.equal(calls[0].url, "/auth/logout");
    assert.equal(calls[1], "reset");
    assert.equal(calls[2], "cleared");
});
