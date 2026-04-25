import test from "node:test";
import assert from "node:assert/strict";

import {
  createSessionStore,
  resolveSessionPayload,
  restoreSession,
} from "../../examples/react-app/src/lib/client/session.js";

test("resolveSessionPayload reads CSRF cookie and builds session config", () => {
  const payload = {
    userID: "todo-alice",
    baseURL: "https://app.example.com",
    bootstrapPath: "/auth/bootstrap",
    handshakePath: "/handshake",
  };

  const resolved = resolveSessionPayload(payload, {
    cookieSource: "securehttp_csrf=csrf-token-123",
    credentials: { username: "alice" },
  });

  assert.equal(resolved.identity, "todo-alice");
  assert.equal(resolved.config.csrfToken, "csrf-token-123");
  assert.equal(resolved.session.config.bootstrapPath, "/auth/bootstrap");
});

test("restoreSession clears saved session when csrf cookie is missing", async () => {
  let cleared = false;
  const sessionStore = {
    load() {
      return {
        identity: "todo-alice",
        config: {
          baseURL: "https://app.example.com",
          bootstrapPath: "/auth/bootstrap",
          handshakePath: "/handshake",
          csrfCookieName: "securehttp_csrf",
          csrfHeaderName: "X-CSRF-Token",
          autoHandshake: true,
        },
      };
    },
    clear() {
      cleared = true;
    },
  };

  const client = {
    async init() {
      throw new Error("client.init should not be called without a csrf cookie");
    },
  };

  const restored = await restoreSession({
    client,
    sessionStore,
    cookieSource: "",
  });

  assert.equal(restored, null);
  assert.equal(cleared, true);
});

test("createSessionStore round-trips data in provided storage", () => {
  const memory = new Map();
  const storage = {
    getItem(key) {
      return memory.has(key) ? memory.get(key) : null;
    },
    setItem(key, value) {
      memory.set(key, value);
    },
    removeItem(key) {
      memory.delete(key);
    },
  };

  const store = createSessionStore({ storage, storageKey: "secure-http-test" });
  store.save({ identity: "todo-bob" });
  assert.deepEqual(store.load(), { identity: "todo-bob" });
  store.clear();
  assert.equal(store.load(), null);
});
