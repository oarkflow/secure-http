import test from "node:test";
import assert from "node:assert/strict";

import { SecureHttpClient } from "../../examples/react-app/src/lib/client/secure_http.js";

test("SecureHttpClient rejects insecure non-local origins", () => {
  assert.throws(
    () =>
      new SecureHttpClient({
        wasmUrl: "https://cdn.example.com/fetch.wasm",
        labConfig: {
          baseURL: "http://example.com",
          bootstrapPath: "/auth/bootstrap",
        },
      }),
    /must use HTTPS outside trusted local development hosts/,
  );
});

test("SecureHttpClient retries recoverable session failures with refreshed csrf token", async () => {
  const calls = [];
  let requestCount = 0;

  const windowRef = {
    document: {
      cookie: "securehttp_csrf=rotated-token",
    },
    async secureFetch(payload) {
      requestCount += 1;
      calls.push({ type: "fetch", payload });
      if (requestCount === 1) {
        throw new Error("request failed with status 404");
      }
      return { ok: true, payload };
    },
    secureFetchReset() {
      calls.push({ type: "reset" });
    },
    async secureFetchHandshake() {
      calls.push({ type: "handshake" });
    },
    async secureFetchInit(config) {
      calls.push({ type: "init", config });
    },
  };

  const client = new SecureHttpClient({
    wasmUrl: "http://localhost:5173/fetch.wasm",
    windowRef,
    labConfig: {
      baseURL: "http://localhost:8443",
      bootstrapPath: "/auth/bootstrap",
      csrfCookieName: "securehttp_csrf",
      csrfToken: "stale-token",
    },
  });

  client.state = "ready";

  const response = await client.performRequest({
    endpoint: "/api/todos",
    method: "POST",
    body: { title: "hello" },
  });

  assert.equal(response.ok, true);
  assert.equal(calls[0].type, "fetch");
  assert.equal(calls[1].type, "reset");
  assert.equal(calls[2].type, "init");
  assert.equal(calls[2].config.csrfToken, "rotated-token");
  assert.equal(calls[3].type, "fetch");
  assert.equal(calls[3].payload.forceHandshake, true);
});
