# Node Server SDK

`sdks/server/node` is the first non-Go server SDK in this repo.

It includes:

- gate verification
- `/handshake` handling
- secure request decrypt / response encrypt flow
- browser login/bootstrap response builders
- an Express adapter

## Minimal HTTP server

```js
import http from "node:http";
import { SecureHttpServerSDK } from "./index.js";

const sdk = new SecureHttpServerSDK({
  handshakePath: "/handshake",
  requireDevice: true,
  requireUser: true,
  allowedOrigins: ["http://localhost:5173"],
  gateSecrets: [{ id: "2026-Q1", secret: Buffer.from("gate-secret-1") }],
  gateSecretStrings: { "2026-Q1": "base64:Z2F0ZS1zZWNyZXQtMQ==" },
  deviceSecrets: { "device-1": Buffer.from("device-secret-1") },
  deviceSecretStrings: { "device-1": "base64:ZGV2aWNlLXNlY3JldC0x" },
  capabilities: [
    { token: "cap-root", routes: [{ path: "/handshake", methods: ["POST"] }, { path: "/api/echo", methods: ["POST"] }] },
  ],
  async userAuthenticator(token) {
    return token === "user-token-1" ? { id: "user-1", roles: ["admin"] } : null;
  },
});

const server = http.createServer(sdk.createHTTPRequestHandler({
  secure: {
    "POST /api/echo": async ({ json, deviceID, userContext }) => ({
      ok: true,
      deviceID,
      userID: userContext?.id || "",
      payload: json(),
    }),
  },
}));

server.listen(8443);
```

## Express

```js
import express from "express";
import { SecureHttpServerSDK, createExpressAdapter } from "./index.js";

const app = express();
const sdk = new SecureHttpServerSDK(config);
const adapter = createExpressAdapter(sdk);

app.post("/handshake", adapter.gate, adapter.handshake);
app.post("/api/echo", adapter.gate, adapter.secure(async ({ json }) => ({ ok: true, payload: json() })));
```

## Browser bootstrap helpers

```js
sdk.buildLoginResponse({
  userID: "user-1",
  baseURL: "https://api.example.com",
  bootstrapPath: "/auth/bootstrap",
});

sdk.buildBootstrapConfig({
  baseURL: "https://api.example.com",
  deviceID: "device-1",
  userToken: "user-token-1",
  capabilityToken: "cap-root",
});
```
