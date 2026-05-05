# Secure HTTP Core

`secure-http` is the core protocol and security package for Secure HTTP. It provides reusable Go primitives for the encrypted transport, pre-routing gate, stateless auth helpers, config loading, browser bootstrap contracts, manifests, and the Node.js server SDK.

The Go Fiber/stdlib SDK and React demo live in the sibling project [`github.com/oarkflow/secure-go`](https://github.com/oarkflow/secure-go). Keep demo and Go SDK work there; keep protocol hardening and shared contracts here.

## What Lives Here

- `pkg/crypto`: ECDH session setup, HKDF key derivation, AES-GCM envelopes, HMAC validation, replay defense.
- `pkg/security`: device/user auth interfaces, gatekeeper, capability checks, audit events, stateless token helpers, trusted proxy client-IP handling.
- `pkg/http/server`: reusable `net/http` transport middleware for handshake, decrypt/encrypt, gate, auth, and CSRF flows.
- `pkg/http/client`: Go client protocol implementation.
- `pkg/browser` and `pkg/manifest`: browser bootstrap and portable manifest contracts consumed by SDKs.
- `pkg/wasm/fetch`: WASM secure fetch bridge core.
- `sdks/server/node`: Node.js server SDK using built-in Node modules only.

## Production Configuration

Strict production config must not commit real secrets. Use `env:` references in config files:

```json
{
  "runtime": { "mode": "strict" },
  "auth": {
    "jwt_signing_key": "env:SECURE_HTTP_JWT_SIGNING_KEY"
  },
  "gate": {
    "strict_origin": true,
    "allowed_origins": ["https://app.example.com"],
    "secrets": [
      { "id": "2026-Q2", "secret": "env:SECURE_HTTP_GATE_SECRET_Q2" }
    ]
  }
}
```

Strict mode rejects missing, placeholder, short, demo-like, or committed production-like secrets. It also returns opaque public `404` rejection bodies while preserving detailed audit events internally.

Forwarded client-IP headers are ignored by default. Configure trusted proxy CIDRs only when the app is behind a proxy that strips spoofed forwarding headers:

```json
{
  "proxy": {
    "trusted_cidrs": ["10.0.0.0/8"],
    "forwarded_for_header": "X-Forwarded-For"
  }
}
```

## Node Server SDK

```js
import { SecureHttpServerSDK } from "./sdks/server/node/index.js";

const sdk = new SecureHttpServerSDK({
  handshakePath: "/handshake",
  requireDevice: true,
  requireUser: true,
  gateSecrets: [{ id: "2026-Q2", secret: Buffer.from(process.env.SECURE_HTTP_GATE_SECRET_Q2, "base64") }],
  deviceSecrets: { "device-1": Buffer.from(process.env.SECURE_HTTP_DEVICE_SECRET, "base64") },
  capabilities: [
    { token: process.env.SECURE_HTTP_CAPABILITY_TOKEN, routes: [{ path: "/api/echo", methods: ["POST"] }] },
  ],
  async userAuthenticator(token) {
    return token === process.env.SECURE_HTTP_USER_TOKEN ? { id: "user-1", roles: ["user"] } : null;
  },
});

const handler = sdk.createHTTPRequestHandler({
  secure: {
    "POST /api/echo": async ({ json, deviceID, userContext }) => ({
      ok: true,
      deviceID,
      userID: userContext?.id,
      payload: json(),
    }),
  },
});
```

## Checks

```bash
make test
make build
make vuln
```

Equivalent direct commands:

```bash
go test ./...
go build ./...
npm run test:node
govulncheck ./...
```

## Go SDK And Demo

Use `github.com/oarkflow/secure-go` for:

- Fiber server SDK
- stdlib/`net/http` Go adapter
- React todo demo
- browser/demo Makefile and Playwright e2e workflows

During local development, use a Go workspace or temporary `replace` in `secure-go` so it consumes this local core checkout.
