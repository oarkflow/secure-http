# Server SDK Notes

`secure-http` owns the shared protocol contracts and the Node.js server SDK. The Go server SDK and React demo live in `github.com/oarkflow/secure-go`.

## Core Contracts

- Gate requests sign `METHOD`, path, timestamp, nonce, and capability token with HMAC-SHA256.
- Handshake uses P-256 ECDH and device HMAC over client public key plus timestamp.
- Message keys are derived with HKDF-SHA512 and info `secure-communication-v1`.
- Envelopes use AES-256-GCM plus HMAC-SHA256 over nonce, ciphertext, and timestamp.
- Sessions reject replayed encrypted message nonces inside the message TTL.

## Node

Use `sdks/server/node/index.js`:

- `new SecureHttpServerSDK(options)`
- `sdk.createHTTPRequestHandler({ secure })`
- `sdk.buildBootstrapConfig(options)`

The v1 Node SDK intentionally uses Node built-ins only.

## Go

Use `github.com/oarkflow/secure-go` for Fiber and stdlib adapters. During local development, point `secure-go` at this checkout with a Go workspace:

```bash
cd ~/Projects
go work init ./secure-http ./secure-go
```

or with a temporary replace in `secure-go/go.mod`:

```go
replace github.com/oarkflow/secure-http => ../secure-http
```
