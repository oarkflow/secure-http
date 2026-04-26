# Server SDKs

This folder is the new home for reusable server-side SDKs.

The repo now separates three concerns cleanly:

- `sdks/server/go/fiber/server`: Go Fiber server integration.
- `sdks/server/go/stdlib`: Go `net/http` integration that also fits `chi`, `echo.WrapHandler`, and similar servers.
- `sdks/server/*`: language-facing server SDKs and framework adapters.

## What is available now

- Go: production-ready via `sdks/server/go/stdlib` and `sdks/server/go/fiber/server`.
- Node.js: production-ready reference SDK in [node](./node/README.md).
- Python: reference core SDK in [python/secure_http_server_sdk.py](./python/secure_http_server_sdk.py).
- PHP: Composer library in [php/composer.json](./php/composer.json) with source under [php/src](./php/src).
- Java: reference core SDK in [java/src/main/java/dev/oarkflow/securehttp/server/SecureHttpServerSDK.java](./java/src/main/java/dev/oarkflow/securehttp/server/SecureHttpServerSDK.java).

## Shared contract

Every server SDK in this repo is expected to implement the same transport contract:

1. Gate verification before route execution.
2. `POST /handshake` using the canonical handshake JSON fields.
3. Session storage derived from ECDH + HKDF.
4. Secure request decryption before user handlers run.
5. Secure response encryption after user handlers return.
6. Shared browser login/bootstrap payloads for cookie-backed browser clients.

Use [manifest.schema.json](./manifest.schema.json) with [go/manifest/manifest.go](./go/manifest/manifest.go) as the canonical portable contract.
