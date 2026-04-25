# Secure HTTP Reference Implementation

This repository shows how to front-load every HTTP request with a pre-routing cryptographic challenge, enforce per-route capability tokens, and keep application payloads encrypted from the client all the way into the handlers. The stack ships with:

- A GoFiber server (`cmd/server`) that loads every secret, capability, and policy from `config/server.json`.
- A hardened Go client (`cmd/client`, `pkg/http/client`) that performs the handshake, encrypts payloads, and reuses sessions.
- A WASM bridge (`pkg/wasm/securefetch`) so browsers can call the same encrypted APIs through `secureFetch`.
- Uniform, opaque error responses plus audit fan-out (console + file + optional webhook).

## Reusable server

The reusable API surface now lives in the root package, so another Go app can stand up the secure server in a couple of lines:

```go
srv, err := securehttp.NewServerFromFile("config/server.json", securehttp.ServerOptions{
	RegisterAPIRoutes: func(api fiber.Router, deps securehttp.ServerDependencies) {
		api.Post("/widgets", createWidget)
	},
})
log.Fatal(srv.Listen(""))
```

For browser/WASM flows, the reusable contract now lives in `pkg/browser`. That package is framework-agnostic, so any Go server can return the same login/bootstrap JSON that the WASM bridge understands, even if it does not use Fiber.

The split is:

- `pkg/browser`: canonical browser login/bootstrap types plus pure Go builders
- `pkg/http/server`: Fiber adapters that produce the same contract from the reusable secure server dependencies
- `pkg/wasm/fetch`: consumes the shared `pkg/browser` bootstrap contract

For clients, you can connect from config in one line:

```go
client, err := securehttp.ConnectClientFromFile("config/client.json")
```

If you want to control the handshake yourself, use `securehttp.NewClientFromFile(...)` and call `Handshake()` when you are ready.

If you are integrating with your own Go server instead of the built-in demo server, the browser flow is:

1. Authenticate the user however your app wants.
2. Return `browser.BuildLoginResponse(...)` or `securehttp.BuildBrowserLoginResponse(...)`.
3. Expose a bootstrap route that returns `browser.BuildBootstrapConfig(...)` or `securehttp.BuildBrowserBootstrapConfig(...)`.
4. Initialize the browser client/WASM bridge with the returned `bootstrapPath`.

## Server quickstart

```bash
SECURE_HTTP_CONFIG=config/server.json go run ./cmd/fullstack
```

Key behaviors:

1. **Gatekeeper** – Every request must include the HMAC-based headers shown in `config/server.json`. Requests with missing/invalid headers are dropped with a fake `404` before hitting Fiber.
2. **Handshake** – `/handshake` is the only public route. It validates the device signature, optional user token, pins the session to the caller's IP+User-Agent fingerprint, and returns the encrypted session envelope.
3. **Encrypted APIs** – `/api/**` handlers only accept encrypted payloads. The middleware decrypts the body, injects the session/user metadata, then re-encrypts the response.
4. **Hijack protection** – If someone steals the `X-Session-ID` header, the request still fails because the session is bound to the original IP/User-Agent fingerprint. Any mismatch is logged, the session is revoked, and the caller receives the same uniform `404`.

Update `config/server.json` with your own gate secrets, device registry entries, users, and capability tokens. All secrets support the prefixes `base64:` and `hex:` so they can live outside the binary.

## Go client workflow

```bash
# Configure via JSON (avoids hard-coded secrets)
SECURE_HTTP_CLIENT_CONFIG=config/client.json go run ./cmd/client
```

The client performs the following steps:

1. Loads device/user credentials plus gate material from `config/client.json`.
2. Runs `Handshake()` **before** calling any encrypted endpoint. This step derives the shared keys and stores the session ID.
3. Uses `PostJSON()` (or `Post`) to talk to `/api/...`. The middleware automatically refreshes the handshake when the session expires.

> ⚠️ **Handshake required** – If you see `Handshake error: Initialize the client first`, it means `secureFetch`/`PostJSON` was called before completing `Handshake()`. Always call `Handshake()` once at startup (or enable `autoHandshake` in the WASM client) before dispatching encrypted requests.

## Browser / secureFetch example

1. Build the WASM bridge and copy Go's runtime shim:

   ```bash
   GOOS=js GOARCH=wasm go build -o web/securefetch-demo/securefetch.wasm ./cmd/securefetchwasm
   cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" web/securefetch-demo/
   ```

2. Serve `web/securefetch-demo` (or embed these calls into your own app) and initialize the client:

   ```html
   <script src="wasm_exec.js"></script>
   <script type="module">
     const go = new Go();
     const { instance } = await WebAssembly.instantiateStreaming(fetch("securefetch.wasm"), go.importObject);
     go.run(instance);

     await window.secureFetchInit({
       baseURL: "https://localhost:8443",
       deviceID: "device-001",
       deviceSecret: "base64:ZGV2aWNlLTAwMS1zZWNyZXQ=",
       gateSecrets: [{ id: "2026-Q1", secret: "base64:Z2F0ZS1zZWNyZXQtMjAyNi1xMQ==" }],
       capabilityToken: "cap-root",
       userToken: "user-token-123",
       autoHandshake: true
     });

     const echo = await window.secureFetch({
       endpoint: "/api/echo",
       body: { name: "Browser", message: "Hello" },
       responseType: "json"
     });
     console.log("Echo response", echo);
   </script>
   ```

`secureFetchInit` must run exactly once per page load. It performs/queues the handshake and stores the session in WASM memory. Subsequent `secureFetch` calls reuse that session until it expires, at which point the bridge silently performs another handshake.

> Demo UI note: When you serve [web/securefetch-demo](web/securefetch-demo), the page automatically loads the curated lab accounts defined in [web/securefetch-demo/lab-config.json](web/securefetch-demo/lab-config.json) so testers only pick from pre-authorized devices instead of pasting secrets into the browser. Update that JSON when you want to rotate demo material.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Handshake error: Initialize the client first` | `secureFetch` or `PostJSON` called before the handshake completed. | Call `secureFetchInit`/`Handshake()` during startup and await the returned promise before issuing API calls. Enable `autoHandshake` in the WASM config for convenience. |
| `404` on every encrypted call | Missing gate headers, wrong capability token, or session fingerprint mismatch. | Ensure the client applied the latest gate secret & capability token and that the call originates from the same IP/User-Agent tuple that created the session. |
| Audit log empty | `alerts.log_file` not writable. | Update `config/server.json` with a path the server process can create (default `logs/audit.log`). |

## Security highlights

- **Pre-routing gate** – Blocks unauthenticated traffic before Fiber, returning indistinguishable `404`s.
- **Encrypted-only APIs** – Payloads stay encrypted over the wire; handlers never see plaintext without passing through the middleware.
- **Session fingerprinting** – Each session is pinned to the requester's IP and User-Agent hash; replayed session IDs are revoked instantly.
- **Capability tokens** – Every capability is scoped to specific routes/methods; adding new endpoints requires explicit tokens.
- **Auditing & alerting** – Console logs + async file writer + optional webhook let you forward incidents to SIEM/Slack/etc.

Customize the configs, drop in your own alert transports, and build on top of the hardened primitives instead of re-implementing crypto or auth plumbing.

## Full-stack test lab

Need a single binary that serves the encrypted API **and** the WASM demo so you can test login flows, persisted sessions, or run a quick pentest drill from one origin? Use the `cmd/fullstack` entrypoint:

```bash
# Build the WASM bridge one time so the static bundle is complete
GOOS=js GOARCH=wasm go build -o web/securefetch-demo/securefetch.wasm ./cmd/securefetchwasm
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" web/securefetch-demo/

# Launch the integrated lab
go run ./cmd/fullstack  -config config/server.json -web web/demo -static-prefix /lab -addr :8443
```

This binary reuses the exact same crypto middleware and gatekeeper configuration, but it also:

- Hosts the static WASM demo beneath the prefix you pick (defaults to `/demo`), so browsers load `index.html`, `securefetch.wasm`, and `wasm_exec.js` over the same origin as the encrypted API.
- Exposes additional secure endpoints for manual verification:
  - `POST /api/login` — Confirms that the current session + user token are valid, returning the bound user/device metadata.
  - `POST /api/session/state` — Shows session issuance time, expiry, and whether the fingerprint binding still matches the caller (proves persistence protections work).
  - `POST /api/logout` — Explicitly invalidates the encrypted session, deletes it server-side, and emits a logout audit event.
  - `POST /api/pentest/probe` — Accepts arbitrary JSON describing an attack vector and records it as an `pentest_probe` audit event so you can validate alert fan-out.
- Provides a browser UI with a login form where users enter their `user_id` and `user_token` credentials. Upon submission:
  1. The client sends credentials to `/login` (unauthenticated endpoint)
  2. Server validates the credentials and returns session configuration (deviceID, deviceSecret, gateSecrets, capabilityToken)
  3. Client initializes the WASM bridge with the returned configuration
  4. Client performs the handshake automatically (`/handshake`)
  5. Client calls `/api/login` (encrypted endpoint) to establish the application session
  6. All subsequent protected API calls use the encrypted channel with proper session binding

Static assets remain unauthenticated so you can load the UI, but every handshake and API call beneath `/api` still requires the pre-HTTP gate headers plus encrypted payloads. That makes it ideal for side-by-side “legit user vs. attacker” exercises or demos where you want to showcase the full secure channel without orchestrating multiple servers.
