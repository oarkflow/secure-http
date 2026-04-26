# Server SDK

This repo now has two reusable Go server-side integration layers:

- `sdks/server/go/fiber/server`: the Fiber-native server SDK.
- `sdks/server/go/stdlib`: a standard `net/http` adapter that speaks the same handshake, gate, decrypt, and encrypt protocol.

On top of that, `sdks/server/go/manifest` exports a portable manifest so non-Go runtimes can implement the same contract without guessing header names, cookie names, or route requirements.

## Go

`net/http`

```go
transport, _ := securehttp.NewStdHTTPMiddleware(policy)

mux := http.NewServeMux()
mux.Handle("/handshake", stdlib.GateMiddleware(gatekeeper)(transport.HandshakeHandler()))
mux.Handle("/api/echo", stdlib.GateMiddleware(gatekeeper)(transport.Secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	_ = stdlib.DecodeJSON(r, &payload)
	_ = json.NewEncoder(w).Encode(payload)
}))))
```

`chi`

Use the same stdlib handlers behind `chi.Router.Handle` or a small adapter middleware; the important bit is that `GateMiddleware(...)` runs before `transport.Secure(...)`.

`echo`

Use `echo.WrapHandler(...)` around the stdlib handlers, or keep the existing Fiber adapter when that is the easier fit.

## Portable Manifest

Build once from your server config:

```go
manifest := securehttp.BuildServerSDKManifest(cfg, securehttp.ServerSDKManifestOptions{
	BaseURL:       "https://api.example.com",
	HandshakePath: "/handshake",
	BootstrapPath: "/auth/bootstrap",
})
```

The manifest contains:

- secure transport headers: `X-Session-ID`, `X-User-Token`
- gate headers: `X-Gate-Key`, `X-Gate-Timestamp`, `X-Gate-Nonce`, `X-Gate-Signature`, `X-Capability-Token`
- cookie and CSRF settings
- gate origin policy
- capability tokens and route rules

That gives Node, PHP, Python, Java, and future runtimes one stable contract to follow.

## Other Languages

The clean split for non-Go SDKs is:

1. Validate the gate headers exactly as described by the manifest.
2. Expose `POST /handshake` using the same request/response JSON structs as `pkg/crypto.HandshakeRequest` and `pkg/crypto.HandshakeResponse`.
3. Store the derived session keys and metadata.
4. Decrypt secure API requests into plaintext before user handlers run.
5. Encrypt successful plaintext responses back into `EncryptedMessage`.
6. Reuse the browser login/bootstrap contract from `pkg/browser` for cookie-backed browser flows.

Suggested mappings:

- Node.js: Express middleware or Fastify hooks around the gate and secure body flow.
- PHP: Laravel middleware, Slim PSR-15 middleware, or plain front-controller wrappers.
- Python: FastAPI/Starlette middleware, Flask `before_request` plus response wrapping.
- Java: Spring `OncePerRequestFilter`, servlet filters, or Micronaut/Vert.x interceptors.

The important part is that every runtime should consume the same manifest and protocol structs so the browser/WASM client and Go client continue to work unchanged.

Reference implementations now live here too:

- Python: `sdks/server/python/secure_http_server_sdk.py`
- PHP: `sdks/server/php/composer.json` with source in `sdks/server/php/src`
- Java: `sdks/server/java/src/main/java/dev/oarkflow/securehttp/server/SecureHttpServerSDK.java`
