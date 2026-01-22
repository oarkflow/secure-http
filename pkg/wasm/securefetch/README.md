# secureFetch WASM bridge

This package exposes the secure HTTP client over WebAssembly so that browsers can call the encrypted APIs without relying on the standard `fetch` primitive.

## Building the module

```bash
GOOS=js GOARCH=wasm go build -o securefetch.wasm ./cmd/securefetchwasm
```

Load Go's runtime JavaScript shim before instantiating the module:

```html
<script src="https://ssl.gstatic.com/webp/wasm/go1.23.0/go.wasm.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("securefetch.wasm"), go.importObject).then((result) => {
    go.run(result.instance);
  });
</script>
```

## Runtime API

The module registers four globals on `window`:

- `secureFetchInit(config)` – configures the client. Required fields: `baseURL`, `deviceID`, `deviceSecret`, `capabilityToken`, and at least one `gateSecret`. Provide gate material either as `gateSecrets: [{ id: "2026-Q1", secret: "base64:..." }]` or via the shorthand `gateSecretID` + `gateSecret`. Optional fields: `userToken`, `handshakePath`, `timeoutMs`, `autoHandshake` (defaults to `true`), `gateNonceBytes`. Secrets accept UTF-8 strings, `Uint8Array`s, or `base64:`-prefixed strings.
- `secureFetch(request)` – sends an encrypted POST. Required field: `endpoint` (or `url`). Optional: `body`, `responseType` (`json`, `text`, `bytes`), `forceHandshake` (bool). Returns a `Promise` that resolves with the decrypted payload.
- `secureFetchHandshake(force)` – forces a handshake (default `false`). Returns a `Promise`.
- `secureFetchReset()` – clears the current client/session.

### Example

```js
await secureFetchInit({
  baseURL: "https://secure.example.com",
  deviceID: "device-001",
  deviceSecret: "base64:ZGV2LXNlY3JldA==",
  gateSecrets: [
    { id: "2026-Q1", secret: "base64:Z2F0ZS1sYXllci0x" },
  ],
  capabilityToken: "cap-root",
  userToken: "user-token-123",
});

const echo = await secureFetch({
  endpoint: "/api/echo",
  body: { name: "Browser", message: "Hello" },
  responseType: "json",
});
console.log(echo);
```

Concurrent calls to `secureFetch` share the same session and the middleware guarantees that only one handshake runs at a time, even when many requests need a renewal simultaneously.

## Browser demo client

The folder `web/securefetch-demo` contains a minimal UI that wires `secureFetchInit`, `secureFetch`, `secureFetchHandshake`, and `secureFetchReset` exactly as documented above. To run it:

1. Build the WASM binary and copy it into the demo directory:

  ```bash
  GOOS=js GOARCH=wasm go build -o web/securefetch-demo/securefetch.wasm ./cmd/securefetchwasm
  ```

2. Copy Go's runtime shim next to the HTML file (once per Go install):

  ```bash
  cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" web/securefetch-demo/
  ```

3. Serve the folder with any static server (Vite, `python -m http.server`, nginx, etc.) and open it in a browser that supports WebAssembly.

### Serve with Go

Prefer to keep everything Go-native? Use the bundled helper:

```bash
go run ./cmd/securefetchweb -addr :8082 -dir web/securefetch-demo
```

It automatically registers the correct MIME type for `securefetch.wasm`, adds handy request logging, and (optionally) enables permissive CORS for local development.

Within the UI you can pick how the device secret is provided—plain string, automatic `base64:` prefix, or a `Uint8Array` derived from comma-separated byte values—matching the capabilities of the underlying WASM bridge.
