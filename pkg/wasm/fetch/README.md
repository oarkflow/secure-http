# secureFetch WASM bridge

This package exposes the secure HTTP client over WebAssembly so that browsers can call the encrypted APIs without relying on the standard `fetch` primitive.

## Building the module

This package is library code. The browser demo and build wrapper live in `github.com/oarkflow/secure-go` under `examples/react-app`.

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

Use `github.com/oarkflow/secure-go/examples/react-app` for the maintained browser demo. That project builds the WASM entrypoint, copies `wasm_exec.js`, and runs the React/Vite demo against the Go SDK.
