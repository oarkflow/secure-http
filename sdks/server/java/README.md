# Java Server SDK

Java now ships a reusable reference SDK in [src/main/java/dev/oarkflow/securehttp/server/SecureHttpServerSDK.java](./src/main/java/dev/oarkflow/securehttp/server/SecureHttpServerSDK.java).

It includes:

- manifest-driven config
- gate verification
- `/handshake` processing
- in-memory session storage
- secure request decrypt / response encrypt helpers
- browser login/bootstrap payload builders

Recommended framework mappings:

- Spring Boot: `OncePerRequestFilter` or servlet filter.
- JAX-RS / Jersey: request filters and response interceptors.
- Micronaut / Vert.x: route interceptors.

## Minimal usage

```java
var sdk = new SecureHttpServerSDK(Map.of(
    "handshakePath", "/handshake",
    "requireDevice", true,
    "requireUser", true,
    "gateSecrets", List.of(Map.of("id", "2026-Q1", "secret", "gate-secret-1".getBytes(StandardCharsets.UTF_8))),
    "gateSecretStrings", Map.of("2026-Q1", "base64:Z2F0ZS1zZWNyZXQtMQ=="),
    "deviceSecrets", Map.of("device-1", "device-secret-1".getBytes(StandardCharsets.UTF_8)),
    "deviceSecretStrings", Map.of("device-1", "base64:ZGV2aWNlLXNlY3JldC0x"),
    "capabilities", List.of(Map.of(
        "token", "cap-root",
        "routes", List.of(
            Map.of("path", "/handshake", "methods", List.of("POST")),
            Map.of("path", "/api/echo", "methods", List.of("POST"))
        )
    ))
));
```

Use `verifyGate(...)`, `handleHandshake(...)`, `decryptRequest(...)`, and `encryptResponse(...)` inside a servlet filter, Spring `OncePerRequestFilter`, or another interceptor layer.

Implementation requirements are the same across all runtimes:

1. Validate gate headers.
2. Handle `POST /handshake`.
3. Persist secure session keys plus metadata.
4. Decrypt secure request bodies.
5. Encrypt successful secure responses.
6. Reuse the browser bootstrap/login payload shapes.
