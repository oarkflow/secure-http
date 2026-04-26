# PHP Server SDK

PHP now ships as a Composer library with PSR-4 autoloading.

It includes:

- manifest-driven config
- gate verification
- `/handshake` processing
- in-memory session storage
- secure request decrypt / response encrypt helpers
- browser login/bootstrap payload builders

Recommended framework mappings:

- Laravel: HTTP middleware for gate/session resolution.
- Slim: PSR-15 middleware.
- Raw PHP: front-controller gate validation plus secure body wrapping.

## Install With Composer

From this monorepo during development:

```bash
composer config repositories.secure-http-server-sdk path ./sdks/server/php
composer require oarkflow/secure-http-server-sdk:@dev
```

As a package, Composer will autoload:

- [src/SecureHttpServerSDK.php](./src/SecureHttpServerSDK.php)
- [src/SecureSession.php](./src/SecureSession.php)

## Minimal usage

```php
require __DIR__ . '/vendor/autoload.php';

use Oarkflow\SecureHttp\Server\SecureHttpServerSDK;

$sdk = new SecureHttpServerSDK([
    'handshakePath' => '/handshake',
    'requireDevice' => true,
    'requireUser' => true,
    'gateSecrets' => [['id' => '2026-Q1', 'secret' => 'gate-secret-1']],
    'gateSecretStrings' => ['2026-Q1' => 'base64:Z2F0ZS1zZWNyZXQtMQ=='],
    'deviceSecrets' => ['device-1' => 'device-secret-1'],
    'deviceSecretStrings' => ['device-1' => 'base64:ZGV2aWNlLXNlY3JldC0x'],
    'capabilities' => [[
        'token' => 'cap-root',
        'routes' => [
            ['path' => '/handshake', 'methods' => ['POST']],
            ['path' => '/api/echo', 'methods' => ['POST']],
        ],
    ]],
], fn (string $token) => $token === 'user-token-1' ? ['id' => 'user-1'] : null);
```

Use `verifyGate(...)`, `handleHandshake(...)`, `decryptRequest(...)`, and `encryptResponse(...)` from Laravel middleware, Slim middleware, or a plain front controller.

## Laravel shape

The intended Laravel integration is:

1. Bind `SecureHttpServerSDK` as a singleton in a service provider.
2. Add gate verification in route middleware before controller execution.
3. Handle `/handshake` in a controller or route closure with `handleHandshake(...)`.
4. Wrap secure API routes so `decryptRequest(...)` runs before controller code and `encryptResponse(...)` runs on the way out.

That keeps the package framework-agnostic while still fitting Laravel's container and middleware model naturally.

The runtime implementation follows the same lifecycle as the Go and Node SDKs:

1. Gate verification.
2. Handshake.
3. Session derivation and storage.
4. Request decryption.
5. Response encryption.
6. Browser bootstrap/login contract reuse.
