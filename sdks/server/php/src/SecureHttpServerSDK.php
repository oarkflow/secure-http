<?php

declare(strict_types=1);

namespace Oarkflow\SecureHttp\Server;

use RuntimeException;

final class SecureHttpServerSDK
{
    private const DEFAULT_GATE_HEADERS = [
        'secretID' => 'X-Gate-Key',
        'timestamp' => 'X-Gate-Timestamp',
        'nonce' => 'X-Gate-Nonce',
        'signature' => 'X-Gate-Signature',
        'capability' => 'X-Capability-Token',
    ];

    private const DEFAULT_TRANSPORT_HEADERS = [
        'sessionID' => 'X-Session-ID',
        'userToken' => 'X-User-Token',
    ];

    private array $config;
    private string $handshakePath;
    private array $transportHeaders;
    private array $gateHeaders;
    private bool $requireDevice;
    private bool $requireUser;
    private int $sessionTTLms;
    private int $messageTTLms;
    private int $maxClockSkewMs;
    private bool $strictOrigin;
    private array $allowedOrigins;
    private array|object $deviceSecrets;
    private array $capabilities;
    private array $gateSecrets;
    private array $sessions = [];
    private mixed $userAuthenticator;
    private mixed $loadSession;
    private mixed $saveSession;
    private mixed $deleteSession;
    private mixed $serverKeyPair;
    private string $serverPrivateKeyPEM;
    private string $serverPublicKeyRaw;

    public function __construct(array $config = [], ?callable $userAuthenticator = null)
    {
        $this->config = $config;
        $this->handshakePath = self::normalizePath((string) ($config['handshakePath'] ?? '/handshake'));
        $this->transportHeaders = array_merge(self::DEFAULT_TRANSPORT_HEADERS, $config['transportHeaders'] ?? []);
        $this->gateHeaders = array_merge(self::DEFAULT_GATE_HEADERS, $config['gateHeaders'] ?? []);
        $this->requireDevice = ($config['requireDevice'] ?? true) !== false;
        $this->requireUser = (bool) ($config['requireUser'] ?? false);
        $this->sessionTTLms = (int) ($config['sessionTTLms'] ?? 30 * 60 * 1000);
        $this->messageTTLms = (int) ($config['messageTTLms'] ?? 5 * 60 * 1000);
        $this->maxClockSkewMs = (int) ($config['maxClockSkewMs'] ?? 60 * 1000);
        $this->strictOrigin = (bool) ($config['strictOrigin'] ?? false);
        $this->allowedOrigins = array_values(array_filter(array_map([self::class, 'normalizeOrigin'], $config['allowedOrigins'] ?? [])));
        $this->deviceSecrets = $config['deviceSecrets'] ?? [];
        $this->capabilities = [];
        foreach ($config['capabilities'] ?? [] as $capability) {
            $matcher = self::buildCapabilityMatcher($capability);
            if ($matcher['token'] !== '') {
                $this->capabilities[$matcher['token']] = $matcher;
            }
        }
        $this->gateSecrets = [];
        foreach ($config['gateSecrets'] ?? [] as $secret) {
            $secretID = trim((string) ($secret['id'] ?? ''));
            $material = $secret['secret'] ?? '';
            if ($secretID !== '' && $material !== '') {
                $this->gateSecrets[] = [
                    'id' => $secretID,
                    'secret' => (string) $material,
                    'notBefore' => self::parseEpochMs($secret['notBefore'] ?? null, PHP_INT_MIN),
                    'expiresAt' => self::parseEpochMs($secret['expiresAt'] ?? null, PHP_INT_MAX),
                ];
            }
        }
        $this->userAuthenticator = $userAuthenticator ?? ($config['userAuthenticator'] ?? static fn(string $token) => null);
        $this->loadSession = $config['loadSession'] ?? null;
        $this->saveSession = $config['saveSession'] ?? null;
        $this->deleteSession = $config['deleteSession'] ?? null;

        $this->serverKeyPair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($this->serverKeyPair === false) {
            throw new RuntimeException('failed to create EC keypair');
        }
        openssl_pkey_export($this->serverKeyPair, $privateKeyPEM);
        $details = openssl_pkey_get_details($this->serverKeyPair);
        if ($details === false || !isset($details['key'])) {
            throw new RuntimeException('failed to read EC keypair details');
        }
        $this->serverPrivateKeyPEM = $privateKeyPEM;
        $this->serverPublicKeyRaw = self::extractRawPublicKeyFromPEM($details['key']);
    }

    public static function fromManifest(
        array $manifest,
        callable $gateSecretResolver,
        callable $deviceSecretResolver,
        ?callable $userAuthenticator = null,
    ): self {
        $gateSecrets = [];
        foreach ($manifest['gate']['secrets'] ?? [] as $secret) {
            $secretID = trim((string) ($secret['id'] ?? ''));
            if ($secretID === '') {
                continue;
            }
            $gateSecrets[] = [
                'id' => $secretID,
                'secret' => $gateSecretResolver($secretID),
                'notBefore' => $secret['notBefore'] ?? null,
                'expiresAt' => $secret['expiresAt'] ?? null,
            ];
        }
        return new self([
            'handshakePath' => $manifest['handshakePath'] ?? '/handshake',
            'requireDevice' => $manifest['auth']['requireDevice'] ?? true,
            'requireUser' => $manifest['auth']['requireUser'] ?? false,
            'transportHeaders' => $manifest['headers'] ?? [],
            'gateHeaders' => $manifest['headers']['gate'] ?? [],
            'allowedOrigins' => $manifest['gate']['allowedOrigins'] ?? [],
            'strictOrigin' => $manifest['gate']['strictOrigin'] ?? false,
            'capabilities' => $manifest['capabilities'] ?? [],
            'gateSecrets' => $gateSecrets,
            'deviceSecrets' => new class($deviceSecretResolver) {
                public function __construct(private $resolver)
                {
                }

                public function get(string $deviceID): ?string
                {
                    try {
                        return ($this->resolver)($deviceID);
                    } catch (\Throwable) {
                        return null;
                    }
                }
            },
        ], $userAuthenticator);
    }

    public function verifyGate(string $method, string $path, array $headers): array
    {
        $headers = self::lowercaseKeys($headers);
        $origin = self::normalizeOrigin((string) ($headers['origin'] ?? $headers['referer'] ?? ''));
        if (($this->strictOrigin || count($this->allowedOrigins) > 0) && ($origin === '' || !in_array($origin, $this->allowedOrigins, true))) {
            throw new RuntimeException('origin not allowed');
        }

        $secretID = trim((string) ($headers[strtolower($this->gateHeaders['secretID'])] ?? ''));
        $timestamp = trim((string) ($headers[strtolower($this->gateHeaders['timestamp'])] ?? ''));
        $nonce = trim((string) ($headers[strtolower($this->gateHeaders['nonce'])] ?? ''));
        $signature = trim((string) ($headers[strtolower($this->gateHeaders['signature'])] ?? ''));
        $capabilityToken = trim((string) ($headers[strtolower($this->gateHeaders['capability'])] ?? ''));
        if ($secretID === '' || $timestamp === '' || $nonce === '' || $signature === '' || $capabilityToken === '') {
            throw new RuntimeException('missing gate headers');
        }

        $ts = (int) $timestamp;
        $drift = (int) floor(microtime(true) * 1000) - ($ts * 1000);
        if (abs($drift) > $this->maxClockSkewMs) {
            throw new RuntimeException('timestamp skew');
        }

        $capability = $this->capabilities[$capabilityToken] ?? null;
        if ($capability === null || !$capability['allows']($method, $path)) {
            throw new RuntimeException('capability denied');
        }

        $nowMs = (int) floor(microtime(true) * 1000);
        $secret = null;
        foreach ($this->gateSecrets as $item) {
            if ($item['id'] === $secretID && $item['notBefore'] <= $nowMs && $nowMs <= $item['expiresAt']) {
                $secret = $item;
                break;
            }
        }
        if ($secret === null) {
            throw new RuntimeException('unknown gate secret');
        }

        $expected = hash_hmac('sha256', self::gateCanonicalPayload($method, $path, $timestamp, $nonce, $capabilityToken), $secret['secret'], true);
        $provided = base64_decode($signature, true);
        if ($provided === false || !hash_equals($expected, $provided)) {
            throw new RuntimeException('invalid gate signature');
        }

        return [
            'token' => $capabilityToken,
            'metadata' => $capability['metadata'],
        ];
    }

    public function handleHandshake(array $request, array $headers = [], string $clientIP = ''): array
    {
        $clientPublicKey = self::decodeBase64((string) ($request['client_public_key'] ?? ''), 'client_public_key');
        $deviceSignature = self::decodeBase64((string) ($request['device_signature'] ?? ''), 'device_signature');
        $deviceID = trim((string) ($request['device_id'] ?? ''));
        $userToken = trim((string) ($request['user_token'] ?? ''));
        $timestamp = (int) ($request['timestamp'] ?? 0);
        $drift = (int) floor(microtime(true) * 1000) - ($timestamp * 1000);
        if ($timestamp <= 0 || abs($drift) > $this->maxClockSkewMs) {
            throw new RuntimeException('timestamp skew');
        }

        if ($this->requireDevice) {
            $deviceSecret = $this->resolveDeviceSecret($deviceID);
            if ($deviceSecret === null) {
                throw new RuntimeException('unknown device');
            }
            $expected = hash_hmac('sha256', $clientPublicKey . self::uint64BE($timestamp), $deviceSecret, true);
            if (!hash_equals($expected, $deviceSignature)) {
                throw new RuntimeException('invalid device signature');
            }
        }

        $userContext = null;
        if ($userToken !== '') {
            $userContext = ($this->userAuthenticator)($userToken);
            if (!$userContext) {
                throw new RuntimeException('invalid user token');
            }
        } elseif ($this->requireUser) {
            throw new RuntimeException('missing user token');
        }

        $sharedSecret = openssl_pkey_derive(self::buildPEMPublicKeyFromRawPoint($clientPublicKey), $this->serverPrivateKeyPEM);
        if ($sharedSecret === false) {
            throw new RuntimeException('key derivation failed');
        }
        [$encKey, $macKey] = self::deriveKeys($sharedSecret);
        $sessionID = base64_encode(random_bytes(24));
        $metadata = [];
        if ($deviceID !== '') {
            $metadata['device_id'] = $deviceID;
        }
        if (is_array($userContext)) {
            if (!empty($userContext['id'])) {
                $metadata['user_id'] = (string) $userContext['id'];
            }
            if (!empty($userContext['roles']) && is_array($userContext['roles'])) {
                $metadata['user_roles'] = implode(',', array_map('strval', $userContext['roles']));
            }
            if (!empty($userContext['metadata']) && is_array($userContext['metadata'])) {
                foreach ($userContext['metadata'] as $key => $value) {
                    $metadata['user_meta_' . $key] = (string) $value;
                }
            }
        }
        $fingerprint = self::fingerprintForRequest(self::lowercaseKeys($headers), $clientIP);
        if ($fingerprint !== '') {
            $metadata['session_fp'] = $fingerprint;
        }

        $expiresAtMs = (int) floor(microtime(true) * 1000) + $this->sessionTTLms;
        $this->persistSession(new SecureSession($sessionID, $encKey, $macKey, $expiresAtMs, $metadata));

        return [
            'server_public_key' => base64_encode($this->serverPublicKeyRaw),
            'session_id' => base64_encode($sessionID),
            'device_id' => $deviceID,
            'expires_at' => intdiv($expiresAtMs, 1000),
            'timestamp' => time(),
        ];
    }

    public function decryptRequest(array $message, array $headers, string $clientIP = ''): array
    {
        [$session, $userContext] = $this->resolveSession($headers, $clientIP);
        $plaintext = $session->decrypt($message, $this->messageTTLms);
        return [
            'session' => $session,
            'sessionID' => $session->sessionID,
            'deviceID' => $session->metadata['device_id'] ?? '',
            'userContext' => $userContext,
            'plaintext' => $plaintext,
            'json' => $plaintext !== '' ? json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR) : null,
        ];
    }

    public function resolveSecureRequest(array $headers, string $clientIP = ''): array
    {
        [$session, $userContext] = $this->resolveSession($headers, $clientIP);
        return [
            'session' => $session,
            'sessionID' => $session->sessionID,
            'deviceID' => $session->metadata['device_id'] ?? '',
            'userContext' => $userContext,
        ];
    }

    public function encryptResponse(string $sessionID, mixed $payload): ?array
    {
        $session = $this->lookupSession($sessionID);
        if (!$session instanceof SecureSession) {
            throw new RuntimeException('invalid session');
        }
        if ($payload === null) {
            return null;
        }
        $plaintext = is_string($payload) ? $payload : json_encode($payload, JSON_THROW_ON_ERROR);
        if ($plaintext === '') {
            return null;
        }
        return $session->encrypt($plaintext);
    }

    public function buildLoginResponse(
        string $userID,
        string $baseURL = '',
        string $bootstrapPath = '/auth/bootstrap',
        ?string $handshakePath = null,
        bool $cookieAuth = true,
        string $csrfCookieName = 'securehttp_csrf',
        string $csrfHeaderName = 'X-CSRF-Token',
        string $accessToken = '',
        string $refreshToken = '',
        string $csrfToken = '',
    ): array {
        $response = [
            'status' => 200,
            'success' => true,
            'userID' => $userID,
            'user_id' => $userID,
            'bootstrapPath' => self::normalizePath($bootstrapPath),
            'handshakePath' => self::normalizePath($handshakePath ?? $this->handshakePath),
            'baseURL' => $baseURL,
            'cookieAuth' => $cookieAuth,
            'csrfCookieName' => $csrfCookieName,
            'csrfHeaderName' => $csrfHeaderName,
        ];
        if (!$cookieAuth) {
            $response['accessToken'] = $accessToken;
            $response['refreshToken'] = $refreshToken;
            $response['csrfToken'] = $csrfToken;
        }
        return $response;
    }

    public function buildBootstrapConfig(
        string $deviceID,
        string $capabilityToken,
        string $baseURL = '',
        string $userToken = '',
        ?string $handshakePath = null,
    ): array {
        $gateSecrets = [];
        foreach ($this->gateSecrets as $secret) {
            $exported = trim((string) (($this->config['gateSecretStrings'] ?? [])[$secret['id']] ?? ''));
            if ($exported !== '') {
                $gateSecrets[] = [
                    'id' => $secret['id'],
                    'secret' => $exported,
                ];
            }
        }
        $deviceSecret = trim((string) (($this->config['deviceSecretStrings'] ?? [])[$deviceID] ?? ''));
        if ($deviceSecret === '') {
            throw new RuntimeException('device secret not found for ' . $deviceID);
        }
        if ($capabilityToken === '') {
            throw new RuntimeException('capabilityToken is required');
        }
        if (count($gateSecrets) === 0) {
            throw new RuntimeException('at least one gate secret must be exported');
        }
        return [
            'baseURL' => $baseURL,
            'deviceID' => $deviceID,
            'deviceSecret' => $deviceSecret,
            'userToken' => $userToken,
            'handshakePath' => self::normalizePath($handshakePath ?? $this->handshakePath),
            'capabilityToken' => $capabilityToken,
            'gateSecrets' => $gateSecrets,
        ];
    }

    private function resolveSession(array $headers, string $clientIP): array
    {
        $headers = self::lowercaseKeys($headers);
        $sessionID = trim((string) ($headers[strtolower($this->transportHeaders['sessionID'])] ?? ''));
        if ($sessionID === '') {
            throw new RuntimeException('missing session');
        }
        $session = $this->lookupSession($sessionID);
        if (!$session instanceof SecureSession || (int) floor(microtime(true) * 1000) > $session->expiresAtMs) {
            $this->dropSession($sessionID);
            throw new RuntimeException('invalid session');
        }
        $fingerprint = self::fingerprintForRequest($headers, $clientIP);
        if (($session->metadata['session_fp'] ?? '') !== '' && ($session->metadata['session_fp'] ?? '') !== $fingerprint) {
            $this->dropSession($sessionID);
            throw new RuntimeException('fingerprint mismatch');
        }

        $userContext = null;
        $userToken = trim((string) ($headers[strtolower($this->transportHeaders['userToken'])] ?? ''));
        if ($userToken !== '') {
            $userContext = ($this->userAuthenticator)($userToken);
            if (!$userContext) {
                throw new RuntimeException('invalid user token');
            }
        } elseif ($this->requireUser && empty($session->metadata['user_id'])) {
            throw new RuntimeException('missing user token');
        } elseif (!empty($session->metadata['user_id'])) {
            $userContext = [
                'id' => $session->metadata['user_id'],
                'roles' => !empty($session->metadata['user_roles']) ? explode(',', $session->metadata['user_roles']) : [],
                'metadata' => [],
            ];
            foreach ($session->metadata as $key => $value) {
                if (str_starts_with($key, 'user_meta_')) {
                    $userContext['metadata'][substr($key, 10)] = $value;
                }
            }
        }

        return [$session, $userContext];
    }

    private function persistSession(SecureSession $session): void
    {
        $this->sessions[$session->sessionID] = $session;
        if (is_callable($this->saveSession)) {
            ($this->saveSession)($session->sessionID, $session);
        }
    }

    private function lookupSession(string $sessionID): ?SecureSession
    {
        $session = $this->sessions[$sessionID] ?? null;
        if ($session instanceof SecureSession) {
            return $session;
        }
        if (!is_callable($this->loadSession)) {
            return null;
        }
        $loaded = ($this->loadSession)($sessionID);
        if ($loaded instanceof SecureSession) {
            $this->sessions[$sessionID] = $loaded;
            return $loaded;
        }
        if (is_array($loaded)) {
            $session = SecureSession::fromArray($loaded);
            $this->sessions[$sessionID] = $session;
            return $session;
        }
        return null;
    }

    private function dropSession(string $sessionID): void
    {
        unset($this->sessions[$sessionID]);
        if (is_callable($this->deleteSession)) {
            ($this->deleteSession)($sessionID);
        }
    }

    private function resolveDeviceSecret(string $deviceID): ?string
    {
        if (is_array($this->deviceSecrets)) {
            return $this->deviceSecrets[$deviceID] ?? null;
        }
        if (is_object($this->deviceSecrets) && method_exists($this->deviceSecrets, 'get')) {
            return $this->deviceSecrets->get($deviceID);
        }
        return null;
    }

    private static function lowercaseKeys(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $key => $value) {
            $normalized[strtolower((string) $key)] = (string) $value;
        }
        return $normalized;
    }

    private static function buildCapabilityMatcher(array $definition): array
    {
        $methods = [];
        foreach ($definition['methods'] ?? [] as $method) {
            $method = strtoupper(trim((string) $method));
            if ($method !== '') {
                $methods[$method] = true;
            }
        }
        $paths = array_values(array_filter(array_map('strval', $definition['paths'] ?? []), static fn(string $path) => trim($path) !== ''));
        $routes = [];
        foreach ($definition['routes'] ?? [] as $route) {
            $path = trim((string) ($route['path'] ?? ''));
            if ($path === '') {
                continue;
            }
            $routeMethods = [];
            foreach ($route['methods'] ?? [] as $method) {
                $method = strtoupper(trim((string) $method));
                if ($method !== '') {
                    $routeMethods[$method] = true;
                }
            }
            $routes[] = [
                'path' => $path,
                'methods' => $routeMethods,
            ];
        }
        return [
            'token' => trim((string) ($definition['token'] ?? '')),
            'metadata' => $definition['metadata'] ?? [],
            'allows' => static function (string $method, string $path) use ($methods, $paths, $routes): bool {
                $normalizedMethod = strtoupper(trim($method));
                $normalizedPath = self::normalizePath($path);
                if (count($routes) > 0) {
                    foreach ($routes as $route) {
                        if (self::pathMatches($route['path'], $normalizedPath) && (count($route['methods']) === 0 || isset($route['methods'][$normalizedMethod]))) {
                            return true;
                        }
                    }
                    return false;
                }
                if (count($methods) > 0 && !isset($methods[$normalizedMethod])) {
                    return false;
                }
                if (count($paths) === 0) {
                    return true;
                }
                foreach ($paths as $pattern) {
                    if (self::pathMatches($pattern, $normalizedPath)) {
                        return true;
                    }
                }
                return false;
            },
        ];
    }

    private static function deriveKeys(string $sharedSecret): array
    {
        $okm = hash_hkdf('sha512', $sharedSecret, 64, 'secure-communication-v1', '');
        return [substr($okm, 0, 32), substr($okm, 32, 32)];
    }

    private static function decodeBase64(string $value, string $fieldName): string
    {
        if (trim($value) === '') {
            throw new RuntimeException($fieldName . ' is required');
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new RuntimeException('invalid base64 for ' . $fieldName);
        }
        return $decoded;
    }

    private static function normalizePath(string $rawPath): string
    {
        $value = trim($rawPath);
        if ($value === '') {
            return '/';
        }
        $parts = parse_url($value);
        $path = $parts['path'] ?? explode('?', $value, 2)[0];
        if ($path === '' || $path === false) {
            $path = '/';
        }
        return str_starts_with($path, '/') ? $path : '/' . $path;
    }

    private static function pathMatches(string $pattern, string $path): bool
    {
        if ($pattern === '') {
            return false;
        }
        if (str_ends_with($pattern, '*')) {
            return str_starts_with($path, substr($pattern, 0, -1));
        }
        return $pattern === $path;
    }

    private static function normalizeOrigin(string $origin): string
    {
        $value = rtrim(strtolower(trim($origin)), '/');
        if ($value === '') {
            return '';
        }
        $parts = parse_url($value);
        if (!empty($parts['scheme']) && !empty($parts['host'])) {
            $port = isset($parts['port']) ? ':' . $parts['port'] : '';
            return strtolower($parts['scheme'] . '://' . $parts['host'] . $port);
        }
        return $value;
    }

    private static function gateCanonicalPayload(string $method, string $path, string $timestamp, string $nonce, string $capability): string
    {
        return implode("\n", [
            strtoupper(trim($method)),
            self::normalizePath($path),
            $timestamp,
            $nonce,
            $capability,
        ]);
    }

    private static function fingerprintForRequest(array $headers, string $clientIP): string
    {
        $userAgent = trim((string) ($headers['user-agent'] ?? ''));
        $clientIP = trim($clientIP);
        if ($clientIP === '' && $userAgent === '') {
            return '';
        }
        return hash('sha256', $clientIP . '|' . $userAgent);
    }

    private static function parseEpochMs(mixed $value, int $default): int
    {
        if ($value === null || $value === '') {
            return $default;
        }
        if (is_numeric($value)) {
            return (int) $value;
        }
        $timestamp = strtotime((string) $value);
        return $timestamp === false ? $default : $timestamp * 1000;
    }

    private static function uint64BE(int $value): string
    {
        $high = ($value >> 32) & 0xffffffff;
        $low = $value & 0xffffffff;
        return pack('N2', $high, $low);
    }

    private static function extractRawPublicKeyFromPEM(string $pem): string
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
        if ($der === false || strlen($der) < 65) {
            throw new RuntimeException('invalid public key');
        }
        return substr($der, -65);
    }

    private static function buildPEMPublicKeyFromRawPoint(string $rawPoint): string
    {
        $der = hex2bin('3059301306072A8648CE3D020106082A8648CE3D030107034200') . $rawPoint;
        $base64 = chunk_split(base64_encode($der), 64, PHP_EOL);
        return "-----BEGIN PUBLIC KEY-----" . PHP_EOL . $base64 . "-----END PUBLIC KEY-----" . PHP_EOL;
    }
}
