<?php

declare(strict_types=1);

use Oarkflow\SecureHttp\Server\SecureHttpServerSDK;
use Oarkflow\SecureHttp\Server\SecureSession;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (!is_file($autoload)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing vendor/autoload.php. Run composer install in examples/php-server.\n";
    exit;
}
require $autoload;

const DEMO_SESSION_COOKIE = 'securehttp_demo';
const DEMO_CSRF_COOKIE = 'securehttp_csrf';
const DEMO_CSRF_HEADER = 'X-CSRF-Token';
const DEMO_HANDSHAKE_PATH = '/handshake';
const DEMO_BOOTSTRAP_PATH = '/auth/bootstrap';
const DEMO_CAPABILITY_TOKEN = 'todo-cap';
const DEMO_GATE_SECRET_ID = 'todo-sample-2026';
const DEMO_GATE_SECRET_STRING = 'base64:dG9kby1zYW1wbGUtZ2F0ZS1zZWNyZXQ=';
const DEMO_GATE_SECRET_RAW = 'todo-sample-gate-secret';

$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if (PHP_SAPI === 'cli-server') {
    $publicFile = __DIR__ . $requestPath;
    if ($requestPath !== '/' && is_file($publicFile)) {
        return false;
    }
}

session_name(DEMO_SESSION_COOKIE);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

ensureStorageDirectory($root . '/storage/todos');
ensureStorageDirectory($root . '/storage/secure-sessions');

$accounts = seedAccounts();
$allowedOrigins = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
    'http://localhost:9080',
    'http://127.0.0.1:9080',
];

applyCors($allowedOrigins);
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$authState = currentAuthState();
$deviceSecretStrings = [];
if (!empty($authState['device_id'])) {
    $derivedDeviceSecret = deriveDeviceSecret($authState['device_id']);
    $deviceSecretStrings[$authState['device_id']] = 'base64:' . base64_encode($derivedDeviceSecret);
}

$sdk = new SecureHttpServerSDK([
    'handshakePath' => DEMO_HANDSHAKE_PATH,
    'requireDevice' => true,
    'requireUser' => true,
    'strictOrigin' => false,
    'allowedOrigins' => $allowedOrigins,
    'gateSecrets' => [[
        'id' => DEMO_GATE_SECRET_ID,
        'secret' => DEMO_GATE_SECRET_RAW,
        'notBefore' => '2025-01-01T00:00:00Z',
        'expiresAt' => '2027-01-01T00:00:00Z',
    ]],
    'gateSecretStrings' => [
        DEMO_GATE_SECRET_ID => DEMO_GATE_SECRET_STRING,
    ],
    'deviceSecrets' => new class {
        public function get(string $deviceID): ?string
        {
            $deviceID = trim($deviceID);
            if ($deviceID === '') {
                return null;
            }
            return deriveDeviceSecret($deviceID);
        }
    },
    'deviceSecretStrings' => $deviceSecretStrings,
    'capabilities' => [[
        'token' => DEMO_CAPABILITY_TOKEN,
        'routes' => [
            ['path' => '/handshake', 'methods' => ['POST']],
            ['path' => '/api/todos', 'methods' => ['GET', 'POST']],
            ['path' => '/api/todos/*', 'methods' => ['PUT', 'DELETE']],
        ],
    ]],
    'loadSession' => function (string $sessionID) use ($root): ?array {
        $path = secureSessionPath($root, $sessionID);
        if (!is_file($path)) {
            return null;
        }
        $decoded = json_decode((string) file_get_contents($path), true);
        return is_array($decoded) ? $decoded : null;
    },
    'saveSession' => function (string $sessionID, SecureSession $session) use ($root): void {
        file_put_contents(secureSessionPath($root, $sessionID), json_encode($session->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    },
    'deleteSession' => function (string $sessionID) use ($root): void {
        $path = secureSessionPath($root, $sessionID);
        if (is_file($path)) {
            unlink($path);
        }
    },
], function (string $token) use ($accounts): ?array {
    foreach ($accounts as $account) {
        if ($account['user_token'] === $token) {
            return [
                'id' => $account['user_id'],
                'roles' => $account['roles'],
                'metadata' => ['username' => $account['username']],
            ];
        }
    }
    return null;
});

try {
    dispatch($sdk, $accounts, $root, $requestPath);
} catch (Throwable $e) {
    jsonResponse(500, ['error' => $e->getMessage()]);
}

function dispatch(SecureHttpServerSDK $sdk, array $accounts, string $root, string $path): void
{
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

    if ($method === 'POST' && $path === '/auth/login') {
        handleLogin($sdk, $accounts);
        return;
    }
    if ($method === 'POST' && $path === DEMO_BOOTSTRAP_PATH) {
        requireAuth();
        verifyCsrf();
        handleBootstrap($sdk);
        return;
    }
    if ($method === 'POST' && $path === '/auth/logout') {
        requireAuth();
        verifyCsrf();
        handleLogout();
        return;
    }
    if ($method === 'POST' && $path === DEMO_HANDSHAKE_PATH) {
        verifyGate($sdk);
        handleHandshake($sdk);
        return;
    }
    if ($path === '/api/todos' || str_starts_with($path, '/api/todos/')) {
        verifyGate($sdk);
        handleTodos($sdk, $root, $method, $path);
        return;
    }
    if ($method === 'GET' && serveReactBuild($root, $path)) {
        return;
    }
    jsonResponse(404, ['error' => 'not found']);
}

function handleLogin(SecureHttpServerSDK $sdk, array $accounts): void
{
    $request = readJsonBody();
    $identifier = strtolower(trim((string) ($request['username'] ?? $request['user_id'] ?? $request['login'] ?? $request['identifier'] ?? '')));
    $password = trim((string) ($request['password'] ?? $request['user_token'] ?? ''));
    if ($identifier === '' || $password === '') {
        jsonResponse(401, ['error' => 'invalid credentials']);
        return;
    }

    $account = $accounts[$identifier] ?? null;
    if ($account === null) {
        foreach ($accounts as $candidate) {
            if (strcasecmp($candidate['user_id'], $identifier) === 0) {
                $account = $candidate;
                break;
            }
        }
    }
    if ($account === null) {
        jsonResponse(401, ['error' => 'invalid credentials']);
        return;
    }
    $matches = hash_equals($account['password'], $password) || hash_equals($account['user_token'], $password);
    if (!$matches) {
        jsonResponse(401, ['error' => 'invalid credentials']);
        return;
    }

    session_regenerate_id(true);
    $deviceID = $account['user_id'] . '-device';
    $_SESSION['auth'] = [
        'user_id' => $account['user_id'],
        'username' => $account['username'],
        'user_token' => $account['user_token'],
        'roles' => $account['roles'],
        'device_id' => $deviceID,
    ];
    $_SESSION['csrf_token'] = base64_encode(random_bytes(24));
    setDemoCookie(DEMO_CSRF_COOKIE, (string) $_SESSION['csrf_token']);

    $payload = $sdk->buildLoginResponse(
        $account['user_id'],
        requestBaseUrl(),
        DEMO_BOOTSTRAP_PATH,
        DEMO_HANDSHAKE_PATH,
        true,
        DEMO_CSRF_COOKIE,
        DEMO_CSRF_HEADER,
    );
    jsonResponse(200, $payload);
}

function handleBootstrap(SecureHttpServerSDK $sdk): void
{
    $auth = currentAuthState();
    $payload = $sdk->buildBootstrapConfig(
        $auth['device_id'],
        DEMO_CAPABILITY_TOKEN,
        requestBaseUrl(),
        $auth['user_token'],
        DEMO_HANDSHAKE_PATH,
    );
    jsonResponse(200, $payload);
}

function handleLogout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600, $params['path'] ?? '/', '', false, true);
    }
    session_destroy();
    clearDemoCookie(DEMO_CSRF_COOKIE);
    jsonResponse(200, ['success' => true]);
}

function handleHandshake(SecureHttpServerSDK $sdk): void
{
    try {
        $payload = $sdk->handleHandshake(readJsonBody(), requestHeaders(), clientIp());
        jsonResponse(200, $payload);
    } catch (Throwable $e) {
        error_log('secure-http php demo handshake failed: ' . $e->getMessage());
        notFound();
    }
}

function handleTodos(SecureHttpServerSDK $sdk, string $root, string $method, string $path): void
{
    try {
        if ($method === 'GET' && $path === '/api/todos') {
            $resolved = $sdk->resolveSecureRequest(requestHeaders(), clientIp());
            $userID = (string) (($resolved['userContext']['id'] ?? ''));
            encryptedResponse($sdk, $resolved['sessionID'], ['items' => loadTodos($root, $userID)]);
            return;
        }

        if ($method === 'POST' && $path === '/api/todos') {
            $resolved = $sdk->decryptRequest(readJsonBody(), requestHeaders(), clientIp());
            $userID = (string) (($resolved['userContext']['id'] ?? ''));
            $request = is_array($resolved['json'] ?? null) ? $resolved['json'] : [];
            $image = normalizeTodoImage((string) ($request['image_data_url'] ?? ''), (string) ($request['image_content_type'] ?? ''));
            $title = trim((string) ($request['title'] ?? ''));
            if ($title === '') {
                encryptedResponse($sdk, $resolved['sessionID'], ['error' => 'title is required']);
                return;
            }
            $items = loadTodos($root, $userID);
            $now = gmdate(DATE_ATOM);
            $item = [
                'id' => 'todo-' . str_replace('.', '', (string) microtime(true)),
                'title' => $title,
                'description' => trim((string) ($request['description'] ?? '')),
                'done' => false,
                'image_data_url' => $image['data_url'],
                'image_content_type' => $image['content_type'],
                'created_at' => $now,
                'updated_at' => $now,
            ];
            $items[] = $item;
            saveTodos($root, $userID, $items);
            encryptedResponse($sdk, $resolved['sessionID'], $item);
            return;
        }

        if (($method === 'PUT' || $method === 'DELETE') && preg_match('#^/api/todos/([^/]+)$#', $path, $matches) === 1) {
            $todoID = rawurldecode($matches[1]);
            if ($method === 'DELETE') {
                $resolved = $sdk->resolveSecureRequest(requestHeaders(), clientIp());
                $userID = (string) (($resolved['userContext']['id'] ?? ''));
                $items = loadTodos($root, $userID);
                $next = array_values(array_filter($items, static fn(array $item): bool => $item['id'] !== $todoID));
                saveTodos($root, $userID, $next);
                encryptedResponse($sdk, $resolved['sessionID'], ['success' => true]);
                return;
            }

            $resolved = $sdk->decryptRequest(readJsonBody(), requestHeaders(), clientIp());
            $userID = (string) (($resolved['userContext']['id'] ?? ''));
            $request = is_array($resolved['json'] ?? null) ? $resolved['json'] : [];
            $image = normalizeTodoImage((string) ($request['image_data_url'] ?? ''), (string) ($request['image_content_type'] ?? ''));
            $items = loadTodos($root, $userID);
            foreach ($items as &$item) {
                if ($item['id'] !== $todoID) {
                    continue;
                }
                $item['title'] = trim((string) ($request['title'] ?? $item['title']));
                $item['description'] = trim((string) ($request['description'] ?? $item['description']));
                $item['done'] = (bool) ($request['done'] ?? false);
                $item['image_data_url'] = $image['data_url'];
                $item['image_content_type'] = $image['content_type'];
                $item['updated_at'] = gmdate(DATE_ATOM);
                saveTodos($root, $userID, $items);
                encryptedResponse($sdk, $resolved['sessionID'], $item);
                return;
            }
            encryptedResponse($sdk, $resolved['sessionID'], ['error' => 'todo not found']);
            return;
        }
    } catch (Throwable $e) {
        error_log('secure-http php demo secure route failed: ' . $e->getMessage());
        notFound();
        return;
    }

    notFound();
}

function requestHeaders(): array
{
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            return $headers;
        }
    }
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (!str_starts_with($key, 'HTTP_')) {
            continue;
        }
        $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
        $headers[$name] = (string) $value;
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['Content-Type'] = (string) $_SERVER['CONTENT_TYPE'];
    }
    return $headers;
}

function readJsonBody(): array
{
    $raw = (string) file_get_contents('php://input');
    if ($raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function requestBaseUrl(): string
{
    $proto = (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http'));
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? '127.0.0.1:9080';
    return $proto . '://' . $host;
}

function clientIp(): string
{
    $forwarded = trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
    if ($forwarded !== '') {
        return trim(explode(',', $forwarded)[0]);
    }
    return trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
}

function currentAuthState(): array
{
    return is_array($_SESSION['auth'] ?? null) ? $_SESSION['auth'] : [];
}

function requireAuth(): void
{
    if (currentAuthState() === []) {
        jsonResponse(401, ['error' => 'unauthorized']);
        exit;
    }
}

function verifyCsrf(): void
{
    $headerToken = trim((string) (requestHeaders()[DEMO_CSRF_HEADER] ?? requestHeaders()[strtolower(DEMO_CSRF_HEADER)] ?? ''));
    $sessionToken = (string) ($_SESSION['csrf_token'] ?? '');
    if ($sessionToken === '' || $headerToken === '' || !hash_equals($sessionToken, $headerToken)) {
        jsonResponse(403, ['error' => 'invalid csrf token']);
        exit;
    }
}

function verifyGate(SecureHttpServerSDK $sdk): void
{
    try {
        $sdk->verifyGate((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'), (string) ($_SERVER['REQUEST_URI'] ?? '/'), requestHeaders());
    } catch (Throwable) {
        notFound();
        exit;
    }
}

function encryptedResponse(SecureHttpServerSDK $sdk, string $sessionID, array $payload): void
{
    $encrypted = $sdk->encryptResponse($sessionID, $payload);
    jsonResponse(200, $encrypted ?? []);
}

function jsonResponse(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
}

function notFound(): void
{
    http_response_code(404);
}

function applyCors(array $allowedOrigins): void
{
    $origin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
    if ($origin !== '' && in_array($origin, $allowedOrigins, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
        header('Access-Control-Allow-Credentials: true');
    }
    header('Access-Control-Allow-Headers: Content-Type, ' . DEMO_CSRF_HEADER . ', X-Gate-Key, X-Gate-Timestamp, X-Gate-Nonce, X-Gate-Signature, X-Capability-Token, X-Session-ID, X-User-Token');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
}

function setDemoCookie(string $name, string $value): void
{
    setcookie($name, $value, [
        'expires' => 0,
        'path' => '/',
        'httponly' => false,
        'samesite' => 'Lax',
    ]);
}

function clearDemoCookie(string $name): void
{
    setcookie($name, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'httponly' => false,
        'samesite' => 'Lax',
    ]);
}

function secureSessionPath(string $root, string $sessionID): string
{
    return $root . '/storage/secure-sessions/' . hash('sha256', $sessionID) . '.json';
}

function loadTodos(string $root, string $userID): array
{
    $path = todoFilePath($root, $userID);
    if (!is_file($path)) {
        return [];
    }
    $decoded = json_decode((string) file_get_contents($path), true);
    return is_array($decoded) ? $decoded : [];
}

function saveTodos(string $root, string $userID, array $items): void
{
    file_put_contents(todoFilePath($root, $userID), json_encode(array_values($items), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function todoFilePath(string $root, string $userID): string
{
    return $root . '/storage/todos/' . rawurlencode($userID) . '.json';
}

function normalizeTodoImage(string $dataURL, string $contentType): array
{
    $dataURL = trim($dataURL);
    $contentType = trim($contentType);
    if ($dataURL === '') {
        return ['data_url' => '', 'content_type' => ''];
    }
    if (!str_starts_with($dataURL, 'data:') || !str_contains($dataURL, ';base64,')) {
        throw new RuntimeException('image must be a base64 data URL');
    }
    [$meta, $encoded] = explode(',', $dataURL, 2);
    if ($contentType === '') {
        $contentType = trim((string) explode(';', substr($meta, 5), 2)[0]);
    }
    if (!in_array($contentType, ['image/png', 'image/jpeg', 'image/webp', 'image/gif'], true)) {
        throw new RuntimeException('unsupported image type');
    }
    $decoded = base64_decode($encoded, true);
    if ($decoded === false) {
        throw new RuntimeException('image data is invalid');
    }
    if (strlen($decoded) > 2 * 1024 * 1024) {
        throw new RuntimeException('image must be 2MB or smaller');
    }
    return ['data_url' => $dataURL, 'content_type' => $contentType];
}

function deriveDeviceSecret(string $deviceID): string
{
    return hash_hmac('sha256', $deviceID, 'todo-password-sample-device-secret', true);
}

function seedAccounts(): array
{
    $accounts = [];
    foreach ([
        [
            'username' => 'alice',
            'user_id' => 'todo-alice',
            'password' => 'alice-password',
            'user_token' => 'todo-user-token-alice',
            'roles' => ['todo-user'],
        ],
        [
            'username' => 'bob',
            'user_id' => 'todo-bob',
            'password' => 'bob-password',
            'user_token' => 'todo-user-token-bob',
            'roles' => ['todo-user'],
        ],
    ] as $account) {
        $accounts[strtolower($account['username'])] = $account;
        $accounts[strtolower($account['user_id'])] = $account;
    }
    return $accounts;
}

function ensureStorageDirectory(string $path): void
{
    if (!is_dir($path)) {
        mkdir($path, 0777, true);
    }
}

function serveReactBuild(string $root, string $path): bool
{
    $distRoot = realpath($root . '/../react-app/dist');
    if ($distRoot === false) {
        return false;
    }

    $candidate = realpath($distRoot . $path);
    if ($path !== '/' && $candidate !== false && str_starts_with($candidate, $distRoot) && is_file($candidate)) {
        $mime = mime_content_type($candidate) ?: 'application/octet-stream';
        header('Content-Type: ' . $mime);
        readfile($candidate);
        return true;
    }

    $index = $distRoot . '/index.html';
    if (!is_file($index)) {
        return false;
    }
    header('Content-Type: text/html; charset=utf-8');
    readfile($index);
    return true;
}
