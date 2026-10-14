<?php
declare(strict_types=1);

final class CentralException extends RuntimeException
{
}

function central_config(?string $key = null): mixed
{
    static $config;
    if ($config === null) {
        $path = __DIR__ . '/config.local.php';
        if (!is_file($path)) {
            http_response_code(503);
            exit('Avantis Central has not been configured.');
        }
        $config = require $path;
        $database = is_array($config) ? ($config['database'] ?? null) : null;
        $setupKey = is_array($config) ? (string)($config['setup_key'] ?? '') : '';
        if (
            !is_array($database)
            || empty($database['host'])
            || empty($database['name'])
            || empty($database['user'])
            || empty($database['password'])
            || strlen($setupKey) < 43
            || str_contains($setupKey, 'REPLACE_')
        ) {
            http_response_code(503);
            exit('Avantis Central configuration is incomplete.');
        }
    }
    return $key === null ? $config : ($config[$key] ?? null);
}

function central_db(): PDO
{
    static $pdo;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $database = central_config('database');
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $database['host'], $database['name'], $database['charset'] ?? 'utf8mb4');
    $pdo = new PDO($dsn, $database['user'], $database['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function central_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    if (!$https) {
        http_response_code(400);
        exit('HTTPS is required.');
    }
    session_name('avantis_central');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/firewall/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function central_csrf_token(): string
{
    if (!isset($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf'];
}

function central_require_csrf(): void
{
    $submitted = (string)($_POST['csrf'] ?? '');
    if ($submitted === '' || !hash_equals(central_csrf_token(), $submitted)) {
        throw new CentralException('The form expired. Reload the page and try again.');
    }
}

function central_admin_count(PDO $pdo): int
{
    return (int)$pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
}

function central_is_admin(): bool
{
    return isset($_SESSION['admin_id']) && (int)$_SESSION['admin_id'] > 0;
}

function central_require_admin(): void
{
    if (!central_is_admin()) {
        throw new CentralException('Please sign in first.');
    }
}

function central_audit(PDO $pdo, ?int $adminId, ?string $deviceId, string $action, string $detail): void
{
    $statement = $pdo->prepare('INSERT INTO audit_events (admin_id, device_id, action, detail, created_at) VALUES (?, ?, ?, ?, UTC_TIMESTAMP())');
    $statement->execute([$adminId, $deviceId, $action, substr($detail, 0, 500)]);
}

function central_validate_domains(string $input): array
{
    $domains = [];
    $seen = [];
    foreach (preg_split('/[\s,;]+/', strtolower(trim($input))) ?: [] as $domain) {
        if ($domain === '') {
            continue;
        }
        $domain = rtrim($domain, '.');
        if (strlen($domain) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain)) {
            throw new CentralException("Invalid domain: {$domain}");
        }
        $protectedDomains = [
            'bing.com', 'google.com', 'yahoo.com', 'duckduckgo.com',
            'microsoft.com', 'windows.com', 'live.com', 'openai.com',
            'chatgpt.com', 'github.com', 'localhost',
        ];
        foreach ($protectedDomains as $protected) {
            if ($domain === $protected || str_ends_with($domain, '.' . $protected)) {
                throw new CentralException("Protected system domain cannot be blocked: {$domain}");
            }
        }
        if (!isset($seen[$domain])) {
            $seen[$domain] = true;
            $domains[] = $domain;
        }
        if (count($domains) > 1000) {
            throw new CentralException('The current Windows hosts policy is limited to 1,000 domains.');
        }
    }
    return $domains;
}
