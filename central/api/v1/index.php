<?php
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    http_response_code(400);
    echo json_encode(['error' => 'https_required']);
    exit;
}

function api_json(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function api_input(): array
{
    $raw = file_get_contents('php://input', false, null, 0, 65537);
    if ($raw === false || strlen($raw) > 65536) {
        api_json(413, ['error' => 'request_too_large']);
    }
    try {
        $input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        api_json(400, ['error' => 'invalid_json']);
    }
    if (!is_array($input)) {
        api_json(400, ['error' => 'invalid_request']);
    }
    return $input;
}

function api_string(array $input, string $key, int $maximumLength): string
{
    $value = $input[$key] ?? '';
    if (!is_string($value) || strlen($value) > $maximumLength) {
        api_json(400, ['error' => 'invalid_' . $key]);
    }
    return trim($value);
}

function api_bearer(): string
{
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $headers['Authorization'] ?? $headers['authorization'] ?? '');
    if (!preg_match('/^Bearer ([A-Za-z0-9_-]{40,100})$/', $header, $match)) {
        api_json(401, ['error' => 'unauthorized']);
    }
    return $match[1];
}

try {
    $pdo = central_db();
    $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?: '';
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));

    if ($method === 'POST' && str_ends_with($path, '/enroll')) {
        $input = api_input();
        $code = api_string($input, 'code', 100);
        $label = api_string($input, 'device_name', 120);
        $version = api_string($input, 'app_version', 40);
        if (!preg_match('/^[A-Za-z0-9_-]{30,40}$/', $code) || $label === '' || strlen($label) > 120) {
            api_json(400, ['error' => 'invalid_enrollment']);
        }

        $pdo->beginTransaction();
        $lookup = $pdo->prepare('SELECT code_hash, created_by FROM enrollment_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP() FOR UPDATE');
        $lookup->execute([hash('sha256', $code)]);
        $enrollment = $lookup->fetch();
        if (!$enrollment) {
            $pdo->rollBack();
            api_json(403, ['error' => 'enrollment_code_invalid_or_expired']);
        }
        $deviceId = bin2hex(random_bytes(16));
        $deviceToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $insert = $pdo->prepare('INSERT INTO devices (id, label, token_hash, app_version, enrolled_at) VALUES (?, ?, ?, ?, UTC_TIMESTAMP())');
        $insert->execute([$deviceId, $label, hash('sha256', $deviceToken), $version]);
        $consume = $pdo->prepare('UPDATE enrollment_codes SET used_at = UTC_TIMESTAMP() WHERE code_hash = ? AND used_at IS NULL');
        $consume->execute([$enrollment['code_hash']]);
        if ($consume->rowCount() !== 1) {
            $pdo->rollBack();
            api_json(409, ['error' => 'enrollment_code_already_used']);
        }
        central_audit($pdo, (int)$enrollment['created_by'], $deviceId, 'Device enrolled', $label);
        $pdo->commit();
        api_json(201, ['device_id' => $deviceId, 'device_token' => $deviceToken, 'check_in_seconds' => 60]);
    }

    if ($method === 'POST' && str_ends_with($path, '/check-in')) {
        $input = api_input();
        $token = api_bearer();
        $pdo->beginTransaction();
        $find = $pdo->prepare('SELECT id, applied_policy_version, check_requested FROM devices WHERE token_hash = ? AND revoked_at IS NULL LIMIT 1 FOR UPDATE');
        $find->execute([hash('sha256', $token)]);
        $device = $find->fetch();
        if (!$device) {
            $pdo->rollBack();
            api_json(401, ['error' => 'device_revoked_or_unknown']);
        }
        $status = api_string($input, 'protection_status', 40);
        if ($status === '') {
            $status = 'unknown';
        }
        if (!in_array($status, ['active', 'inactive', 'error', 'unknown'], true)) {
            $status = 'unknown';
        }
        $reportedVersion = filter_var($input['applied_policy_version'] ?? 0, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
        if ($reportedVersion === false) {
            $pdo->rollBack();
            api_json(400, ['error' => 'invalid_applied_policy_version']);
        }
        $appVersion = api_string($input, 'app_version', 40);
        $current = $pdo->query('SELECT version, document FROM policies WHERE id = 1')->fetch();
        $serverVersion = $current ? (int)$current['version'] : 0;
        if ($reportedVersion > $serverVersion) {
            $pdo->rollBack();
            api_json(409, ['error' => 'reported_policy_version_ahead_of_server', 'policy_version' => $serverVersion]);
        }
        $requested = (int)$device['check_requested'] === 1;
        $update = $pdo->prepare('UPDATE devices SET last_seen_at = UTC_TIMESTAMP(), app_version = ?, protection_status = ?, applied_policy_version = ?, check_requested = 0 WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < UTC_TIMESTAMP() - INTERVAL 15 SECOND)');
        $update->execute([$appVersion, $status, $reportedVersion, $device['id']]);
        if ($update->rowCount() !== 1) {
            $pdo->rollBack();
            api_json(429, ['error' => 'check_in_too_soon', 'retry_after_seconds' => 15]);
        }

        $policy = null;
        if ($current && ($serverVersion > $reportedVersion || $requested)) {
            $policy = json_decode((string)$current['document'], true, 64, JSON_THROW_ON_ERROR);
        }
        $pdo->commit();
        api_json(200, [
            'server_time' => gmdate('c'),
            'check_in_seconds' => 60,
            'check_requested' => $requested,
            'policy_version' => $serverVersion,
            'policy' => $policy,
        ]);
    }

    api_json(404, ['error' => 'not_found']);
} catch (Throwable $exception) {
    error_log('Avantis Central API error: ' . $exception->getMessage());
    api_json(500, ['error' => 'internal_error']);
}
