<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

header('Cache-Control: no-store');
$notice = '';
$error = '';
try {
    central_session_start();
    $pdo = central_db();
} catch (Throwable $exception) {
    error_log('FireWall Central Administration initialization error: ' . $exception->getMessage());
    http_response_code(503);
    exit('FireWall Central Administration is not available. Check the cPanel PHP error log and setup instructions.');
}

function central_current_policy(PDO $pdo, bool $forUpdate = false): array
{
    $suffix = $forUpdate ? ' FOR UPDATE' : '';
    $row = $pdo->query('SELECT version, document, updated_at FROM policies WHERE id = 1' . $suffix)->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return [
            'version' => 0,
            'document' => ['blocked_domains' => [], 'subdomain_prefixes' => ['www', 'm', 'mobile', 'web', 'login', 'account', 'secure']],
            'updated_at' => null,
        ];
    }
    $document = json_decode((string)$row['document'], true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($document) || !is_array($document['blocked_domains'] ?? null)) {
        throw new CentralException('The published policy is invalid. Restore it from a backup or publish a corrected domain list.');
    }
    if (!is_array($document['subdomain_prefixes'] ?? null)) {
        $document['subdomain_prefixes'] = ['www', 'm', 'mobile', 'web', 'login', 'account', 'secure'];
    }
    return [
        'version' => (int)$row['version'],
        'document' => $document,
        'updated_at' => $row['updated_at'],
    ];
}

function central_save_policy(PDO $pdo, int $adminId, array $current, array $domains, array $prefixes, string $action): int
{
    $version = $current['version'] + 1;
    $document = ['blocked_domains' => $domains, 'subdomain_prefixes' => $prefixes];
    $statement = $pdo->prepare('INSERT INTO policies (id, version, document, updated_by, updated_at) VALUES (1, ?, ?, ?, UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE version = VALUES(version), document = VALUES(document), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)');
    $statement->execute([$version, json_encode($document, JSON_THROW_ON_ERROR), $adminId]);
    central_audit($pdo, $adminId, null, $action, count($domains) . ' blocked domains.');
    return $version;
}

$oneTimeCode = $_SESSION['one_time_code'] ?? '';
unset($_SESSION['one_time_code']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        central_require_csrf();
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'bootstrap') {
            $setupKey = (string)($_POST['setup_key'] ?? '');
            $username = trim((string)($_POST['username'] ?? ''));
            $password = (string)($_POST['password'] ?? '');
            if (!hash_equals((string)central_config('setup_key'), $setupKey)) {
                throw new CentralException('The setup key is incorrect.');
            }
            if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
                throw new CentralException('Enter a valid administrator email address.');
            }
            if (strlen($password) < 14) {
                throw new CentralException('Use an administrator password with at least 14 characters.');
            }

            $pdo->beginTransaction();
            $pdo->query('SELECT id FROM system_state WHERE id = 1 FOR UPDATE')->fetchColumn();
            if (central_admin_count($pdo) !== 0) {
                throw new CentralException('Initial setup has already been completed.');
            }
            $username = strtolower($username);
            $statement = $pdo->prepare('INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, UTC_TIMESTAMP())');
            $statement->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
            central_audit($pdo, (int)$pdo->lastInsertId(), null, 'Initial administrator created', 'Central portal initialized.');
            $pdo->commit();
            $notice = 'The first administrator account is ready. Sign in to continue.';
        } elseif ($action === 'login') {
            $username = strtolower(trim((string)($_POST['username'] ?? '')));
            $password = (string)($_POST['password'] ?? '');
            $ipHash = hash_hmac('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? ''), (string)central_config('setup_key'));
            $attempts = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip_hash = ? AND succeeded = 0 AND attempted_at > UTC_TIMESTAMP() - INTERVAL 15 MINUTE');
            $attempts->execute([$ipHash]);
            if ((int)$attempts->fetchColumn() >= 8) {
                throw new CentralException('Too many sign-in attempts. Wait 15 minutes and try again.');
            }
            $statement = $pdo->prepare('SELECT id, username, password_hash FROM admins WHERE username = ?');
            $statement->execute([$username]);
            $admin = $statement->fetch(PDO::FETCH_ASSOC);
            $succeeded = $admin && password_verify($password, $admin['password_hash']);
            $record = $pdo->prepare('INSERT INTO login_attempts (ip_hash, attempted_at, succeeded) VALUES (?, UTC_TIMESTAMP(), ?)');
            $record->execute([$ipHash, $succeeded ? 1 : 0]);
            if (!$succeeded) {
                throw new CentralException('Email or password is incorrect.');
            }
            session_regenerate_id(true);
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            $_SESSION['admin_id'] = (int)$admin['id'];
            $_SESSION['admin_name'] = (string)$admin['username'];
            central_audit($pdo, (int)$admin['id'], null, 'Administrator signed in', '');
            header('Location: ./');
            exit;
        } elseif ($action === 'logout') {
            central_require_admin();
            central_audit($pdo, (int)$_SESSION['admin_id'], null, 'Administrator signed out', '');
            $_SESSION = [];
            session_regenerate_id(true);
            header('Location: ./');
            exit;
        } elseif ($action === 'change_password') {
            central_require_admin();
            $adminId = (int)$_SESSION['admin_id'];
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $newPassword = (string)($_POST['new_password'] ?? '');
            $confirmPassword = (string)($_POST['confirm_password'] ?? '');
            $statement = $pdo->prepare('SELECT password_hash FROM admins WHERE id = ?');
            $statement->execute([$adminId]);
            $passwordHash = $statement->fetchColumn();
            if (!is_string($passwordHash) || !password_verify($currentPassword, $passwordHash)) {
                throw new CentralException('The current password is incorrect.');
            }
            if (strlen($newPassword) < 14) {
                throw new CentralException('Use a new password with at least 14 characters.');
            }
            if (!hash_equals($newPassword, $confirmPassword)) {
                throw new CentralException('The new password confirmation does not match.');
            }
            if (password_verify($newPassword, $passwordHash)) {
                throw new CentralException('Choose a new password different from your current password.');
            }
            $pdo->beginTransaction();
            $update = $pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?');
            $update->execute([password_hash($newPassword, PASSWORD_DEFAULT), $adminId]);
            central_audit($pdo, $adminId, null, 'Administrator changed password', '');
            $pdo->commit();
            session_regenerate_id(true);
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            $notice = 'Your administrator password has been changed.';
        } elseif ($action === 'add_admin') {
            central_require_admin();
            $adminId = (int)$_SESSION['admin_id'];
            $username = strtolower(trim((string)($_POST['username'] ?? '')));
            $password = (string)($_POST['password'] ?? '');
            $confirmPassword = (string)($_POST['confirm_password'] ?? '');
            if (!filter_var($username, FILTER_VALIDATE_EMAIL) || strlen($username) > 190) {
                throw new CentralException('Enter a valid administrator email address (maximum 190 characters).');
            }
            if (strlen($password) < 14) {
                throw new CentralException('Use an administrator password with at least 14 characters.');
            }
            if (!hash_equals($password, $confirmPassword)) {
                throw new CentralException('The administrator password confirmation does not match.');
            }
            $pdo->beginTransaction();
            $exists = $pdo->prepare('SELECT 1 FROM admins WHERE username = ?');
            $exists->execute([$username]);
            if ($exists->fetchColumn()) {
                throw new CentralException('An administrator with that email address already exists.');
            }
            try {
                $insert = $pdo->prepare('INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, UTC_TIMESTAMP())');
                $insert->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
            } catch (PDOException $exception) {
                if ($exception->getCode() === '23000') {
                    throw new CentralException('An administrator with that email address already exists.');
                }
                throw $exception;
            }
            central_audit($pdo, $adminId, null, 'Administrator account created', $username);
            $pdo->commit();
            $notice = 'Administrator account created for ' . $username . '. Share its initial password securely.';
        } else {
            central_require_admin();
            $adminId = (int)$_SESSION['admin_id'];

            if ($action === 'add_domains') {
                $incoming = central_validate_domains((string)($_POST['domains'] ?? ''));
                if (!$incoming) {
                    throw new CentralException('Enter at least one valid domain to add.');
                }
                $pdo->beginTransaction();
                $current = central_current_policy($pdo, true);
                $existing = central_validate_domains(implode("\n", array_filter($current['document']['blocked_domains'], 'is_string')));
                $domains = central_validate_domains(implode("\n", array_merge($existing, $incoming)));
                $added = count($domains) - count($existing);
                if ($added > 0) {
                    central_save_policy($pdo, $adminId, $current, $domains, $current['document']['subdomain_prefixes'], 'Company policy updated');
                    $pdo->commit();
                    $notice = "{$added} domain" . ($added === 1 ? '' : 's') . " added. The full policy now contains " . count($domains) . ' domains and will sync to enrolled PCs.';
                } else {
                    $pdo->rollBack();
                    $notice = 'Those domains are already in the published policy; the existing list was kept.';
                }
            } elseif ($action === 'remove_domain') {
                $toRemove = central_validate_domains((string)($_POST['domain'] ?? ''));
                if (count($toRemove) !== 1) {
                    throw new CentralException('Select one valid domain to remove.');
                }
                $pdo->beginTransaction();
                $current = central_current_policy($pdo, true);
                $domains = central_validate_domains(implode("\n", array_filter($current['document']['blocked_domains'], 'is_string')));
                if (!in_array($toRemove[0], $domains, true)) {
                    throw new CentralException('That domain is no longer in the published policy. Reload the page and try again.');
                }
                $domains = array_values(array_filter($domains, static fn(string $domain): bool => $domain !== $toRemove[0]));
                central_save_policy($pdo, $adminId, $current, $domains, $current['document']['subdomain_prefixes'], 'Domain removed from company policy');
                $pdo->commit();
                $notice = "{$toRemove[0]} removed. Enrolled PCs will remove its block at their next check-in.";
            } elseif ($action === 'enroll_device') {
                $label = trim((string)($_POST['label'] ?? ''));
                if ($label === '' || strlen($label) > 120) {
                    throw new CentralException('Enter a device label (1–120 characters).');
                }
                $code = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
                $insert = $pdo->prepare('INSERT INTO enrollment_codes (code_hash, created_by, expires_at) VALUES (?, ?, UTC_TIMESTAMP() + INTERVAL 24 HOUR)');
                $insert->execute([hash('sha256', $code), $adminId]);
                central_audit($pdo, $adminId, null, 'Device enrollment code created', $label);
                $_SESSION['one_time_code'] = $code;
                $oneTimeCode = $code;
                $notice = 'Enrollment code created. It is shown once and expires in 24 hours.';
            } elseif ($action === 'check_now') {
                $deviceId = preg_replace('/[^a-f0-9]/', '', (string)($_POST['device_id'] ?? ''));
                $exists = $pdo->prepare('SELECT id FROM devices WHERE id = ? AND revoked_at IS NULL');
                $exists->execute([$deviceId]);
                if (!$exists->fetchColumn()) {
                    throw new CentralException('The device was not found or is already revoked.');
                }
                $statement = $pdo->prepare('UPDATE devices SET check_requested = 1 WHERE id = ? AND revoked_at IS NULL');
                $statement->execute([$deviceId]);
                central_audit($pdo, $adminId, $deviceId, 'Check-in requested', 'The agent will receive this request the next time it checks in.');
                $notice = 'Check-in request queued. The device must be online with its agent running.';
            } elseif ($action === 'revoke_device') {
                $deviceId = preg_replace('/[^a-f0-9]/', '', (string)($_POST['device_id'] ?? ''));
                if (($_POST['confirm_revoke'] ?? '') !== 'yes') {
                    throw new CentralException('Confirm device revocation before continuing.');
                }
                $statement = $pdo->prepare('UPDATE devices SET revoked_at = UTC_TIMESTAMP(), check_requested = 0 WHERE id = ? AND revoked_at IS NULL');
                $statement->execute([$deviceId]);
                if ($statement->rowCount() !== 1) {
                    throw new CentralException('The device was not found or is already revoked.');
                }
                central_audit($pdo, $adminId, $deviceId, 'Device revoked', 'The device credential can no longer check in.');
                $notice = 'Device credential revoked.';
            } elseif ($action === 'delete_device') {
                $deviceId = strtolower((string)($_POST['device_id'] ?? ''));
                if (!preg_match('/^[a-f0-9]{32}$/', $deviceId)) {
                    throw new CentralException('Select a valid device record to delete.');
                }
                if (($_POST['confirm_delete'] ?? '') !== 'yes') {
                    throw new CentralException('Confirm permanent deletion of this revoked device.');
                }
                $pdo->beginTransaction();
                $find = $pdo->prepare('SELECT id, label, revoked_at FROM devices WHERE id = ? FOR UPDATE');
                $find->execute([$deviceId]);
                $device = $find->fetch(PDO::FETCH_ASSOC);
                if (!$device || $device['revoked_at'] === null) {
                    throw new CentralException('Only an existing, revoked device can be permanently deleted.');
                }
                $detach = $pdo->prepare("UPDATE audit_events SET detail = LEFT(CONCAT('Device ', ?, ' [', ?, ']: ', detail), 500), device_id = NULL WHERE device_id = ?");
                $detach->execute([$device['label'], $deviceId, $deviceId]);
                $delete = $pdo->prepare('DELETE FROM devices WHERE id = ? AND revoked_at IS NOT NULL');
                $delete->execute([$deviceId]);
                if ($delete->rowCount() !== 1) {
                    throw new CentralException('The revoked device could not be deleted.');
                }
                central_audit($pdo, $adminId, null, 'Revoked device permanently deleted', $device['label'] . ' [' . $deviceId . ']');
                $pdo->commit();
                $notice = 'The revoked device record was permanently deleted. Its audit history was retained.';
            } else {
                throw new CentralException('Unknown action.');
            }
        }
    } catch (CentralException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $error = $exception->getMessage();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('FireWall Central Administration portal error: ' . $exception->getMessage());
        $error = 'The request could not be completed. Check the server error log or try again.';
    }
}

$admin = central_is_admin();
$devices = [];
$events = [];
$admins = [];
$policy = ['blocked_domains' => []];
$policyVersion = 0;
$policyUpdatedAt = null;
$domainSearch = strtolower(trim((string)($_GET['domain_search'] ?? '')));
$activityPage = filter_var($_GET['activity_page'] ?? 1, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$activityPage = $activityPage === false ? 1 : min($activityPage, intdiv(PHP_INT_MAX - 1, 10));
$activityLimit = $activityPage * 10;
$hasMoreActivity = false;
try {
    $adminCount = central_admin_count($pdo);
    if ($admin) {
        $admins = $pdo->query('SELECT username, created_at FROM admins ORDER BY username ASC')->fetchAll(PDO::FETCH_ASSOC);
        $devices = $pdo->query('SELECT id, label, app_version, last_seen_at, applied_policy_version, protection_status, check_requested, revoked_at FROM devices ORDER BY enrolled_at DESC')->fetchAll(PDO::FETCH_ASSOC);
        $current = central_current_policy($pdo);
        $policyVersion = $current['version'];
        $policy = $current['document'];
        $policyUpdatedAt = $current['updated_at'];
        $events = $pdo->query('SELECT a.action, a.detail, a.created_at, COALESCE(ad.username, d.label, "System") AS actor FROM audit_events a LEFT JOIN admins ad ON ad.id = a.admin_id LEFT JOIN devices d ON d.id = a.device_id ORDER BY a.id DESC LIMIT ' . ($activityLimit + 1))->fetchAll(PDO::FETCH_ASSOC);
        $hasMoreActivity = count($events) > $activityLimit;
        if ($hasMoreActivity) {
            array_pop($events);
        }
    }
} catch (Throwable $exception) {
    error_log('FireWall Central Administration dashboard error: ' . $exception->getMessage());
    http_response_code(503);
    exit('FireWall Central Administration is not initialized. Import the database schema and check the cPanel PHP error log.');
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function device_state(array $device): array
{
    if ($device['revoked_at'] !== null) {
        return ['Revoked', 'revoked'];
    }
    if ($device['last_seen_at'] === null) {
        return ['Never checked in', 'offline'];
    }
    $seen = strtotime((string)$device['last_seen_at'] . ' UTC');
    if ($seen === false || $seen < time() - 180) {
        return ['No recent check-in', 'offline'];
    }
    return [$device['protection_status'] === 'active' ? 'Connected · protected' : 'Connected · review status', $device['protection_status'] === 'active' ? 'online' : 'pending'];
}

function device_policy_state(array $device, int $currentPolicyVersion): array
{
    if ($device['revoked_at'] !== null) {
        return ['Archived', 'revoked'];
    }
    if ($currentPolicyVersion === 0) {
        return ['No policy published', 'pending'];
    }
    $seen = $device['last_seen_at'] === null ? false : strtotime((string)$device['last_seen_at'] . ' UTC');
    if ($seen === false || $seen < time() - 180) {
        if ((int)$device['applied_policy_version'] >= $currentPolicyVersion) {
            return ['Last synced', 'offline'];
        }
        return ['Waiting for check-in', 'offline'];
    }
    if ((int)$device['applied_policy_version'] >= $currentPolicyVersion) {
        return ['Up to date', 'online'];
    }
    return ['Update at next check-in', 'pending'];
}

$deviceNameCounts = [];
foreach ($devices as $device) {
    if ($device['revoked_at'] !== null) {
        continue;
    }
    $name = strtolower(trim((string)$device['label']));
    $deviceNameCounts[$name] = ($deviceNameCounts[$name] ?? 0) + 1;
}
$allDomains = array_values(array_filter($policy['blocked_domains'] ?? [], 'is_string'));
$visibleDomains = array_values(array_filter(
    $allDomains,
    static fn(string $domain): bool => $domainSearch === '' || str_contains(strtolower($domain), $domainSearch),
));

$csrf = central_csrf_token();
header("Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Referrer-Policy: no-referrer');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FireWall Central Administration</title>
  <style>
    :root{font-family:'Segoe UI',Arial,sans-serif;color:#172a2d;background:#f2f5f1;font-synthesis:none;--ink:#172a2d;--muted:#718082;--line:#e3e9e4;--paper:#fff;--forest:#132529;--green:#17765f;--deep:#0f5f4a;--mint:#dff3e6;--lime:#c5ed6b;--amber:#d89237;--coral:#c45b4e}
    *{box-sizing:border-box}body{margin:0;min-width:360px}h1,h2,h3,p{margin-top:0}
    .site-header{background:#fff;color:#119eaa;border-bottom:1px solid #e3e9e4;box-shadow:0 3px 12px rgba(20,45,39,.04)}.header-inner{width:min(1180px,100%);min-height:92px;margin:auto;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;gap:22px}.brand{display:flex;align-items:center;gap:16px;text-decoration:none;color:inherit}.brand-logo{display:block;width:230px;height:68px;object-fit:contain}.brand-copy strong,.brand-copy span{display:block}.brand-copy strong{color:#119eaa;font-family:Georgia,serif;font-size:20px;letter-spacing:.2px}.brand-copy span{margin-top:5px;color:#64777a;font-size:12px}.header-inner form{margin:0}.wrap{width:min(1180px,100%);margin:28px auto;padding:0 28px 42px}
    .page-intro{margin:0 0 20px}.page-intro .eyebrow{color:var(--green);font:600 10px Consolas,monospace;letter-spacing:1.2px;text-transform:uppercase}.page-intro h1{margin:7px 0;color:#183033;font:700 28px Georgia,serif}.page-intro p{margin:0;color:var(--muted);font-size:13px}
    .card{min-width:0;padding:22px;border:1px solid var(--line);border-radius:12px;background:var(--paper);box-shadow:0 12px 30px rgba(20,45,39,.045)}.grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);align-items:start;gap:18px;margin-bottom:18px}.card h2{margin:0 0 10px;color:#183033;font:700 19px Georgia,serif}.card h3{margin:21px 0 7px;color:#294344;font-size:13px}.muted{color:var(--muted);font-size:12px;line-height:1.6}
    .section-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin-bottom:14px}.section-head p{margin:4px 0 0}.count-chip,.badge{display:inline-flex;align-items:center;justify-content:center;border-radius:99px;padding:6px 10px;font-size:10px;font-weight:700;white-space:nowrap}.count-chip{color:#0f5f4a;background:var(--mint)}
    label{display:block;margin:13px 0 6px;color:#304342;font-size:11px;font-weight:700}input,textarea{width:100%;padding:10px 12px;border:1px solid #d6e0d8;border-radius:7px;color:var(--ink);background:#fff;font:inherit}input:focus,textarea:focus{outline:3px solid rgba(23,118,95,.17);border-color:#76a994}textarea{min-height:92px;resize:vertical;font:12px Consolas,monospace}input::placeholder,textarea::placeholder{color:#99a5a0}
    button{min-height:37px;padding:0 14px;border:1px solid transparent;border-radius:7px;color:#fff;background:var(--green);font-size:11px;font-weight:700;cursor:pointer;transition:background .15s,transform .15s}button:hover{background:var(--deep)}button:active{transform:translateY(1px)}button.secondary{border-color:#dce5de;color:#435452;background:#fff}button.secondary:hover{background:#f4f8f4}button.danger{min-height:29px;padding:0 10px;border-color:#f0d9d5;color:#a64a41;background:#fff8f7;font-size:10px}button.danger:hover{background:#fff0ed}.form-row{display:flex;align-items:flex-end;gap:10px}.form-row>div{flex:1}.form-row label{margin-top:0}.form-row button{flex:0 0 auto}.signout{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .activity-more{display:flex;justify-content:center;margin-top:16px}.read-more{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 16px;border-radius:7px;color:#fff;background:var(--green);font-size:11px;font-weight:700;text-decoration:none;transition:background .15s}.read-more:hover{background:var(--deep)}
    .account-summary{display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;list-style:none}.account-summary::-webkit-details-marker{display:none}.account-summary strong{color:#183033;font:700 19px Georgia,serif}.account-summary::after{content:'+';color:var(--green);font-size:20px;font-weight:700}.account-card[open] .account-summary::after{content:'−'}.account-content{padding-top:18px}.account-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.account-grid form{padding:18px;border:1px solid var(--line);border-radius:9px;background:#fbfcfa}.account-grid h3{margin:0 0 6px;color:#183033;font:700 16px Georgia,serif}.account-grid p{margin-bottom:12px}.account-list{margin-top:20px}.account-list h3{margin:0 0 8px;color:#294344;font-size:13px}
    .notice,.error,.code{padding:12px 15px;border-radius:8px;margin:0 0 16px}.notice{border:1px solid #d7ebdd;color:#226145;background:#edf8ef;font-size:12px}.error{border:1px solid #efd4cf;color:#902f28;background:#fff4f1;font-size:12px}.code{border:1px solid #d6e5f0;color:#244d5b;background:#f5f9fb;word-break:break-all;font:13px Consolas,monospace}
    .domain-tools{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:16px 0 10px}.domain-tools .muted{margin:0}.search{max-width:270px}.domain-list{max-height:400px;overflow:auto;border:1px solid var(--line);border-radius:8px}.domain-row{display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:42px;padding:6px 10px;border-bottom:1px solid #edf0ec;font:11px Consolas,monospace}.domain-row:last-child{border-bottom:0}.domain-row:nth-child(even){background:#fafbf9}.domain-list-empty{padding:18px;color:var(--muted);font-size:12px}.domain-summary{display:flex;justify-content:space-between;gap:12px;margin-top:9px;color:var(--muted);font-size:10px}
    .table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:11px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #edf0ec;vertical-align:top}th{color:#71807b;font:600 9px Consolas,monospace;letter-spacing:.8px;text-transform:uppercase}tbody tr:hover{background:#fafcf9}.badge.online{color:#176441;background:#e6f4e9}.badge.offline{color:#9d362c;background:#fff0ed}.badge.pending{color:#80590e;background:#fbf1df}.badge.revoked{color:#5e6c72;background:#edf0f2}.badge.duplicate{margin-top:6px;color:#80590e;background:#fff5df}.device-name{color:#294344;font-weight:700}.small{color:var(--muted);font-size:9px}.device-actions{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.device-actions form{margin:0}.device-actions label{display:flex;align-items:center;gap:5px;margin:0;font-size:9px}.device-actions input[type=checkbox]{width:auto}.signin{max-width:440px;margin:7vh auto}.signin h1{margin:0 0 8px;color:#183033;font:700 24px Georgia,serif}.signin form>button{margin-top:14px}.footer{margin-top:18px;color:var(--muted);font-size:10px}
    .signin{max-width:480px;padding:30px;border-top:4px solid var(--green)}.signin form>button{width:100%;margin-top:18px;min-height:42px}.auth .wrap{width:min(720px,100%);min-height:calc(100vh - 92px);display:flex;flex-direction:column;justify-content:flex-start;padding-top:20px}.auth .signin{width:100%;margin:34px auto 0;box-shadow:0 18px 48px rgba(20,45,39,.09)}.auth .footer{margin-top:auto;padding-top:32px}
    @media(max-width:760px){.header-inner{align-items:flex-start;padding:14px 16px;flex-direction:column}.brand-logo{width:156px;height:46px}.brand-copy strong{font-size:15px}.brand{gap:12px}.wrap{margin-top:20px;padding-right:16px;padding-left:16px}.grid,.account-grid{grid-template-columns:1fr}.form-row{align-items:stretch;flex-direction:column}.form-row button{align-self:flex-start}.domain-tools{align-items:stretch;flex-direction:column}.search{max-width:none}.card{padding:17px}.signin{padding:22px}.page-intro h1{font-size:24px}}
  </style>
</head>
<body class="<?= $admin ? 'dashboard' : 'auth' ?>">
<header class="site-header"><div class="header-inner">
  <a class="brand" href="./" aria-label="FireWall Central Administration home"><img class="brand-logo" src="./assets/avantis-logo-prl.png" alt="Avantis, Product of Zimbabwe"><span class="brand-copy"><strong>FireWall Central Administration</strong><span>Secure device policy management</span></span></a>
  <?php if ($admin): ?><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="logout"><button class="secondary signout">Sign out · <?=h((string)$_SESSION['admin_name'])?></button></form><?php endif; ?>
</div>
</header>
<main class="wrap">
<?php if ($notice !== ''): ?><div class="notice"><?=h($notice)?></div><?php endif; ?>
<?php if ($error !== ''): ?><div class="error"><?=h($error)?></div><?php endif; ?>
<?php if (!$admin && $adminCount === 0): ?>
  <section class="card signin"><h1>Set up the first administrator</h1><p class="muted">Enter your private setup key. Setup closes after the first admin is created.</p>
  <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="bootstrap">
  <label for="setup_key">One-time setup key</label><input id="setup_key" name="setup_key" type="password" required autocomplete="off">
  <label for="username">Administrator email</label><input id="username" name="username" type="email" required autocomplete="username">
  <label for="password">Password (14+ characters)</label><input id="password" name="password" type="password" required minlength="14" autocomplete="new-password">
  <button>Create administrator</button></form></section>
<?php elseif (!$admin): ?>
  <section class="card signin"><h1>Administrator sign in</h1><p class="muted">Manage device policy and administrators.</p>
  <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="login">
  <label for="username">Email</label><input id="username" name="username" type="email" required autocomplete="username">
  <label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password">
  <button>Sign in</button></form></section>
<?php else: ?>
  <div class="page-intro"><div class="eyebrow">ADMINISTRATION <span>·</span> COMPANY NETWORK</div><h1>Protection overview</h1><p>Manage blocked sites and enrolled PCs.</p></div>
  <details class="card account-card" id="administrator-accounts" style="margin-bottom:18px" <?=in_array((string)($_POST['action'] ?? ''), ['change_password', 'add_admin'], true) ? 'open' : ''?>><summary class="account-summary"><strong>Administrator accounts</strong><span class="muted">Password and account settings</span></summary>
    <div class="account-content">
    <div class="account-grid">
      <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="change_password"><h3>Change your password</h3><p class="muted">Use at least 14 characters.</p>
        <label for="current_password">Current password</label><input id="current_password" name="current_password" type="password" required autocomplete="current-password">
        <label for="new_password">New password</label><input id="new_password" name="new_password" type="password" required minlength="14" autocomplete="new-password">
        <label for="confirm_new_password">Confirm new password</label><input id="confirm_new_password" name="confirm_password" type="password" required minlength="14" autocomplete="new-password">
        <button type="submit">Update password</button>
      </form>
      <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="add_admin"><h3>Add an administrator</h3><p class="muted">New admins get full dashboard access.</p>
        <label for="new_admin_email">Administrator email</label><input id="new_admin_email" name="username" type="email" maxlength="190" required autocomplete="off">
        <label for="new_admin_password">Initial password (14+ characters)</label><input id="new_admin_password" name="password" type="password" required minlength="14" autocomplete="new-password">
        <label for="confirm_admin_password">Confirm password</label><input id="confirm_admin_password" name="confirm_password" type="password" required minlength="14" autocomplete="new-password">
        <button type="submit">Create administrator</button>
      </form>
    </div>
    <div class="account-list"><h3>Current administrators</h3><div class="table-wrap"><table><thead><tr><th>Email</th><th>Account created (UTC)</th></tr></thead><tbody><?php foreach ($admins as $account): ?><tr><td><?=h((string)$account['username'])?></td><td><?=h((string)$account['created_at'])?></td></tr><?php endforeach; ?></tbody></table></div></div>
    </div>
  </details>
  <?php if ($oneTimeCode !== ''): ?><section class="card"><h2>Enrollment code</h2><p class="muted">Use once within 24 hours.</p><div class="code"><?=h($oneTimeCode)?></div></section><?php endif; ?>
  <div class="grid">
    <section class="card">
      <div class="section-head"><div><h2>Company block policy</h2><p class="muted">Blocked domains sync to enrolled PCs.</p></div><span class="count-chip"><?=count($allDomains)?> blocked</span></div>
      <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="add_domains">
        <label for="domains">Add domain(s)</label><div class="form-row"><div><textarea id="domains" name="domains" rows="3" placeholder="example.com&#10;example.org" spellcheck="false" required></textarea></div><button type="submit">Add to policy</button></div>
        <p class="small muted">Adds to the list. Duplicates are ignored.</p>
      </form>
      <div class="domain-tools"><p class="muted"><strong>Published domains</strong> · <?=count($allDomains)?> total<?= $policyUpdatedAt ? ' · Updated ' . h((string)$policyUpdatedAt) . ' UTC' : '' ?></p><form method="get"><input class="search" type="search" id="domain_search" name="domain_search" value="<?=h($domainSearch)?>" placeholder="Find a domain" aria-label="Find a published domain"></form></div>
      <div class="domain-list">
        <?php foreach ($visibleDomains as $domain): ?>
        <div class="domain-row"><span><?=h($domain)?></span><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="remove_domain"><input type="hidden" name="domain" value="<?=h($domain)?>"><button class="danger" type="submit">Remove</button></form></div>
        <?php endforeach; ?>
        <?php if (!$visibleDomains): ?><div class="domain-list-empty"><?= $domainSearch !== '' ? 'No published domains match that search.' : 'No domains are currently published. Add domains above to create the company policy.' ?></div><?php endif; ?>
      </div>
      <div class="domain-summary"><span><?=count($visibleDomains)?> of <?=count($allDomains)?> domains</span><span>Syncs at next check-in.</span></div>
    </section>
    <section class="card"><h2>Enroll a PC</h2><p class="muted">Create a one-time code. Expires in 24 hours.</p>
      <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="enroll_device">
      <label for="label">Device label</label><input id="label" name="label" maxlength="120" placeholder="e.g. Reception-PC-01" required>
      <button type="submit">Create enrollment code</button></form>
    </section>
  </div>
  <section class="card" style="margin-top:18px"><div class="section-head"><div><h2>Enrolled devices</h2><p class="muted">Connection and policy status for enrolled PCs.</p></div><span class="badge pending">Checks in every minute</span></div>
    <?php if (!$devices): ?><p class="muted">No devices enrolled yet.</p><?php else: ?><div class="table-wrap"><table><thead><tr><th>Device</th><th>Connection</th><th>Last check-in (UTC)</th><th>App</th><th>Policy sync</th><th>Actions</th></tr></thead><tbody>
    <?php foreach ($devices as $device): [$stateLabel, $stateClass] = device_state($device); [$syncLabel, $syncClass] = device_policy_state($device, $policyVersion); $duplicateName = ($deviceNameCounts[strtolower(trim((string)$device['label']))] ?? 0) > 1; ?><tr><td><span class="device-name"><?=h((string)$device['label'])?></span><?php if ($duplicateName): ?><br><span class="badge duplicate">Duplicate device name</span><?php endif; ?><br><span class="small"><?=h((string)$device['id'])?></span></td><td><span class="badge <?=h($stateClass)?>"><?=h($stateLabel)?></span></td><td><?=h((string)($device['last_seen_at'] ?? '—'))?></td><td><?=h((string)$device['app_version'])?></td><td><span class="badge <?=h($syncClass)?>"><?=h($syncLabel)?></span></td><td><div class="device-actions">
    <?php if ($device['revoked_at'] === null): ?><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="check_now"><input type="hidden" name="device_id" value="<?=h((string)$device['id'])?>"><button class="secondary">Check in now</button></form>
    <form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="revoke_device"><input type="hidden" name="device_id" value="<?=h((string)$device['id'])?>"><label><input type="checkbox" name="confirm_revoke" value="yes" required> Confirm</label><button class="danger"><?= $duplicateName && $stateClass === 'offline' ? 'Retire old entry' : 'Revoke' ?></button></form><?php else: ?><span class="small">Archived <?=h((string)$device['revoked_at'])?></span><form method="post"><input type="hidden" name="csrf" value="<?=h($csrf)?>"><input type="hidden" name="action" value="delete_device"><input type="hidden" name="device_id" value="<?=h((string)$device['id'])?>"><label><input type="checkbox" name="confirm_delete" value="yes" required> Confirm delete</label><button class="danger" type="submit">Delete record</button></form><?php endif; ?>
    </div>
    </td></tr><?php endforeach; ?></tbody></table><?php endif; ?>
  </section>
  <section class="card" id="recent-activity" style="margin-top:18px"><h2>Recent activity</h2><?php if (!$events): ?><p class="muted">No activity yet.</p><?php else: ?><div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Admin / device</th><th>Action</th><th>Details</th></tr></thead><tbody><?php foreach ($events as $event): ?><tr><td><?=h((string)$event['created_at'])?></td><td><?=h((string)$event['actor'])?></td><td><?=h((string)$event['action'])?></td><td><?=h((string)$event['detail'])?></td></tr><?php endforeach; ?></tbody></table></div><?php if ($hasMoreActivity): ?><div class="activity-more"><a class="read-more" href="?activity_page=<?=h((string)($activityPage + 1))?>#recent-activity">Read more</a></div><?php endif; ?><?php endif; ?></section>
<?php endif; ?>
<p class="footer">FireWall Central Administration · Admin access only.</p>
</main></body></html>
