CREATE TABLE IF NOT EXISTS admins (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_state (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT IGNORE INTO system_state (id) VALUES (1);

CREATE TABLE IF NOT EXISTS policies (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    version BIGINT UNSIGNED NOT NULL,
    document JSON NOT NULL,
    updated_by BIGINT UNSIGNED NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT fk_policy_admin FOREIGN KEY (updated_by) REFERENCES admins(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS devices (
    id CHAR(32) NOT NULL PRIMARY KEY,
    label VARCHAR(120) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    app_version VARCHAR(40) NOT NULL DEFAULT '',
    last_seen_at DATETIME NULL,
    applied_policy_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    protection_status VARCHAR(40) NOT NULL DEFAULT 'unknown',
    check_requested TINYINT(1) NOT NULL DEFAULT 0,
    enrolled_at DATETIME NOT NULL,
    revoked_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS enrollment_codes (
    code_hash CHAR(64) NOT NULL PRIMARY KEY,
    created_by BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    CONSTRAINT fk_enrollment_admin FOREIGN KEY (created_by) REFERENCES admins(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    admin_id BIGINT UNSIGNED NULL,
    device_id CHAR(32) NULL,
    action VARCHAR(80) NOT NULL,
    detail VARCHAR(500) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    INDEX idx_audit_created (created_at),
    CONSTRAINT fk_audit_admin FOREIGN KEY (admin_id) REFERENCES admins(id),
    CONSTRAINT fk_audit_device FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip_hash CHAR(64) NOT NULL,
    attempted_at DATETIME NOT NULL,
    succeeded TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_login_ip_time (ip_hash, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
