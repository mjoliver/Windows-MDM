-- 0001_initial_schema.up.sql
-- Initial Pane database schema

-- Users: admins and enrolling users
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    display_name TEXT,
    role        TEXT NOT NULL DEFAULT 'user',      -- 'super_admin', 'admin', 'user'
    auth_provider TEXT NOT NULL DEFAULT 'oidc',    -- 'oidc', 'ldap', 'builtin'
    password_hash TEXT,                            -- only for builtin auth
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME
);

-- Enrolled Windows devices
CREATE TABLE IF NOT EXISTS devices (
    id              TEXT PRIMARY KEY,
    hardware_id     TEXT UNIQUE NOT NULL,          -- from device during enrollment
    device_name     TEXT,
    os_version      TEXT,
    os_build        TEXT,
    manufacturer    TEXT,
    model           TEXT,
    serial_number   TEXT,
    enrolled_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enrolled_by     TEXT,                          -- user email
    last_checkin    DATETIME,
    compliance_status TEXT NOT NULL DEFAULT 'unknown', -- 'compliant', 'non_compliant', 'pending', 'unknown'
    is_active       INTEGER NOT NULL DEFAULT 1     -- 0 = unenrolled
);

-- Device certificates issued by the internal CA
CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_type       TEXT NOT NULL,                 -- 'root_ca', 'device'
    subject         TEXT,
    thumbprint      TEXT UNIQUE NOT NULL,
    serial_number   TEXT NOT NULL,
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    cert_pem        TEXT NOT NULL,
    key_pem_encrypted TEXT,                        -- only set for root_ca, AES-256 encrypted
    device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Policy catalog - populated by DDF ingestion tool
CREATE TABLE IF NOT EXISTS policy_catalog (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    oma_uri         TEXT UNIQUE NOT NULL,
    display_name    TEXT,
    description     TEXT,
    category        TEXT,                          -- e.g. 'Security/BitLocker', 'Network'
    csp_name        TEXT,                          -- e.g. 'BitLocker', 'DeviceLock'
    data_type       TEXT NOT NULL,                 -- 'boolean', 'integer', 'string', 'enum', 'xml'
    allowed_values  TEXT,                          -- JSON array: [{"value":"0","label":"Disabled"}]
    default_value   TEXT,
    min_os_version  TEXT,
    access_types    TEXT,                          -- JSON array: ["Get","Replace"]
    is_deprecated   INTEGER NOT NULL DEFAULT 0,
    source          TEXT NOT NULL DEFAULT 'ddf',   -- 'ddf', 'manual'
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Configuration profiles: named collections of policy settings
CREATE TABLE IF NOT EXISTS profiles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    created_by  TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Policy settings within a profile
CREATE TABLE IF NOT EXISTS profile_settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    catalog_id      INTEGER NOT NULL REFERENCES policy_catalog(id),
    desired_value   TEXT NOT NULL,
    UNIQUE(profile_id, catalog_id)
);

-- Device groups for bulk policy assignment
CREATE TABLE IF NOT EXISTS device_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Device group membership
CREATE TABLE IF NOT EXISTS device_group_members (
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, group_id)
);

-- Profile assignment to groups
CREATE TABLE IF NOT EXISTS group_profiles (
    group_id    TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, profile_id)
);

-- OMA-DM command queue: pending commands per device
CREATE TABLE IF NOT EXISTS command_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_type    TEXT NOT NULL,                 -- 'Get', 'Replace', 'Add', 'Delete', 'Exec'
    oma_uri         TEXT NOT NULL,
    payload         TEXT,
    status          TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'sent', 'success', 'failed'
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at         DATETIME,
    completed_at    DATETIME,
    result_code     TEXT,
    result_data     TEXT
);

-- Compliance records per device per policy
CREATE TABLE IF NOT EXISTS compliance_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    catalog_id      INTEGER NOT NULL REFERENCES policy_catalog(id),
    profile_id      TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    desired_value   TEXT,
    actual_value    TEXT,
    is_compliant    INTEGER,                       -- 1 = compliant, 0 = not, NULL = unknown
    checked_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit log: every admin action recorded
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email  TEXT,
    action      TEXT NOT NULL,                     -- 'device.enroll', 'device.wipe', 'policy.apply'
    target_type TEXT,                              -- 'device', 'profile', 'group', 'user'
    target_id   TEXT,
    details     TEXT,                              -- JSON with action-specific data
    ip_address  TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_devices_hardware_id ON devices(hardware_id);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active);
CREATE INDEX IF NOT EXISTS idx_certificates_thumbprint ON certificates(thumbprint);
CREATE INDEX IF NOT EXISTS idx_certificates_device ON certificates(device_id);
CREATE INDEX IF NOT EXISTS idx_command_queue_device_status ON command_queue(device_id, status);
CREATE INDEX IF NOT EXISTS idx_compliance_device ON compliance_records(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_policy_catalog_csp ON policy_catalog(csp_name);
