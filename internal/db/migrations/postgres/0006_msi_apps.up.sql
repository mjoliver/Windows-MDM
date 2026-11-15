-- MSI line-of-business application deployment via EnterpriseDesktopAppManagement CSP
CREATE TABLE IF NOT EXISTS msi_apps (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    publisher              TEXT NOT NULL DEFAULT '',
    version                TEXT NOT NULL DEFAULT '1.0.0',
    product_code           TEXT NOT NULL UNIQUE,
    upgrade_code           TEXT NOT NULL DEFAULT '',
    content_url            TEXT NOT NULL,
    sha256                 TEXT NOT NULL,
    file_size_bytes        BIGINT NOT NULL DEFAULT 0,
    command_line           TEXT NOT NULL DEFAULT '/quiet /norestart',
    timeout_minutes        INTEGER NOT NULL DEFAULT 15,
    retry_count            INTEGER NOT NULL DEFAULT 3,
    retry_interval_minutes INTEGER NOT NULL DEFAULT 5,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_apps (
    group_id    TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    app_id      TEXT NOT NULL REFERENCES msi_apps(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, app_id)
);

CREATE TABLE IF NOT EXISTS device_app_installs (
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app_id          TEXT NOT NULL REFERENCES msi_apps(id) ON DELETE CASCADE,
    product_code    TEXT NOT NULL,
    desired_action  TEXT NOT NULL DEFAULT 'install',
    status_code     INTEGER,
    status_label    TEXT NOT NULL DEFAULT 'Queued',
    last_error      TEXT NOT NULL DEFAULT '',
    last_error_desc TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, app_id)
);
