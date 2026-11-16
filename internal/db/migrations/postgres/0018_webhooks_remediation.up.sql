CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    url              TEXT NOT NULL,
    format           TEXT NOT NULL DEFAULT 'json',
    secret_encrypted TEXT NOT NULL DEFAULT '',
    has_secret       INTEGER NOT NULL DEFAULT 0,
    events_csv       TEXT NOT NULL DEFAULT '*',
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id           BIGSERIAL PRIMARY KEY,
    webhook_id   TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    status_code  INTEGER NOT NULL DEFAULT 0,
    success      INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id, id DESC);

CREATE TABLE IF NOT EXISTS compliance_automation_settings (
    id                 TEXT PRIMARY KEY,
    auto_remediate     INTEGER NOT NULL DEFAULT 0,
    remediation_count  INTEGER NOT NULL DEFAULT 0,
    last_remediated_at TIMESTAMPTZ,
    updated_by         TEXT NOT NULL DEFAULT '',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
