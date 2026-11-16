CREATE TABLE IF NOT EXISTS bulk_enrollment_tokens (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    token_prefix  TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    auto_group_id TEXT NOT NULL DEFAULT '',
    max_uses      INTEGER NOT NULL DEFAULT 0,
    use_count     INTEGER NOT NULL DEFAULT 0,
    expires_at    TIMESTAMP,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bulk_enrollment_tokens_hash ON bulk_enrollment_tokens(token_hash);
