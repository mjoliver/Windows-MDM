-- Track consumed enrollment-token IDs (jti) so a short-lived enrollment token
-- can only be redeemed once (prevents replay → unlimited device enrollment).
CREATE TABLE IF NOT EXISTS consumed_enrollment_tokens (
    jti         TEXT PRIMARY KEY,
    consumed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
