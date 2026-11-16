-- 0021_pki_revocation_crl_ocsp.up.sql
-- Milestone 20: RFC 5280 CRL sequence state + revocation timestamp & reason on certificates

ALTER TABLE certificates ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE certificates ADD COLUMN revocation_reason INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS pki_crl_state (
    id         TEXT PRIMARY KEY,
    crl_number INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO pki_crl_state (id, crl_number) VALUES ('default', 0) ON CONFLICT (id) DO NOTHING;
