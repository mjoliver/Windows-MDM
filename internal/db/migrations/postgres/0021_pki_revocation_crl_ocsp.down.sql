DROP TABLE IF EXISTS pki_crl_state;
ALTER TABLE certificates DROP COLUMN revocation_reason;
ALTER TABLE certificates DROP COLUMN revoked_at;
