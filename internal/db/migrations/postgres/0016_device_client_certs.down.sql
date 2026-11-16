DROP TABLE IF EXISTS device_issued_client_certs;
ALTER TABLE network_pki_profiles DROP COLUMN IF EXISTS wifi_eap_server_names;
ALTER TABLE network_pki_profiles DROP COLUMN IF EXISTS client_cert_key_location;
ALTER TABLE network_pki_profiles DROP COLUMN IF EXISTS client_cert_exportable;
ALTER TABLE network_pki_profiles DROP COLUMN IF EXISTS client_cert_validity_days;
ALTER TABLE network_pki_profiles DROP COLUMN IF EXISTS client_cert_subject_template;
