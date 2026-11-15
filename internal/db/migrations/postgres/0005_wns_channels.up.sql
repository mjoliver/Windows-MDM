-- Windows Push Notification Services (WNS) channel URIs reported via DMClient Push CSP
CREATE TABLE IF NOT EXISTS device_wns_channels (
    device_id        TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    channel_uri      TEXT NOT NULL,
    push_status      INTEGER,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_push_at     TIMESTAMP,
    last_push_status TEXT
);
