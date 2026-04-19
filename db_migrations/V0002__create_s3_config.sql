CREATE TABLE IF NOT EXISTS t_p89874656_cloud_security_audit.s3_config (
    service_name TEXT NOT NULL,
    config_key   TEXT NOT NULL,
    config_value TEXT NOT NULL,
    updated_at   TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (service_name, config_key)
);