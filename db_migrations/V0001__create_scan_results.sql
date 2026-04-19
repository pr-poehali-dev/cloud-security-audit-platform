CREATE TABLE IF NOT EXISTS t_p89874656_cloud_security_audit.scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID DEFAULT gen_random_uuid() NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'completed',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'unknown',
    env_vars_count INTEGER DEFAULT 0,
    secrets_found INTEGER DEFAULT 0,
    suspicious_files INTEGER DEFAULT 0,
    open_ports TEXT[],
    platform_info JSONB,
    env_snapshot JSONB,
    fs_snapshot JSONB,
    network_info JSONB,
    process_info JSONB,
    summary JSONB,
    raw_data JSONB
);