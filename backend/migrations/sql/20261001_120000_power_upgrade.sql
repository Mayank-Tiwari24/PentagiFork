-- +goose Up
-- Migration: Add parallel execution groups, ATT&CK mapping, and plugin support

-- ============================================================================
-- 1. Parallel Execution Groups
--    Subtasks can now belong to execution groups. Subtasks in the same group
--    run concurrently; groups execute sequentially in ascending order.
-- ============================================================================

ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS group_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE subtasks ADD COLUMN IF NOT EXISTS depends_on INTEGER[] DEFAULT '{}';

COMMENT ON COLUMN subtasks.group_index IS 'Parallel execution group index. 0 = ungrouped (sequential). >0 = subtasks with same index run in parallel.';
COMMENT ON COLUMN subtasks.depends_on IS 'Array of group indices this subtask depends on. Empty = depends on previous group only.';

-- Index for efficient group lookups during parallel execution
CREATE INDEX IF NOT EXISTS idx_subtasks_group ON subtasks (task_id, group_index) WHERE group_index > 0;


-- ============================================================================
-- 2. MITRE ATT&CK Technique Mapping
--    Records which ATT&CK techniques were exercised during a pentest flow.
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_mappings (
    id BIGSERIAL PRIMARY KEY,
    flow_id BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    subtask_id BIGINT REFERENCES subtasks(id) ON DELETE SET NULL,
    toolcall_id BIGINT REFERENCES toolcalls(id) ON DELETE SET NULL,

    technique_id VARCHAR(20) NOT NULL,       -- e.g., "T1059.004"
    technique_name VARCHAR(255) DEFAULT '',  -- e.g., "Unix Shell"
    tactic VARCHAR(50) DEFAULT '',           -- e.g., "execution"
    confidence REAL NOT NULL DEFAULT 0.0,    -- 0.0 to 1.0
    source VARCHAR(255) NOT NULL DEFAULT '', -- e.g., "tool:terminal", "keyword:nmap"

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_mappings_flow ON attack_mappings (flow_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique ON attack_mappings (technique_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_tactic ON attack_mappings (tactic);

COMMENT ON TABLE attack_mappings IS 'MITRE ATT&CK technique mappings auto-generated during pentest flows.';


-- ============================================================================
-- 3. Attack Patterns (Cross-Flow Learning)
--    Global knowledge store for reusable pentest patterns.
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_patterns (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_flow_id BIGINT REFERENCES flows(id) ON DELETE SET NULL,
    source_task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    source_subtask_id BIGINT REFERENCES subtasks(id) ON DELETE SET NULL,

    -- Classification
    pattern_type VARCHAR(50) NOT NULL DEFAULT 'successful_attack',
    -- CHECK (pattern_type IN ('successful_attack','failed_attack','tool_sequence','target_profile','vulnerability','remediation'))

    -- Content
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',

    -- Target context
    target_type VARCHAR(50) DEFAULT '',      -- web_app, network, api, cloud, mobile
    target_tech TEXT[] DEFAULT '{}',          -- ["nginx","php","mysql"]
    target_os VARCHAR(50) DEFAULT '',         -- linux, windows, macos
    attack_surface VARCHAR(50) DEFAULT '',    -- external, internal, wireless

    -- Effectiveness tracking
    success BOOLEAN NOT NULL DEFAULT false,
    confidence REAL NOT NULL DEFAULT 0.5,
    use_count INTEGER NOT NULL DEFAULT 0,
    last_used TIMESTAMP WITH TIME ZONE,

    -- MITRE ATT&CK references
    attack_techniques TEXT[] DEFAULT '{}',    -- ["T1059.004","T1046"]
    attack_tactics TEXT[] DEFAULT '{}',       -- ["execution","discovery"]

    -- Vulnerability details (for vulnerability patterns)
    cve VARCHAR(30) DEFAULT '',
    cvss REAL DEFAULT 0.0,
    severity VARCHAR(20) DEFAULT '',          -- critical, high, medium, low, info

    -- Tool chain (JSON array of steps for tool_sequence patterns)
    tool_chain JSONB DEFAULT '[]'::JSONB,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_patterns_user ON attack_patterns (user_id);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns (pattern_type);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_target ON attack_patterns (target_type, target_os);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_success ON attack_patterns (success) WHERE success = true;
CREATE INDEX IF NOT EXISTS idx_attack_patterns_techniques ON attack_patterns USING gin (attack_techniques);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_cve ON attack_patterns (cve) WHERE cve != '';

COMMENT ON TABLE attack_patterns IS 'Cross-flow knowledge base: reusable attack patterns learned from previous pentests.';


-- ============================================================================
-- 4. Plugin Registry
--    Persists loaded plugins and their configuration state.
-- ============================================================================

CREATE TABLE IF NOT EXISTS plugins (
    id BIGSERIAL PRIMARY KEY,
    plugin_id VARCHAR(100) UNIQUE NOT NULL,       -- Unique plugin identifier from manifest
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL DEFAULT '0.0.0',
    plugin_type VARCHAR(50) NOT NULL,             -- tool, agent, search, reporter, integration
    description TEXT DEFAULT '',
    author VARCHAR(255) DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- active, disabled, error
    config JSONB DEFAULT '{}'::JSONB,             -- Plugin-specific configuration
    manifest JSONB NOT NULL DEFAULT '{}'::JSONB,   -- Full manifest snapshot
    source_dir VARCHAR(500) DEFAULT '',
    error_message TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_plugins_plugin_id ON plugins (plugin_id);

COMMENT ON TABLE plugins IS 'Plugin registry tracking installed and active plugins.';


-- ============================================================================
-- 5. Webhook Subscriptions
--    Notify external systems when events occur (flow completion, vuln found, etc.)
-- ============================================================================

CREATE TABLE IF NOT EXISTS webhooks (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL DEFAULT '',
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(255) NOT NULL DEFAULT '',   -- HMAC signing secret for payload verification
    events TEXT[] NOT NULL DEFAULT '{}',       -- ["flow_completed","vulnerability_found","flow_failed"]
    enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Delivery tracking
    last_triggered_at TIMESTAMP WITH TIME ZONE,
    last_status_code INTEGER DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    
    -- Auto-disable after too many failures
    max_failures INTEGER NOT NULL DEFAULT 10,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks (user_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_events ON webhooks USING gin (events);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks (enabled) WHERE enabled = true;

COMMENT ON TABLE webhooks IS 'Webhook subscriptions for external event notifications.';


-- ============================================================================
-- 6. Audit Log
--    Immutable record of all security-relevant actions.
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,              -- e.g., "flow.create", "provider.update", "user.login"
    resource_type VARCHAR(50) NOT NULL,         -- e.g., "flow", "provider", "user", "token"
    resource_id VARCHAR(100) DEFAULT '',        -- ID of the affected resource
    details JSONB DEFAULT '{}'::JSONB,          -- Additional context (old/new values, IP, etc.)
    ip_address VARCHAR(45) DEFAULT '',          -- Client IP address
    user_agent TEXT DEFAULT '',                 -- Client user agent

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Partition-friendly index for time-range queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource_type, resource_id);

COMMENT ON TABLE audit_logs IS 'Immutable audit trail of all security-relevant actions. Append-only — no UPDATE or DELETE.';

-- Protect audit log from modification
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable — UPDATE and DELETE are not permitted';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_immutable ON audit_logs;
CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();


-- ============================================================================
-- 7. Grant permissions to the application role (if it exists)
-- ============================================================================

DO $$
BEGIN
    -- Grant permissions on new tables to pentagi_app role if it exists
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pentagi_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON attack_mappings TO pentagi_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON attack_patterns TO pentagi_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON plugins TO pentagi_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON webhooks TO pentagi_app;
        GRANT SELECT, INSERT ON audit_logs TO pentagi_app;  -- No UPDATE/DELETE for audit
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pentagi_app;
    END IF;
END $$;


-- +goose Down

DROP TRIGGER IF EXISTS audit_log_immutable ON audit_logs;
DROP FUNCTION IF EXISTS prevent_audit_log_modification();
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS webhooks;
DROP TABLE IF EXISTS plugins;
DROP TABLE IF EXISTS attack_patterns;
DROP TABLE IF EXISTS attack_mappings;
ALTER TABLE subtasks DROP COLUMN IF EXISTS depends_on;
ALTER TABLE subtasks DROP COLUMN IF EXISTS group_index;
