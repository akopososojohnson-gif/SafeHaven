-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email               VARCHAR(255) UNIQUE NOT NULL,
    zkp_public_key      BYTEA NOT NULL,
    argon2_salt         BYTEA NOT NULL CHECK (octet_length(argon2_salt) = 32),
    argon2_memory       INTEGER NOT NULL DEFAULT 65536 CHECK (argon2_memory >= 65536),
    argon2_iterations   INTEGER NOT NULL DEFAULT 3 CHECK (argon2_iterations >= 3),
    argon2_parallelism  INTEGER NOT NULL DEFAULT 4 CHECK (argon2_parallelism >= 1),
    vault_key_wrap      BYTEA NOT NULL CHECK (octet_length(vault_key_wrap) = 60),
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_type            VARCHAR(20) CHECK (mfa_type IN ('totp', 'webauthn', 'backup_codes')),
    mfa_secret          BYTEA,
    mfa_backup_codes    BYTEA,
    webauthn_credential_id BYTEA,
    failed_login_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    last_login_ip           INET,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,
    storage_used_bytes  BIGINT NOT NULL DEFAULT 0,
    storage_quota_bytes BIGINT NOT NULL DEFAULT 1073741824,
    version             INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_locked ON users(locked_until) WHERE locked_until IS NOT NULL AND deleted_at IS NULL;

-- ─────────────────────────────────────────────────────────────
-- VAULT ITEMS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE vault_items (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob_id         UUID NOT NULL UNIQUE,
    blob_size       INTEGER NOT NULL CHECK (blob_size > 0),
    item_type       VARCHAR(50) NOT NULL CHECK (item_type IN (
        'password', 'secure_note', 'credit_card',
        'identity', 'ssh_key', 'api_key', 'file', 'folder'
    )),
    name_hash       BYTEA,
    parent_id       UUID REFERENCES vault_items(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    version         INTEGER NOT NULL DEFAULT 1,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    favorite        BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT valid_parent CHECK (
        parent_id IS NULL OR parent_id != id
    )
);

CREATE INDEX idx_vault_items_user ON vault_items(user_id, deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_user_type ON vault_items(user_id, item_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_parent ON vault_items(parent_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_updated ON vault_items(user_id, updated_at);

-- ─────────────────────────────────────────────────────────────
-- VAULT BLOBS (temporary; production uses MinIO/S3)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE vault_blobs (
    blob_id     UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data        BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vault_blobs_user ON vault_blobs(user_id);

-- ─────────────────────────────────────────────────────────────
-- SHARE LINKS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE share_links (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob_id         UUID NOT NULL,
    expiry          TIMESTAMPTZ NOT NULL,
    max_uses        INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count      INTEGER NOT NULL DEFAULT 0 CHECK (used_count <= max_uses),
    hmac            BYTEA NOT NULL CHECK (octet_length(hmac) = 32),
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users(id),
    password_protected  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hint       VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    last_used_ip    INET
);

CREATE INDEX idx_share_links_active ON share_links(expiry, revoked, used_count, max_uses)
    WHERE NOT revoked AND used_count < max_uses;
CREATE INDEX idx_share_links_creator ON share_links(creator_id);

-- ─────────────────────────────────────────────────────────────
-- SESSIONS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ DEFAULT NOW(),
    last_used_ip    INET,
    user_agent      TEXT,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    device_id       VARCHAR(255),
    device_name     VARCHAR(255)
);

CREATE INDEX idx_sessions_user ON sessions(user_id, revoked) WHERE NOT revoked;
CREATE INDEX idx_sessions_expiry ON sessions(expires_at) WHERE NOT revoked;

-- ─────────────────────────────────────────────────────────────
-- AUDIT LOG (Partitioned)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id              BIGSERIAL,
    user_id         UUID REFERENCES users(id),
    action          VARCHAR(100) NOT NULL CHECK (action IN (
        'user_registered', 'login_success', 'login_failed', 'logout',
        'mfa_enabled', 'mfa_disabled', 'mfa_verified', 'mfa_challenge_failed',
        'vault_item_created', 'vault_item_updated', 'vault_item_deleted',
        'vault_item_accessed', 'vault_sync_initiated', 'vault_sync_completed',
        'share_created', 'share_redeemed', 'share_revoked', 'share_expired',
        'password_changed', 'account_locked', 'account_unlocked',
        'export_initiated', 'import_completed', 'hibp_check',
        'device_authorized', 'device_revoked'
    )),
    ip_address      INET,
    user_agent      TEXT,
    session_id      UUID,
    success         BOOLEAN NOT NULL,
    failure_reason  VARCHAR(255),
    details         JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);

CREATE TABLE audit_log_2026_05 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_log_2026_06 PARTITION OF audit_log
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_audit_user_time ON audit_log(user_id, timestamp);
CREATE INDEX idx_audit_action_time ON audit_log(action, timestamp);
CREATE INDEX idx_audit_ip ON audit_log(ip_address, timestamp);

-- Immutable trigger
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- ─────────────────────────────────────────────────────────────
-- HIBP CACHE
-- ─────────────────────────────────────────────────────────────
CREATE TABLE hibp_cache (
    prefix          VARCHAR(5) PRIMARY KEY CHECK (prefix ~ '^[A-Fa-f0-9]{5}$'),
    suffixes        JSONB NOT NULL,
    cached_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_hibp_expiry ON hibp_cache(expires_at);
