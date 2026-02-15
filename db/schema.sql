CREATE TABLE IF NOT EXISTS app_users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS api_tokens (
  service TEXT PRIMARY KEY,
  access_token TEXT,
  refresh_token TEXT,
  expires_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhook_data (
  id BIGSERIAL PRIMARY KEY,
  source TEXT NOT NULL,
  payload JSONB NOT NULL,
  headers JSONB,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS flow_payments (
    id TEXT PRIMARY KEY,
    company TEXT,
    fornecedor TEXT NOT NULL,
    data TEXT,
    descricao TEXT,
    valor DOUBLE PRECISION,
    centro TEXT,
    categoria TEXT,
    assinatura JSONB,
    version INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS flow_archives (
    id TEXT PRIMARY KEY,
    company TEXT,
    label TEXT NOT NULL,
    payments JSONB NOT NULL,
    created_by TEXT,
    count INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_user_companies (
    user_id BIGINT NOT NULL,
    company TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, company)
);

CREATE TABLE IF NOT EXISTS app_center_companies (
    center_key TEXT PRIMARY KEY,
    center_label TEXT NOT NULL,
    company TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_cost_centers (
    center_key TEXT PRIMARY KEY,
    center_label TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_company TEXT
);

CREATE TABLE IF NOT EXISTS backup_snapshots (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logins (
    id BIGSERIAL PRIMARY KEY,
    username TEXT,
    ip TEXT,
    success BOOLEAN DEFAULT FALSE,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    details TEXT,
    username TEXT,
    user_id BIGINT,
    ip TEXT,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_roles (
    name TEXT PRIMARY KEY,
    permissions JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_sessions (
    user_id BIGINT PRIMARY KEY,
    revoked_after TIMESTAMPTZ
);
