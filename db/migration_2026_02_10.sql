-- Migration for multi-user evolution (2026-02-10)
-- Safe, idempotent changes for existing databases.

ALTER TABLE flow_payments
  ADD COLUMN IF NOT EXISTS company TEXT;

ALTER TABLE flow_payments
  ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE flow_payments
  ADD COLUMN IF NOT EXISTS updated_by TEXT;

ALTER TABLE flow_archives
  ADD COLUMN IF NOT EXISTS company TEXT;

CREATE TABLE IF NOT EXISTS app_roles (
  name TEXT PRIMARY KEY,
  permissions JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_user_companies (
  user_id BIGINT NOT NULL,
  company TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, company)
);

-- Optional indexes for performance
CREATE INDEX IF NOT EXISTS idx_flow_payments_company ON flow_payments(company);
CREATE INDEX IF NOT EXISTS idx_flow_archives_company ON flow_archives(company);
