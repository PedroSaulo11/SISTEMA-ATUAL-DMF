-- Multiuser hardening migration (2026-02-26)
-- Goals:
-- 1) Ensure flow_payments is isolated per company (composite PK: company,id)
-- 2) Normalize legacy rows with NULL/empty company to DMF
-- 3) Ensure refresh-session table exists

ALTER TABLE flow_payments
  ADD COLUMN IF NOT EXISTS company TEXT;

UPDATE flow_payments
SET company = 'DMF'
WHERE company IS NULL OR BTRIM(company) = '';

ALTER TABLE flow_payments
  ALTER COLUMN company SET DEFAULT 'DMF';

ALTER TABLE flow_payments
  ALTER COLUMN company SET NOT NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.table_constraints tc
    WHERE tc.table_name = 'flow_payments'
      AND tc.constraint_type = 'PRIMARY KEY'
      AND tc.constraint_name <> 'flow_payments_pkey'
  ) THEN
    EXECUTE (
      SELECT 'ALTER TABLE flow_payments DROP CONSTRAINT ' || quote_ident(tc.constraint_name)
      FROM information_schema.table_constraints tc
      WHERE tc.table_name = 'flow_payments'
        AND tc.constraint_type = 'PRIMARY KEY'
      LIMIT 1
    );
  END IF;
EXCEPTION WHEN undefined_table THEN
  -- No-op if table does not exist in the target environment.
  NULL;
END $$;

-- Rebuild canonical PK as (company,id). Safe if already in the desired shape.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.table_constraints tc
    WHERE tc.table_name = 'flow_payments'
      AND tc.constraint_type = 'PRIMARY KEY'
      AND tc.constraint_name = 'flow_payments_pkey'
  ) THEN
    ALTER TABLE flow_payments DROP CONSTRAINT flow_payments_pkey;
  END IF;
EXCEPTION WHEN undefined_object THEN
  NULL;
END $$;

ALTER TABLE flow_payments
  ADD CONSTRAINT flow_payments_pkey PRIMARY KEY (company, id);

CREATE INDEX IF NOT EXISTS idx_flow_payments_company ON flow_payments(company);
CREATE INDEX IF NOT EXISTS idx_flow_payments_company_id ON flow_payments(company, id);

CREATE TABLE IF NOT EXISTS app_user_refresh_sessions (
  token_id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  family_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  rotated_at TIMESTAMPTZ,
  user_agent TEXT,
  ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_refresh_sessions_user ON app_user_refresh_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_refresh_sessions_family ON app_user_refresh_sessions(family_id);
