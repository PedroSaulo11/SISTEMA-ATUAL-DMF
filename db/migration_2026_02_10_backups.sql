-- Migration for automated backups (2026-02-10)
CREATE TABLE IF NOT EXISTS backup_snapshots (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  payload JSONB NOT NULL
);
