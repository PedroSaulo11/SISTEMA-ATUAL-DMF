CREATE TABLE IF NOT EXISTS app_center_companies (
    center_key TEXT PRIMARY KEY,
    center_label TEXT NOT NULL,
    company TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
