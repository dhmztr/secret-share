-- Monthly quota window: quota refills to the tier default once this timestamp passes.
ALTER TABLE users ADD COLUMN IF NOT EXISTS quota_reset_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '1 month');
