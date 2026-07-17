-- Add email-verification flag to users. NULL = unverified.
ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
