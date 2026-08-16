-- Add password_version column to track legacy vs. new passwords
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_version SMALLINT NOT NULL DEFAULT 0;
