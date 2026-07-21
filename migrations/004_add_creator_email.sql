-- Add creator_email column to secrets table
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS creator_email TEXT;
