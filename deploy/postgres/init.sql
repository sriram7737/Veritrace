-- Veritrace bootstrap DDL
-- Tables are created by PostgresStore on first connection (auto-DDL).
-- This script creates the DB role and grants, run once at cluster init.

-- Restrict to schema-level permissions (least-privilege)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'veritrace') THEN
    CREATE ROLE veritrace LOGIN;
  END IF;
END
$$;

-- Grant only what the app needs
GRANT CONNECT ON DATABASE veritrace TO veritrace;
GRANT USAGE, CREATE ON SCHEMA public TO veritrace;
