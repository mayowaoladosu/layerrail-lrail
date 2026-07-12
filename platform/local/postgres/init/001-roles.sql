\set ON_ERROR_STOP on

-- Development-only roles mirror production privilege separation. The shared
-- password is deliberately public and cannot be used outside this local stack.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lrail_web') THEN
    CREATE ROLE lrail_web LOGIN PASSWORD 'local-only-not-a-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lrail_worker') THEN
    CREATE ROLE lrail_worker LOGIN PASSWORD 'local-only-not-a-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lrail_auth') THEN
    CREATE ROLE lrail_auth LOGIN PASSWORD 'local-only-not-a-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$$;

GRANT CONNECT ON DATABASE lrail_control_development TO lrail_web, lrail_worker, lrail_auth;
