QL
-- init_db.sql
-- PostgreSQL initialisation script for UsersLinker.
--
-- PURPOSE:
--   Creates the dedicated application role, the database, and the schema
--   with the correct ownership, encoding and locale settings.
--
-- HOW TO RUN:
--   1. Open pgAdmin → Query Tool (connect as the 'postgres' superuser).
--   2. Paste this entire file and execute it (F5).
--   OR from the Windows command prompt:
--      psql -U postgres -f init_db.sql
--
-- IMPORTANT:
--   Change 'userslinker' below to a strong password before running.
--   This password must also be set in your .env file (PG_PASSWORD).
--
-- Location: init_db.sql (root of the project — do NOT expose via web server)
-- ============================================================================
 
 
-- ----------------------------------------------------------------------------
-- STEP 1 — Create the application role
-- ----------------------------------------------------------------------------
-- 'userslinker_app' is the dedicated PostgreSQL user for this application.
-- It can log in and create databases (CREATEDB is needed so db_setup.py
-- can verify the connection cleanly; it can be revoked after first run).
-- It is NOT a superuser — principle of least privilege.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    -- Only create the role if it does not already exist
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'userslinker_app'
    ) THEN
        CREATE ROLE userslinker_app
            LOGIN
            PASSWORD 'userslinker'   -- <-- CHANGE THIS PASSWORD
            CREATEDB;                -- Allows db_setup.py to run without superuser
 
        RAISE NOTICE 'Role userslinker_app created.';
    ELSE
        RAISE NOTICE 'Role userslinker_app already exists — skipped.';
    END IF;
END
$$;