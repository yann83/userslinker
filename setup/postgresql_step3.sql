-- ----------------------------------------------------------------------------
-- STEP 3 — Connect to the new database, then create the application schema
-- ----------------------------------------------------------------------------
-- \c is a psql meta-command.  In pgAdmin, run the statements BELOW this line
-- in a *new* Query Tool window connected to 'bd_userslinker'.
-- ----------------------------------------------------------------------------
-- \c bd_userslinker
 
 
-- Create a dedicated schema so application tables are isolated from the
-- public schema (PostgreSQL 15+ revokes CREATE on public by default).
CREATE SCHEMA IF NOT EXISTS app
    AUTHORIZATION userslinker_app;
 
COMMENT ON SCHEMA app
    IS 'Main application schema for UsersLinker tables';
 
 
-- ----------------------------------------------------------------------------
-- STEP 4 — Grant the minimum required privileges
-- ----------------------------------------------------------------------------
 
-- Allow the app role to open connections to the database
GRANT CONNECT ON DATABASE bd_userslinker TO userslinker_app;
 
-- Allow the app role to use and create objects in the 'app' schema
GRANT USAGE,  CREATE ON SCHEMA app TO userslinker_app;
 
-- Future tables created in 'app' will automatically be accessible
ALTER DEFAULT PRIVILEGES
    FOR ROLE userslinker_app
    IN SCHEMA app
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO userslinker_app;
 
ALTER DEFAULT PRIVILEGES
    FOR ROLE userslinker_app
    IN SCHEMA app
    GRANT USAGE, SELECT ON SEQUENCES TO userslinker_app;
 
 
-- ----------------------------------------------------------------------------
-- DONE
-- You can now run:  python db_setup.py
-- db_setup.py will connect as userslinker_app and create all tables inside
-- the 'app' schema of bd_userslinker.
-- ----------------------------------------------------------------------------
 