-- ----------------------------------------------------------------------------
-- STEP 2 — Create the database
-- ----------------------------------------------------------------------------
-- CREATE DATABASE cannot run inside a transaction block, so this statement
-- must be executed on its own (not wrapped in BEGIN/COMMIT).
--
-- TEMPLATE template0  : starts from the clean "empty" template so that
--                        ENCODING and LC_* can be set freely.
-- ENCODING 'UTF8'     : required for accented characters (French content).
-- LC_COLLATE / LC_CTYPE: 'C' gives byte-order collation — portable across
--                        all Windows/Linux locales and avoids collation
--                        mismatch errors when restoring backups.
-- ----------------------------------------------------------------------------
-- NOTE: If the database already exists, comment out this block or it will
--       raise an error.  You can also add "IF NOT EXISTS" (PostgreSQL 9.3+).
-- ----------------------------------------------------------------------------
CREATE DATABASE bd_userslinker
    OWNER     userslinker_app
    ENCODING  'UTF8'
    LC_COLLATE 'C'
    LC_CTYPE   'C'
    TEMPLATE  template0;
 
