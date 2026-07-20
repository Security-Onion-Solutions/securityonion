#!/bin/bash
set -e

# Create or update application user for SOC platform access
# This script runs on first database initialization via docker-entrypoint-initdb.d
# The password is properly escaped to handle special characters
if [ -z "${SO_POSTGRES_PASS:-}" ] && [ -n "${SO_POSTGRES_PASS_FILE:-}" ] && [ -r "$SO_POSTGRES_PASS_FILE" ]; then
    SO_POSTGRES_PASS="$(< "$SO_POSTGRES_PASS_FILE")"
fi
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Shield the plaintext password below from postgres.log if this DDL errors:
    -- log_min_error_statement defaults to 'error', which would append a STATEMENT line
    -- containing the full CREATE/ALTER ROLE ... PASSWORD text. panic suppresses that.
    SET log_min_error_statement = panic;
    -- Race-safe upsert: try CREATE, and if the role was created concurrently
    -- (another session re-entering init) fall back to ALTER. Catching the
    -- exception -- rather than an IF NOT EXISTS check -- avoids a TOCTOU window
    -- where CREATE ROLE would abort the whole script with a duplicate-key error
    -- and skip the grants below. Both SQLSTATEs are covered: duplicate_object
    -- (role already exists) and unique_violation (racy pg_authid index insert).
    DO \$\$
    BEGIN
        BEGIN
            EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', '${SO_POSTGRES_USER}', '${SO_POSTGRES_PASS}');
        EXCEPTION WHEN duplicate_object OR unique_violation THEN
            EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', '${SO_POSTGRES_USER}', '${SO_POSTGRES_PASS}');
        END;
    END
    \$\$;
    GRANT ALL ON SCHEMA public TO "$SO_POSTGRES_USER";
    GRANT ALL PRIVILEGES ON DATABASE "$POSTGRES_DB" TO "$SO_POSTGRES_USER";
    -- Lock the SOC database down at the connect layer; PUBLIC gets CONNECT
    -- by default, which would let per-minion telegraf roles open sessions
    -- here. They have no schema/table grants inside so reads fail, but
    -- revoking CONNECT closes the soft edge entirely.
    REVOKE CONNECT ON DATABASE "$POSTGRES_DB" FROM PUBLIC;
    GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO "$SO_POSTGRES_USER";
EOSQL

# Bootstrap the Telegraf metrics database. Per-minion roles + schemas are
# reconciled on every state.apply by postgres/telegraf_users.sls; this block
# only ensures the shared database exists on first initialization.
if ! psql -U "$POSTGRES_USER" -tAc "SELECT 1 FROM pg_database WHERE datname='so_telegraf'" | grep -q 1; then
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -c "CREATE DATABASE so_telegraf"
fi