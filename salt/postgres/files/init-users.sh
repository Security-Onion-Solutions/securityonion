#!/bin/bash
set -e

# Create or update application user for SOC platform access
# This script runs on first database initialization via docker-entrypoint-initdb.d
# The password is properly escaped to handle special characters
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${SO_POSTGRES_USER}') THEN
            EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', '${SO_POSTGRES_USER}', '${SO_POSTGRES_PASS}');
        ELSE
            EXECUTE format('ALTER ROLE %I WITH PASSWORD %L', '${SO_POSTGRES_USER}', '${SO_POSTGRES_PASS}');
        END IF;
    END
    \$\$;
    GRANT ALL PRIVILEGES ON DATABASE "$POSTGRES_DB" TO "$SO_POSTGRES_USER";
EOSQL
