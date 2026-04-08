#!/bin/bash
set -e

# Create application user for SOC platform access
# This script runs on first database initialization only
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$SO_POSTGRES_USER') THEN
            CREATE ROLE "$SO_POSTGRES_USER" WITH LOGIN PASSWORD '$SO_POSTGRES_PASS';
        END IF;
    END
    \$\$;
    GRANT ALL PRIVILEGES ON DATABASE "$POSTGRES_DB" TO "$SO_POSTGRES_USER";
EOSQL
