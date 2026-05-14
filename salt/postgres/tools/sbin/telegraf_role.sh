#!/bin/bash
set -e

# Provision or update a Telegraf postgres role.
# Expects ROLE_USER and ROLE_PASS environment variables.

docker exec -i so-postgres psql \
  -v ON_ERROR_STOP=1 \
  -v role_user="$ROLE_USER" \
  -v role_pass="$ROLE_PASS" \
  -U postgres -d so_telegraf <<'EOSQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :role_user) THEN
        EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', :role_user, :role_pass);
    ELSE
        EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :role_user, :role_pass);
    END IF;
END
$$;
GRANT CONNECT ON DATABASE so_telegraf TO :"role_user";
GRANT so_telegraf TO :"role_user";
EOSQL
