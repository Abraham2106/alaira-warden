#!/bin/sh
set -eu

# psql quotes the password as a SQL literal; do not interpolate it into shell SQL.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$WARDEN_DB_APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE warden_app LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_app') \gexec
GRANT CONNECT ON DATABASE warden TO warden_app;
GRANT USAGE ON SCHEMA public TO warden_app;
SQL

