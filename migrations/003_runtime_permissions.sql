-- Production identity/RBAC remains pending; separate the local API role from the migrator.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_app') THEN
        GRANT USAGE ON SCHEMA public TO warden_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO warden_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO warden_app;
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON schema_migrations FROM warden_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM warden_app;
    END IF;
END
$$;

