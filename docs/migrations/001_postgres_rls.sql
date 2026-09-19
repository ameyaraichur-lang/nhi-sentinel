-- NHI Sentinel — PostgreSQL tenant isolation migration (SC01/SC02, EX08, S11)
-- Target: PostgreSQL 15+. Apply with the application role NON-superuser and NOT the table
-- owner so FORCE ROW LEVEL SECURITY binds every query (ADR-0004).
--
--   create role nhi_app login password '<secret>';        -- application role (NO bypassrls)
--   create role nhi_owner;                                -- migration/DDL owner
--   psql -v ON_ERROR_STOP=1 -U nhi_owner -f 001_postgres_rls.sql
--
-- SQLite dev deployments rely on the repository-layer tenant scoping + AT01 negative tests;
-- this migration is REQUIRED before any customer pilot (blueprint Start Here: P0 gates).

BEGIN;

-- 1) Tables are created by SQLAlchemy metadata.create_all against the nhi_owner role.
--    Grant least-privilege DML to the application role.
GRANT USAGE ON SCHEMA public TO nhi_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nhi_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT
    SELECT, INSERT, UPDATE, DELETE ON TABLES TO nhi_app;

-- 2) Enable + force RLS on every tenant-scoped table (all tables carry tenant_id per SC01).
DO $$
DECLARE t text;
BEGIN
    FOR t IN
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
          AND EXISTS (SELECT 1 FROM information_schema.columns c
                      WHERE c.table_schema = 'public' AND c.table_name = tablename
                        AND c.column_name = 'tenant_id')
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        $f$, t);
    END LOOP;
END $$;

-- 3) EX08 tenant-composite indexes (SQLAlchemy creates the unique constraints; these add
--    the lookup indexes the query plans rely on at the D04 scale envelope).
CREATE INDEX IF NOT EXISTS ix_findings_tenant_sev_status
    ON findings (tenant_id, severity, workflow_status, updated_at, finding_id);
CREATE INDEX IF NOT EXISTS ix_tasks_tenant_run_node
    ON tasks (tenant_id, run_id, node, partition);
CREATE INDEX IF NOT EXISTS ix_events_tenant_run_seq
    ON events (tenant_id, run_id, sequence);
CREATE INDEX IF NOT EXISTS ix_identities_tenant_canonical
    ON identities (tenant_id, provider, authority, native_id);

-- 4) UTC discipline: all timestamptz columns are stored naive-UTC by the app layer
--    (core/db.utcnow); a CHECK pass guards accidental NULLs on mandatory timestamps.
ALTER TABLE audit_log ALTER COLUMN created_at SET NOT NULL;

COMMIT;

-- 5) Application sessions MUST set the tenant context per transaction:
--
--    SET app.tenant_id = '<tenant-uuid>';
--
--    (SQLAlchemy: event.listens_for(engine, 'begin') →
--       dbapi_conn.cursor().execute("SELECT set_config('app.tenant_id', %s, true)", (tid,)))
--
--    current_setting(..., true) returns NULL when unset → policy denies all rows
--    (fail closed). AT01 cross-tenant suite must run against Postgres in CI as well.
