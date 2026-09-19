# ADR-0004: SQLite for the dev slice; Postgres RLS remains the pilot boundary

**Status:** accepted for slice 0.1  ·  **Blueprint refs:** SC01/SC02, EX08, S11, AT01

The schema (all EX08 indexes/constraints) is SQLAlchemy and Postgres-ready. The slice runs
on SQLite for one-command dev runs. Tenant isolation does not rely on the DB engine here:
every repository access is tenant-bound (`core/repo.py: scoped_get` + tenant_id filters),
object access returns **404 without metadata leakage** for cross-tenant ids, SSE is
tenant-filtered, and the negative tests (AT01) enforce it.

**Why:** RLS (SC01: `FORCE ROW LEVEL SECURITY` + non-owner application role) requires a
real Postgres with roles; wiring that into the dev loop would compromise the "clone and
run" property without adding isolation the app layer must enforce anyway (defense in
depth at pilot time).

**Consequences:** before any customer pilot: enable RLS policies mirroring the tenant
predicates, run migration tests that verify query plans use tenant indexes (EX08), and
keep the cross-tenant negative suite (already written) in CI against Postgres too.

## Update (slice 0.2): migration shipped

`docs/migrations/001_postgres_rls.sql` now contains the complete pilot-gate migration:
FORCE RLS policies keyed on `app.tenant_id` (fail-closed when unset), least-privilege
application role, EX08 lookup indexes, and the session-context contract. The suite still
runs on SQLite; `NHI_DB_URL` selects Postgres, and the AT01 cross-tenant negative suite
must be executed against Postgres in CI before any customer pilot.
