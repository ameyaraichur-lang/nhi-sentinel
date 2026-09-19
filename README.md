# NHI Sentinel — vertical slice 0.1

Evidence-led **non-human identity (NHI)** and **AI-agent identity** assessment, implementing
the *NHI Sentinel Revised Blueprint v2* workbook (included at
`docs/blueprint/NHI_Sentinel_Revised_Blueprint_v2.xlsx`, with a machine-readable requirement
index at `docs/blueprint/requirements.json` — 475 requirement IDs extracted).

> **Everything in the demo corpus is synthetic.** Fixtures are labeled
> `(NOT customer data)`, the UI carries a persistent synthetic-data banner, and active
> proof is disabled by design (Decision D06). This is a development slice, not a
> production release: acceptance tests marked P0 in the blueprint are the gate for a
> customer pilot and several require infrastructure this slice intentionally does not
> pretend to have (see `docs/adr/`, Limitations).

## Quick start

```bash
pip install -e .            # or: pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings
python run_demo.py reseed   # fresh synthetic demo data
python run_demo.py serve    # portal: http://127.0.0.1:8650/portal  docs: /api-docs
```

One-time headless check (no server): `python run_demo.py headless` — drives a full passive
run to the report-release gate and prints findings.

**Demo logins** (password `demo-synthetic-only`): `analyst@demo.nhi`, `reviewer@demo.nhi`,
`approver1@demo.nhi`, `approver2@demo.nhi`, `operator@demo.nhi`, `viewer@demo.nhi`,
`auditor@demo.nhi`, `admin@demo.nhi`, plus `intruder@contoso.nhi` (tenant-B analyst used
by the isolation tests).

## The end-to-end story this slice demonstrates

1. **Approved scope** — engagement with immutable scope version (ROE ref, sources,
   certified checks only). Uncertified check ids are excluded *visibly* (AT15).
2. **Collection swarm** — the run DAG (N00→N17) fans out per-source collection partitions;
   import connectors validate, redact (SC11), and persist snapshots with signed manifests
   (DC15). Partial collection (a consent gap on Entra) stays partial — no deletion
   inference (G25/AT08).
3. **Passive checks** — 21 pilot checks across AWS / Entra / GitHub / agent-registry
   (identity governance is the differentiator: unregistered agents, delegation
   amplification, MCP audience gaps, missing kill switch…). Unknown and error are distinct
   from pass; unknowns require reasons (DC11).
4. **Evidence validation** — every fail must cite resolvable, signature-valid artifacts or
   it is downgraded with an audit trail; drafts never reach findings (G05/AT10).
5. **Deterministic severity** — policy rules (PS02–PS05) with persisted decisions
   (version + input hash). No LLM severity; missing essential inputs → `undetermined`.
6. **Posture score with honest completeness** — per-dimension pass rates (PS06–PS11);
   the aggregate stays **unavailable** while detection scenarios are unexercised and one
   source is partial. Never invents a score (G01/G03/R03).
7. **Two-person report release** — deterministic report with a claim→evidence registry;
   grounding validation blocks release on unsupported claims (AT13); an independent
   reviewer (never the author) signs the exact revision (SC05); approval proposals
   demonstrate digest-bound, expiring, re-authenticated two-person approvals whose
   approval still cannot enable active execution in pilot (DC16/DC17, D06, AT05).
8. **Audit** — append-only hash-chained audit log with a verification endpoint (SC15/AT17).

## Repository map (adapted from BG03)

```
nhi_sentinel/
  contracts/    DC01–DC22 models + run/task state machines (EX01/EX02)
  core/         db schema (EX08 indexes), tenant-scoped repo, auth/roles, signing, audit, SSE events
  connectors/   import-connector framework + AWS/Entra/GitHub/agent-registry adapters (CN01–CN05)
  checks/       check contract + 21 registered pilot checks (50 original catalog ids honored)
  policies/     deterministic severity (PS01–PS05) + score (PS06–PS11)
  worker/       durable run engine + DAG nodes (N00–N17) + mappings/runbooks
  reports/      deterministic report builder + grounding validator (DC19, AT13)
  api/          FastAPI control API (API contracts subset) + SSE + portal hosting
web/            zero-build control-room SPA (VD tokens, dark/light)
fixtures/       synthetic golden corpus (labeled NOT customer data)
tests/          pytest suite mapping blueprint acceptance-test ids
docs/adr/       deliberate deviations from the blueprint stack, with rationale
scripts/gen_traceability.py   regenerates docs/TRACEABILITY.md (IDs → code/tests)
```

## Tests

```bash
python -m pytest -q
```

The suite maps to blueprint acceptance tests (AT01 tenant isolation, AT05 approvals,
AT07 kill/containment, AT10 workflow topology, AT13 report grounding, AT16 false-positive
boundaries, AT17 custody integrity, AT18 score math, AT25 stream resilience, AT27 golden
check coverage…). `docs/TRACEABILITY.md` maps requirement IDs → code and tests.

## Honest status (BG15: no "finished" claims from scaffolding)

**Working end-to-end:** seed → scope → collection → checks → evidence → findings →
severity → score → report draft → grounding → independent release → publish, with live
SSE run workspace, approvals, audit, and the security behaviors listed above.

**Deliberately out of scope for this slice** (each documented in `docs/adr/`): live vendor
SDK collectors (import adapters certified against the import schema instead), Postgres RLS
(dev runs SQLite; tenant scoping enforced app-side and negative-tested), OPA server
(policy module with version+hash persisted), React portal (zero-build SPA honoring the
same UX contracts), active-proof execution (disabled by D06 — approvals demonstrably do
not confer capability).

## Operations

**CI.** GitHub Actions workflow at `.github/workflows/ci.yml`, two jobs: `test` (Python
3.12, `pip install -e ".[dev]"`, `python -m pytest -q`) and `postgres-rls` — a
`continue-on-error` stub that runs the AT01 tenant-isolation suite against a Postgres 15
service with `NHI_DB_URL` set; it activates when the SQLAlchemy layer gets Postgres
testing support (ADR-0004). Locally, the equivalent of job 1 is just:

```bash
pip install -e ".[dev]"
python -m pytest -q
```

**Containers.** `docker-compose.dev.yml` builds the `Dockerfile` (python:3.12-slim,
`pip install .`, uvicorn app factory `nhi_sentinel.api.app:create_app` on `0.0.0.0:8650`),
bind-mounts the repo over `/app` and persists synthetic demo data in the `nhi_data`
volume at `NHI_DATA_DIR=/data`:

```bash
docker compose -f docker-compose.dev.yml up --build   # portal on http://localhost:8650/portal
docker compose -f docker-compose.dev.yml down         # add -v to also drop the demo data volume
```

**SBOM (AT22-lite).** Regenerate the dependency inventory (stdlib-only script; output is
committed):

```bash
python scripts/gen_sbom.py    # rewrites docs/sbom.json, prints component count
```

**UAT.** The user-acceptance procedure lives at `docs/UAT_PLAN.md` (the UAT procedure
home; create it there if it does not exist yet). It drives the acceptance-test IDs
mapped in `docs/TRACEABILITY.md` against a fresh `python run_demo.py reseed` instance.
