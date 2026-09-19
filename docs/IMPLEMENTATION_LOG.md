# Implementation log — slice 0.1 (BG15 per-iteration report)

Date: 2026-09-18 · Blueprint: `NHI_Sentinel_Revised_Blueprint_v2.xlsx` (v2.0) ·
Method: core spine built first, then a 4-agent parallel swarm (fixtures, checks, frontend,
tests) against frozen contracts, followed by an integration pass.

## Implemented requirement IDs (headline)

| Family | Coverage in this slice |
|---|---|
| BG01–BG17 (build guide) | BG01 requirement index (`docs/blueprint/requirements.json`, 475 IDs); BG03 repo layout (adapted, see ADRs); BG04 first vertical slice **working end-to-end**; BG12 synthetic labeled fixtures; BG15 this log |
| DC01–DC22 (data contracts) | schema + wire models in `contracts/` & `core/db.py`; EX01/EX02 state machines; EX05 approval digests; EX07 error envelope; EX08 indexes/constraints |
| AR01–AR16 (architecture) | portal/BFF-less thin client (ADR-0003), control API, durable engine (ADR-0001), policy layer (ADR-0002), credential-ref-only handling, evidence signing, finding service, SSE event plane |
| SC01–SC25 (security controls) | demo-relevant subset enforced & tested: tenant scoping (SC01/02 via repo + AT01), sessions/CSRF (SC03/20), RBAC matrix (SC04), separation of duty (SC05), secret minimization/redaction (SC11), injection-safe rendering (SC09/VD13), append-only audit chain (SC15), kill flag (SC18), export safety pending |
| CN01–CN05 (connectors) | import adapters + framework (ADR-0005); CN06–CN16 deferred, visibly uncertified (AT15) |
| Check Catalog | 21 pilot checks registered (CLD-002/007/008/009, KEY-001/003/007, OAU-001/004, CICD-006/007, AGI-002/004/005/006/008/011/014/015, INV-001/002); golden pass/fail/unknown/NA fixtures for every enabled check (AT27) |
| PS01–PS15 (policy & scoring) | deterministic severity (PS02–PS05, version+hash persisted), score with visible completeness and honest unavailability (PS06–PS11), control mapping with unmapped disclosure (PS13) |
| Orchestration N00–N17 | full DAG with fan-out partitions, skip propagation, G02 human gate, S00 pending |
| API01–API40 (subset) | ~35 routes implemented (auth, runs+SSE, findings, approvals, reports, agents, audit, scores, settings); exports/tickets/CI-gate/webhooks deferred |
| UI01–UI16 / UX / VD | 13 SPA views incl. Mission Control, Swarm Run board with live SSE, approvals with re-auth, findings, agents, audit verify; tokens per VD02/03; XSS-safe rendering |
| Acceptance tests | 49 pytest tests green mapping AT01/03/05/07/08/10/13/15/16/17/18/25/27 + policy/score unit coverage |

Run `python scripts/gen_traceability.py` → `docs/TRACEABILITY.md` for the per-ID matrix
(186/475 IDs referenced by code/tests; the remainder are deferred features documented above
and in the ADRs, not silent omissions).

## Run commands actually executed (evidence)

- `python run_demo.py reseed && python run_demo.py headless`
  → run reaches `waiting_approval`; 4 snapshots (aws_iam complete/12, entra **partial**/3
  via a recorded 403 page error, github complete/2, agent_registry complete/4);
  **108 check results, 41 findings**; severity decisions persisted with
  `sev-baseline-1.0.0`; report drafted with **47 claims, 0 unsupported**, parked at G02.
- Release flow through the browser UI as `reviewer@demo.nhi` (author ≠ reviewer,
  re-authentication, digest-bound): report → `released`, signature bound to revision;
  engine then finalizes the run as **partial** (honest, because entra is partial).
- `python -m pytest -q` → **49 passed**.
- `python scripts/gen_traceability.py` → regenerated matrix.

## Defects found and fixed during integration

1. Nested `session_scope` under `BEGIN IMMEDIATE` self-deadlocked N04/N05/N06 and the
   claim-feedback route → ambient-session threading for `load_snapshot_view`,
   `assemble_report`, and every in-transaction `append_audit` (audit now commits in the
   same transaction as the mutation it describes — closer to OP05).
2. Engine finalize referenced an unimported enum → runs failed after gate release; fixed
   and re-verified through the UI (run now correctly ends `partial`).
3. Golden mismatch: AGI-014 expected `pass` for agent-research while the fixture lacked the
   `net:egress` capability → fixture aligned to the scenario matrix.
4. `RunCreate` required non-empty connector/check lists → now optional subsets validated
   against the approved scope (no hidden scope expansion, OP17).
5. Audit chain could fork under concurrent appends: the walk ordered by wall-clock
   `created_at` (assigned pre-commit in different threads) while entries chained from a
   head read on a stale transaction snapshot. Fix: chain head read through a fresh
   autocommit connection + chain walked in **insertion order (rowid)**; stability proven
   with 18 consecutive green full-suite runs (previously ~1 failure per 2–3 runs).
6. Proposal revocation was discarded by the HTTPException rollback in the execute route →
   revocation now commits before the 422 (AT05 evidence persists).

## Slice 0.2 — governance, continuous + readiness surfaces (2026-09-19)

Second iteration, same method (backend spine by the lead engineer, portal surfaces by a
UI agent, contract frozen first):

- **AT24 readiness gate**: run creation now blocks until every scoped connector passed
  read-only preflight (`PREFLIGHT_REQUIRED` names the offenders); preflight records state.
- **AT30 remediation/exception lifecycle**: risk exceptions (DC20) with independent
  approval (SC05 no-self-approval at role AND service layer), finding linkage
  (workflow_status `accepted`), expiry → `reopened` via the maintenance loop.
- **AT29 CI gate (API25) + S00 scheduler**: scoped machine-token auth; pass/fail/unknown
  verdicts (unknown = fail-closed default, tolerable via `protected:false`); subscription
  cadence runs with drift/no-change signature events (OP18).
- **AT32 exports (API23)**: released reports only; CSV/JSON with SC21 formula-char
  sanitization; sha256, reconciled finding counts, audited, Content-Disposition download.
- **AT42 offboarding (OP20) + OP08 retention**: irreversible tenant offboarding (revokes
  sessions/connectors/subscriptions, purges evidence content behind a tombstone ledger,
  audit chain survives); retention purge honors legal hold.
- **SC20 security headers**: CSP (strict script-src), XFO DENY, nosniff, HSTS on every
  response; EX07 envelope now also covers route-not-found 404s.
- **API24 assistant (UX12/VD10)**: deterministic citation-backed answers (findings, score,
  coverage), injection-resistant (instructions in questions are data), AI-labeled,
  `ai_generated:false`, model recorded; viewers may query, nobody can make it act.
- **AT12 severity policy pinning**: runs pin the severity bundle; unknown bundle versions
  fail closed to `undetermined` (fail-closed demonstrated by test).
- **Portal**: exceptions queue + decision dialogs, findings risk-acceptance flow, report
  export card, Ask Sentinel drawer, subscriptions/offboarding governance section
  (jsdom smoke 43/43).
- **Postgres migration**: `docs/migrations/001_postgres_rls.sql` (FORCE RLS keyed on
  `app.tenant_id`, least-privilege role, EX08 indexes) — required before customer pilot.

Suite: 66 tests green; two consecutive clean full runs post-merge. One cross-test
contamination fixed: the AT17 deletion-tamper test now corrupts a throwaway tenant chain
instead of the shared one.

## Slice 0.3 — leftovers closed + full code review + UAT (2026-09-19)

- **Leftover features built**: PS15 retest-closure evaluation (resolved vs still-open with
  events), API26 inbound webhooks (HMAC + timestamp skew + dedup), API39 ticket drafts
  (destination allowlist + idempotency), SC22/AT25 rate limiting (sliding window, 429 +
  Retry-After, /health and /portal exempt), SC23/AT33 support elevation (time-bound grants,
  audited access), API33 signed audit export + verify, AT20 readiness SLA clock
  (readiness_accepted_at + baseline latency disclosure), AT11/AT19 tests.
- **Infra**: GitHub Actions CI (+ postgres-rls job stub), Dockerfile + docker-compose.dev.yml,
  stdlib SBOM generator (docs/sbom.json, 7 components), lint report (docs/LINT_REPORT.md),
  pyproject packaging fix (pip install / Docker were broken).
- **Two real product bugs found via UAT and fixed**: emergency-stop endpoint rejected its
  own clients (body model mismatch); stale client CSRF state required a page reload
  (client now self-heals). Also fixed this round: pre-existing graph PARENTS fan-in bug.
- **UAT**: 82 cases across all 12 routes and every control — 82/82 pass on the final
  iteration (first run 80/82). Full report: docs/UAT_RESULTS.md.
- Suite at close: **76/76 green**, two consecutive clean full runs.

## Remaining blockers / next smallest slice (BG15 honesty)

- **S00 continuous scheduler**, CI gate (API25), exports/tickets/webhooks — deferred.
- **Postgres + RLS**, OPA bundles, React/TS portal, live SDK connectors — ADRs 0001–0005
  document the seams; each requires the pilot certification gates from the blueprint
  (AT29–AT36, AT39–AT41).
- Active proof stays disabled by design (D06); proposals/approvals demonstrably do not
  confer execution capability (tested).
