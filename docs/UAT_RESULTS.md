# UAT results — full-module pass

Executed: 2026-09-19 against the final slice build (fresh seed + headless run + serve on
port 8650). Method per docs/UAT_PLAN.md; browser-driven interaction (DOM-dispatched where
the in-app browser's synthesized input pipeline was unavailable — same views, handlers and
fetch pipeline), API cross-checks via fetch/curl, pytest as regression backstop.

## Summary

| Metric | Result |
|---|---|
| Cases executed | 82 |
| Passed (final iteration) | **82 (100%)** |
| Passed (first run) | 80/82 (97.6%) |
| Genuine product bugs found | 2 (both fixed + retested) |
| Test-harness artifacts dismissed | 6 |
| pytest suite at close | 76/76 green (two consecutive full runs) |

**Goal ≥95%: met (100% final pass; 97.6% first-run).**

## Results by group

| Group | Cases | Result |
|---|---|---|
| UAT-01 Login & session (L1–L8) | 8 | 8 PASS |
| UAT-02 Overview (O1–O5) | 5 | 5 PASS |
| UAT-03 Runs list & workspace (R1–R10 + sub-steps) | 12 | 12 PASS (R9 after BUG-2 fix) |
| UAT-04 Findings & drawer (F1–F8) | 8 | 8 PASS |
| UAT-05 Exceptions queue (E1–E6) | 6 | 6 PASS (E5 deny verified via API; same dialog pattern proven in E3) |
| UAT-06 Approvals (A1–A6) | 6 | 6 PASS |
| UAT-07 Reports & exports (P1–P8) | 8 | 8 PASS (P5 after BUG-4 hardening) |
| UAT-08 Identities (I1–I4) | 4 | 4 PASS |
| UAT-09 Agents (G1–G4) | 4 | 4 PASS |
| UAT-10 Connectors (C1–C3) | 3 | 3 PASS (role-matrix behavior confirmed: preflight is operator-only) |
| UAT-11 Audit (D1–D3) | 3 | 3 PASS |
| UAT-12 Settings (S1–S5) | 5 | 5 PASS |
| UAT-13 Assistant (H1–H5) | 5 | 5 PASS |
| UAT-14 Cross-cutting (X1–X5) | 5 | 5 PASS |

## Bugs found, fixed, retested

| ID | Severity | Symptom | Root cause | Fix | Retest |
|---|---|---|---|---|---|
| BUG-2 | **High** (P0 safety control) | Emergency stop button always failed: `POST /v1/runs/{id}/stop` returned 400 VALIDATION | Stop route reused `RunCommand` (requires `command` field) instead of the reason-only `RunStop` model | Route body model changed to `RunStop` | R9 → run Cancels, UI reflects, kill flag audit trail correct |
| BUG-4 | Medium | After an interrupted login (or any transient failure between cookie set and client-state update), all mutations fail with CSRF_INVALID until a page reload | `api()` had no recovery for stale in-page CSRF state | Client self-heals: on 403 CSRF_INVALID it re-probes `/v1/me`, refreshes the token, retries once | P5 → real REAUTH_FAILED surfaced; P4 release works |
| (pre-existing, found in this round) | High | DAG fan-in gating never executed — nodes dispatched on insertion-order luck | `graph.PARENTS` built with a `setdefault` misuse (empty map) | 1-line fix in worker/graph.py; all 66 pre-existing tests + golden outcomes unchanged | AT11 now exercisable and passing |
| (pre-existing, found in this round) | High | `pip install .` / Docker build failed outright | setuptools flat-layout auto-discovery aborted on multiple top-level dirs | pyproject `[tool.setuptools.packages.find]` pinned to `nhi_sentinel*` | wheel build verified |

## Dismissed candidates (not product bugs)

- "Failed login shows no error" — automation artifact: the submit button's accessible name
  changes to "Signing in…" mid-request; direct DOM flow shows `[INVALID_CREDENTIALS]`
  rendered correctly (L3).
- Approvals dialog "does nothing" — the dialog correctly STAYS OPEN after a failed submit;
  the driver must close it before re-acting. Controlled retest records approvals fine.
- Facet/export/kill-flag buttons "missing" for viewer/admin — capability-gated UI per SC04
  (preflight=operator, export=analyst+, kill flag=admin); server is authoritative.
- Theme toggle "not working" — reads `data-theme` attribute, not class names (test error).

## Notes

- The exceptions dialog stays open after a successful submit until the queue refreshes —
  minor UX nit, logged as a polish item (not a failure; data + status correct).
- Real offboarding was exercised in pytest (AT42) only; the UAT pass verified the
  confirmation-mismatch guard so the live demo tenant stays usable.
