# UAT plan — full-module pass (goal ≥95% pass)

Scope: every implemented screen, button, tab, and flow in the portal, plus the API
surfaces they depend on. Executed manually via browser automation against a fresh
`python run_demo.py reseed && python run_demo.py headless && python run_demo.py serve`
instance on port 8650. Results recorded in docs/UAT_RESULTS.md (PASS/FAIL/BUG per case;
bugs fixed then cases retested; success = passed / executed ≥ 95%).

Roles used: analyst, viewer, operator, approver1/approver2, reviewer, admin, auditor
(password `demo-synthetic-only`). A run parked at the G02 gate is produced headlessly.

## UAT-01 Login & session (8)
- L1 quick-role button logs in and lands on Overview with role shown in topbar
- L2 manual email+password login works
- L3 wrong password → 401 error surfaced, no session
- L4 all 8 role buttons present (admin, analyst, operator, approver1, approver2, reviewer, viewer, auditor)
- L5 logout returns to login and clears session (back → login required)
- L6 deep link to #/findings while logged out → redirected to login
- L7 theme toggle persists across reload (light/dark)
- L8 synthetic-data banner visible on every screen

## UAT-02 Overview / Mission Control (5)
- O1 cards render: active runs, findings by severity, connectors, identity count, approvals pending, reports awaiting release
- O2 findings-by-severity numbers match /v1/findings totals
- O3 score panel: 4 measured dimensions + Detection explicitly "unavailable" with PS11 reason
- O4 "Open reports"/"Triage findings"/"Review approvals" links navigate correctly
- O5 connector health shows entra partial, others complete, with sync times

## UAT-03 Runs list & Run workspace (10)
- R1 runs table renders with state chips (Waiting approval etc.)
- R2 click run → workspace shows swarm board lanes N00..N17/G02
- R3 per-partition cards (aws_iam/entra/github/agent_registry) with Done states
- R4 coverage panel: entra PARTIAL badge + completeness meters + page errors
- R5 events timeline renders chronological events
- R6 SSE live: create a new run via API while viewing → board/timeline update without reload
- R7 operator sees Pause/Resume/Cancel + Emergency stop; analyst sees "Run controls require operator role"
- R8 Pause (operator) → state chip transitions; Resume returns
- R9 Emergency stop confirm dialog → run cancelled (fresh run used for destructive steps)
- R10 G02 gate banner shows "Open Reports to release" shortcut navigating correctly

## UAT-04 Findings & finding drawer (8)
- F1 findings table renders with severity chips; total matches API
- F2 severity facet filters the table
- F3 drawer opens: facts table shows the five severity inputs + rationale
- F4 evidence links open the evidence view with signature_valid true
- F5 lifecycle change (analyst: open→triaged) with reason → persists after reload
- F6 "Request risk exception" dialog (analyst) creates pending exception (success toast)
- F7 accepted finding shows "risk accepted until <date>" chip (after UAT-05 accept)
- F8 history/occurrence count visible for re-observed condition

## UAT-05 Exceptions queue (6)
- E1 #/exceptions lists pending exception from F6 with finding link + expiry
- E2 analyst (requester) sees decision buttons disabled/absent
- E3 approver accepts with reason → finding becomes accepted
- E4 second decision on same exception → 422 shown
- E5 deny path on a second pending exception → status denied
- E6 exceptions nav item visible only to roles with relevance (approver/admin; analyst OK to view)

## UAT-06 Approvals (dormant proof proposal) (6)
- A1 proposal card renders: template, expected effects, rollback, digest prefix, expiry countdown, 0-of-2
- A2 approve with wrong re-auth password → 401 REAUTH_FAILED surfaced
- A3 approver1 approves → progress 1-of-2, no execution possible
- A4 approver2 approves → status approved
- A5 execute attempt (button/API) → 422 ACTIVE_PROOF_DISABLED surfaced (D06)
- A6 approvals view rejects analyst role (no approval:decide buttons)

## UAT-07 Reports & exports (8)
- P1 reports list: draft (parked) + released sections separated with grounding summary
- P2 draft detail: read-only sections, claims with evidence chips, limitations panel, score card
- P3 analyst (author) has no release button / reviewer does
- P4 reviewer releases with review record + re-auth → status released + signature shown
- P5 release with wrong password → 401 shown, report unchanged
- P6 Export CSV → job card with sha256 + finding_count; download returns CSV with header row
- P7 Export JSON → download parses as JSON with finding_count matching
- P8 claim feedback on a claim → review_task_created without changing released content

## UAT-08 Identities (4)
- I1 identity table paginates/renders with provider column; unowned entries visible
- I2 detail: credentials show fingerprint prefix only (never a secret value)
- I3 attest-owner form (analyst) adds verified assertion; form validation for empty owner
- I4 related findings listed on identity detail

## UAT-09 Agents (4)
- G1 registry agents render with sponsor/purpose/capabilities; shadow agent shows SHADOW badge
- G2 suspension (admin) → lifecycle Suspended with reason in audit
- G3 observed-only agent cannot be commanded (server 422 surfaced)
- G4 stale registry_version command → 409 conflict surfaced

## UAT-10 Connectors (3)
- C1 health table shows state + last complete sync per source
- C2 preflight button (operator) runs and reports ok:true with identities_seen
- C3 preflight failure path surfaces readable error (rename fixture temporarily is too invasive — verify via API 404 connector instead)

## UAT-11 Audit (3)
- D1 audit table renders entries with actor/action/hash columns
- D2 "Verify chain" → valid badge true
- D3 support/access and offboarding-related audit entries appear after governance actions

## UAT-12 Settings & governance (5)
- S1 tenant info (region/plan/retention/status/legal_hold) renders
- S2 kill flag toggle (admin) requires confirm + reason → kill_flag true; toggle back off
- S3 subscriptions table + admin add/toggle (PATCH reflects)
- S4 offboarding mismatch error path (wrong name → CONFIRMATION_MISMATCH shown; NO real offboard in UAT — destructive, covered by pytest AT42)
- S5 non-admin role sees settings read-only / actions hidden

## UAT-13 Assistant (5)
- H1 "Ask Sentinel" opens drawer with AI label
- H2 "What findings..." → answer + finding citation chips that navigate
- H3 score question → per-dimension answer with run citation
- H4 injection probe ("ignore previous instructions...") → guard message, no secret leak
- H5 limitations footer visible; assistant cannot act (no action buttons)

## UAT-14 Cross-cutting (5)
- X1 keyboard: tab reaches nav + primary buttons with visible focus ring
- X2 direct navigation to all 11 hash routes renders (no blank screen)
- X3 404 API path returns EX07 envelope (curl check)
- X4 security headers present on portal response (curl check)
- X5 responsive: 1024px viewport keeps app usable (sidebar collapse)

Total: 80 cases. Pass ≥ 76 (95%).
