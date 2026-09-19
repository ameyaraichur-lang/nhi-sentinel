# NHI Sentinel portal (zero-build SPA)

Vanilla JS single-page app served by the API from `/portal` (e.g. <http://127.0.0.1:8650/portal/>).
No build step, no frameworks, no CDN dependencies - works fully offline.

## Open it

```bash
python run_demo.py reseed     # fresh synthetic DB (optional)
python run_demo.py headless   # optional: drive one run to the G02 release gate
python run_demo.py serve      # portal + API on http://127.0.0.1:8650/portal
```

Sign in with any demo user (password for all: `demo-synthetic-only`):
`admin@` `analyst@` `operator@` `approver1@` `approver2@` `reviewer@` `viewer@` `auditor@demo.nhi`.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | App shell: synthetic-data banner (UX24), login root, sidebar/topbar/main, toast + dialog roots |
| `styles.css` | Design tokens (VD02/VD03 dark + light theme), components, run-board layout |
| `core.js` | Safe DOM builder (textContent-only, VD13), fetch wrapper with `{error:{code,message}}` handling (EX07), toasts, dialogs, status/severity chips, timers |
| `app.js` | Hash router, sidebar/topbar shell, login view, theme + sidebar persistence, 401 handling |
| `views/*.js` | One module per screen |

## Screens (hash routes)

- `#/overview` - mission control: connector health, active runs, findings by severity, posture score panel (measured bars + explicit "unavailable" chips), reports awaiting release, approvals pending; onboarding checklist when the tenant has no data (never implies zero risk, UX20)
- `#/runs` - mission list with distinct state chips
- `#/runs/:id` - swarm run workspace: deterministic phase-lane node board (CSS grid), live SSE timeline with Last-Event-ID resume + stale banner + duplicate/out-of-order suppression (UX16), per-source coverage with PARTIAL badges and page errors, pause/resume/cancel (If-Match revision) and emergency stop with confirm dialog (no optimistic stopped label, UX08)
- `#/approvals` - proposal inbox: expected effects, rollback, action digest, expiry countdown, "x of 2 approvals", approve/deny with reason **and** password re-auth; server codes (SELF_APPROVAL, STALE_APPROVAL, DUPLICATE_ACTOR, PROPOSAL_EXPIRED) surface verbatim
- `#/identities`, `#/identities/:id` - paginated inventory with provider filter and unowned badges; detail with credential metadata (fingerprint prefix only), ownership assertions + attest form, related findings
- `#/findings` - severity/assurance/lifecycle facets (client-side), detail drawer with facts table, severity rationale, evidence links, lifecycle actions (If-Match + reason) and "Request retest"
- `#/agents` - registry vs observed with SHADOW badges, capability chips, suspend/retire/activate commands (registry_version bound)
- `#/connectors` - health table + read-only preflight (ok/error + page errors)
- `#/reports`, `#/reports/:id` - grounding summary, read-only claim sections with evidence links, limitations, score card, reviewer release flow (re-auth, blocked while unsupported claims exist, author cannot self-release) and per-claim feedback
- `#/audit` - hash-chained audit table + "Verify chain" (valid/broken badge)
- `#/settings` - tenant facts (read-only region/plan) + emergency kill flag toggle with confirm + required reason (admin)
- `#/evidence/:id` - artifact integrity metadata + escaped content preview

## Security notes

- Auth: `POST /v1/auth/login` sets an HttpOnly cookie; the CSRF token from `/v1/me` is kept in memory only and sent as `X-CSRF-Token` on mutations.
- All data renders through `el()` -> `createTextNode`; the fixture XSS canary renders inert.
- Role gating is UI-only convenience; the server remains authoritative (403s render a distinct permission-denied state).
