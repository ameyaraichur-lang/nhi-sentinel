# Pilot scenario matrix (shared contract for fixtures + checks)

This matrix binds the synthetic fixture corpus (`fixtures/*_snapshot.json`) to the check
pack (`nhi_sentinel/checks/pilot.py` + `reference.py`). Every row: check, source, scenario,
expected DC11 status. The golden test runner asserts these outcomes after a full run.

Standard severity inputs (PS02) are carried in `facts`: `impact` (critical/high/moderate/low),
`exposure` (untrusted/internal/constrained), `effective_privilege` (elevated/limited),
`path_certainty` (confirmed/possible/none), `credential_state`
(exposed/enabled/unknown/not_applicable), plus `condition_signature` for dedup.

## AWS (aws_iam)

| Check | Target (native_id) | Scenario | Expected |
|---|---|---|---|
| CLD-002 | role/VendorDeploy | trusts unapproved external account 998877665544 (root), no external ID / subject binding | fail |
| CLD-002 | role/CrossAcctVendor | trusts approved 444455556666 with `sts:ExternalId` condition | pass |
| CLD-002 | role/ApprovedUnbound | trusts approved 444455556666 without binding conditions | unknown (AT16: missing context, not auto-fail) |
| CLD-007 | role/LegacyVendor | trust to account 554433221100 absent from `scope.integrations` register, no owner assertion | fail |
| CLD-007 | role/CrossAcctVendor | registered integration with owner + expiry | pass |
| CLD-008 | role/CiDeploy | OIDC federation trust with wildcard subject condition (repo unbound) | fail |
| CLD-008 | role/TerraformPlan | OIDC federation bound to exact repo+branch+audience | pass |
| CLD-009 | user/svc-etl | has only technical owner (unverified assertion) | fail |
| CLD-009 | role/VendorDeploy | verified business+technical owners | pass |
| CLD-009 | role/CiDeploy | no ownership assertions at all | fail |
| KEY-003 | user/svc-etl | single enabled access key created 2024-01-02, `rotation_policy_days: 90` | fail |
| KEY-003 | role/TerraformPlan | no static keys (federation only) | not_applicable (no static credential) |
| KEY-007 | user/svc-etl | TWO enabled access keys beyond overlap window | fail |
| KEY-007 | user/svc-fresh | one enabled key | pass |

External principals (998877665544, 444455556666, 554433221100) are modeled as identities
with `id_type: "external_principal"`, `authority` = the external account number, so trust
edges persist. Trust edges: `src` = trusting role, `dst` = trusted principal identity,
`conditions.trust_policy = {"principal_arns": [...], "conditions": {...}, "federation_oidc": {...}?}`.

## Entra (entra)

| Check | Target | Scenario | Expected |
|---|---|---|---|
| OAU-001 | sp-reporting-app | application grants Mail.ReadWrite + Files.ReadWrite.All, `consent_record.purpose` null | fail |
| OAU-001 | sp-backup-sync | Directory.Read.All with recorded purpose | pass |
| OAU-004 | sp-backup-sync | multi-tenant external app, NO owner assertion, no risk review | fail |
| OAU-004 | sp-vendor-analytics | multi-tenant but owned + reviewed (consent_record.reviewed=true, owner verified) | pass |
| CLD-009 | sp-backup-sync | no owners | fail |
| CLD-009 | sp-vendor-analytics | verified business+technical owners | pass |
| INV-002 | collection/entra | page_errors on sign-in audit (403) | fail (partial snapshot) |

`sp-reporting-app` display name includes `<script>alert(1)</script>` — XSS-safe rendering is
verified in frontend tests (VD13).

## GitHub (github)

| Check | Target | Scenario | Expected |
|---|---|---|---|
| KEY-001 | payments-api/config/legacy.ini | high-confidence AWS key pattern | fail (credential_state exposed; validity stays unknown per G23) |
| KEY-001 | docs-site/notes.md | low-confidence generic pattern | fail with `confidence: low` |
| CICD-006 | payments-api deploy.yml | contents+deployments+id-token write on `pull_request_target` | fail |
| CICD-006 | docs-site build.yml | contents read on push | pass |
| CICD-007 | payments-api deploy.yml | unpinned action refs | fail |
| CICD-007 | docs-site build.yml | digest-pinned action | pass |
| CLD-009 | deploykey:payments-api | no owner assertions | fail |
| CLD-009 | app:nw-ci-bot | verified owner | pass |

## Agent registry (agent_registry)

| Check | Target | Scenario | Expected |
|---|---|---|---|
| AGI-002 | agent-research-child | capabilities held with NO mission contract (purpose null) | fail |
| AGI-002 | agent-research | capabilities within declared purpose | pass |
| AGI-004 | agent-shadow-7 | observed in gateway sample, absent from registry (`registered: false`) | fail |
| AGI-005 | mcp-tools.internal.example | sensitive endpoint, `auth: none`, unapproved | fail |
| AGI-005 | mcp-search.vendor.example | oauth + approved | pass |
| AGI-006 | agent-research-child | child capabilities exceed parent (net:egress, tool:mcp_client not in parent) | fail |
| AGI-008 | agent-ops | active agent, sponsor null, purpose null | fail |
| AGI-008 | agent-research | sponsor + purpose present | pass |
| AGI-011 | mcp-search.vendor.example | oauth audience `https://wrong-audience.example` != approved tenant audience | fail |
| AGI-014 | agent-research-child | egress allowlist empty | fail |
| AGI-014 | agent-research | egress allowlist has approved destinations | pass |
| AGI-015 | gateway/kill-switch | `kill_switch.configured: false` | fail |

Gateway policy data lives in fixture `attributes_extra` and arrives to checks as the
`collection.extras` artifact (see `SnapshotView.artifacts`).

## Inventory

| Check | Scenario | Expected |
|---|---|---|
| INV-001 | every source (baseline run, no prior complete snapshot) | not_applicable, reason mentions baseline |
| INV-002 | aws_iam, github, agent_registry (complete snapshots) | pass |

## Golden outcomes file

`tests/golden/expected_outcomes.json` format:

```json
{
  "expected": [
    {"check_id": "CLD-002", "target_key_contains": "VendorDeploy", "status": "fail"},
    {"check_id": "CLD-002", "target_key_contains": "CrossAcctVendor", "status": "pass"},
    {"check_id": "CLD-002", "target_key_contains": "ApprovedUnbound", "status": "unknown"}
  ],
  "counts": {"CLD-002": {"fail": 1, "pass": 1, "unknown": 1}},
  "partial_sources": ["entra"],
  "min_total_results": 45
}
```
