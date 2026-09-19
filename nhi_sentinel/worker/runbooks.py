"""N15 vetted runbook lookup. Drafts only - remediation execution is customer-authorized
and outside the default product (UI11/OF06). Unknown remedy escalates to a specialist."""

RUNBOOKS: dict[str, dict] = {
    "CLD-002": {
        "steps": ["Compare trust policy principals against the approved integration register",
                  "Tighten trust conditions (external ID, subject) or remove unused trust",
                  "Record owner attestation for retained cross-account trust"],
        "retest": "Passive re-collect of IAM trust policies; confirm trust matches approved register",
    },
    "CLD-007": {
        "steps": ["Identify business owner for the cross-account relationship",
                  "Add missing conditions or retire the trust"],
        "retest": "Passive re-collect; relationship present in integration register with conditions",
    },
    "CLD-008": {
        "steps": ["Restrict OIDC federation subject/audience to approved repo+branch+environment",
                  "Remove wildcard subject conditions"],
        "retest": "Re-collect federation trust; subject matches approved CI identities exactly",
    },
    "CLD-009": {
        "steps": ["Attest business and technical owners for the principal (UI identity detail)",
                  "Set review expiry per policy"],
        "retest": "Ownership completeness check reports the identity as owned",
    },
    "KEY-001": {
        "steps": ["Verify whether the candidate credential is real and authorized (out-of-band)",
                  "Revoke and rotate if real; remove from source history"],
        "retest": "Local re-scan no longer matches; validity stays untested by design (G23)",
    },
    "KEY-003": {
        "steps": ["Rotate the credential per its type policy",
                  "Prefer short-lived federation for supported workloads"],
        "retest": "Credential metadata shows rotation within policy window",
    },
    "KEY-007": {
        "steps": ["Delete redundant enabled credentials after rollover overlap"],
        "retest": "Single enabled credential per identity unless shared design approved",
    },
    "OAU-001": {
        "steps": ["Confirm business purpose with app owner",
                  "Reduce consented roles to required set or remove grant"],
        "retest": "Effective grant scope within approved purpose",
    },
    "OAU-004": {
        "steps": ["Run third-party app risk review", "Block or constrain multi-tenant consent"],
        "retest": "External app has current owner and completed review",
    },
    "CICD-006": {
        "steps": ["Set least-privilege workflow token permissions (read-only default)",
                  "Scope write permissions to specific jobs"],
        "retest": "Workflow permissions match build needs on untrusted triggers",
    },
    "CICD-007": {
        "steps": ["Pin third-party actions to reviewed digests", "Add allowlist policy for actions"],
        "retest": "All external actions pinned to approved versions",
    },
    "AGI-002": {
        "steps": ["Align agent capability grants with sponsor-approved mission contract",
                  "Revoke excess tool/resource capabilities"],
        "retest": "Effective capabilities within declared mission",
    },
    "AGI-004": {
        "steps": ["Identify operator/sponsor of observed agent", "Register or shut down the agent"],
        "retest": "Complete registry reconciles with runtime observations",
    },
    "AGI-005": {
        "steps": ["Require authentication and reviewed manifest for the MCP endpoint",
                  "Add endpoint to approved registry"],
        "retest": "Endpoint passes untrusted-MCP configuration check",
    },
    "AGI-006": {
        "steps": ["Re-scope child agent capabilities to parent ceiling",
                  "Enforce delegation depth policy"],
        "retest": "Delegation chain shows no capability amplification",
    },
    "AGI-008": {
        "steps": ["Assign accountable sponsor and purpose", "Configure retirement controls"],
        "retest": "Registry lifecycle fields complete for all active agents",
    },
    "AGI-011": {
        "steps": ["Constrain tool auth issuer/audience/resource to approved values"],
        "retest": "Gateway auth policy binds audience and issuer for sensitive tools",
    },
    "AGI-014": {
        "steps": ["Apply egress allowlist for agent tool traffic"],
        "retest": "Egress policy limits destinations to approved data boundary",
    },
    "AGI-015": {
        "steps": ["Enable independent revoke/disable covering delegated identities",
                  "Drill the kill path in an approved window"],
        "retest": "Kill control present and drill scheduled",
    },
    "INV-001": {
        "steps": ["Re-run complete collection for stale source", "Investigate collector health"],
        "retest": "Fresh complete snapshot within window",
    },
    "INV-002": {
        "steps": ["Request missing read permissions for the collector identity",
                  "Re-run collection and confirm full pagination"],
        "retest": "Complete snapshot with no page errors",
    },
}
