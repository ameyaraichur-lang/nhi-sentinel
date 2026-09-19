"""Synthetic demo seed (BG12): tenant, users/roles, engagement, approved scope, connectors,
dormant proof proposal. Idempotent. All data is synthetic and labeled (UX24)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from .config import get_settings
from .core.audit import append_audit
from .core.db import (
    Connector, Engagement, MachineToken, Proposal, ScopeVersion, Tenant, User, new_id,
    session_scope, utcnow,
)
from .core.security import digest_of, hash_password, sha256_hex

PILOT_CHECK_IDS = [
    # cloud (CN01/CN02)
    "CLD-002", "CLD-007", "CLD-008", "CLD-009",
    # credentials
    "KEY-001", "KEY-003", "KEY-007",
    # OAuth/app consent
    "OAU-001", "OAU-004",
    # CI/CD
    "CICD-006", "CICD-007",
    # agent identity governance (the differentiator)
    "AGI-002", "AGI-004", "AGI-005", "AGI-006", "AGI-008", "AGI-011", "AGI-014", "AGI-015",
    # inventory health
    "INV-001", "INV-002",
]

PILOT_SOURCES = ["aws_iam", "entra", "github", "agent_registry"]

USERS = [
    ("admin@demo.nhi", "Tenant Admin", "tenant_admin"),
    ("analyst@demo.nhi", "Ana Analyst", "analyst"),
    ("operator@demo.nhi", "Olive Operator", "operator"),
    ("approver1@demo.nhi", "Sam Approver", "approver"),
    ("approver2@demo.nhi", "Dana Approver", "approver"),
    ("reviewer@demo.nhi", "Reed Reviewer", "reviewer"),
    ("viewer@demo.nhi", "Vic Viewer", "viewer"),
    ("auditor@demo.nhi", "Ari Auditor", "auditor"),
]

# SC23/AT33: platform support sits in its own synthetic tenant, outside every customer tenant.
PLATFORM_TENANT_NAME = "Sentinel Platform (SYNTHETIC)"
PLATFORM_USERS = [
    ("support@nhi.internal", "Sasha Support (SYNTHETIC)", "support"),
]

CAPABILITY_MANIFESTS = {
    "aws_iam": {"read": ["iam:list_roles", "iam:list_users", "iam:get_role_policy",
                         "iam:list_access_keys", "iam:simulate_nothing"]},
    "entra": {"read": ["graph:application.read.all", "graph:serviceprincipal-endpoints"]},
    "github": {"read": ["repo:contents:read", "repo:workflows:read", "repo:deploy-keys:read"]},
    "agent_registry": {"read": ["registry:signed-json-import", "gateway:metadata"]},
}


def _ensure_platform_tenant(s) -> None:
    """SC23 top-up for databases seeded before the platform tenant/support user existed."""
    exists = s.execute(select(User).where(
        User.email == PLATFORM_USERS[0][0])).scalars().first()
    if exists:
        return
    platform = Tenant(id=new_id("tnt"), name=PLATFORM_TENANT_NAME,
                      region="eu-central-1", plan="platform", synthetic=True)
    s.add(platform)
    s.flush()
    for email, name, role in PLATFORM_USERS:
        s.add(User(id=new_id("usr"), tenant_id=platform.id, email=email, display_name=name,
                   role=role, password_hash=hash_password(get_settings().demo_password)))
    append_audit(platform.id, "seed", "tenant.create", "tenant", platform.id, {"synthetic": True},
                 session=s)


def ensure_seed() -> dict:
    with session_scope() as s:
        existing = s.execute(select(Tenant).where(Tenant.name.like("%SYNTHETIC DEMO%"))).scalars().first()
        if existing:
            _ensure_platform_tenant(s)
            return {"seeded": False, "tenant_id": existing.id}

    demo = Tenant(id=new_id("tnt"), name="Northwind Logistics (SYNTHETIC DEMO)",
                  region="eu-central-1", plan="pilot", synthetic=True)
    att = Tenant(id=new_id("tnt"), name="Contoso Attack-Tests (SYNTHETIC DEMO)",
                 region="eu-central-1", plan="pilot", synthetic=True)
    platform = Tenant(id=new_id("tnt"), name=PLATFORM_TENANT_NAME,
                      region="eu-central-1", plan="platform", synthetic=True)
    with session_scope() as s:
        s.add(demo)
        s.add(att)
        s.add(platform)
        pwd = hash_password(get_settings().demo_password)
        for email, name, role in USERS:
            s.add(User(id=new_id("usr"), tenant_id=demo.id, email=email, display_name=name,
                       role=role, password_hash=pwd))
        # tenant B: isolation-test counterpart (AT01)
        s.add(User(id=new_id("usr"), tenant_id=att.id, email="intruder@contoso.nhi",
                   display_name="Cross-Tenant Tester", role="analyst", password_hash=pwd))
        # platform support user (SC23): elevation only via audited SupportGrant
        for email, name, role in PLATFORM_USERS:
            s.add(User(id=new_id("usr"), tenant_id=platform.id, email=email, display_name=name,
                       role=role, password_hash=pwd))
        for source in PILOT_SOURCES:
            s.add(Connector(id=new_id("cn"), tenant_id=demo.id, connector_type=source,
                            display_name={"aws_iam": "AWS IAM (import)",
                                          "entra": "Entra ID (import)",
                                          "github": "GitHub (import)",
                                          "agent_registry": "Agent registry/gateway (import)"}[source],
                            capability_manifest_json=CAPABILITY_MANIFESTS[source]))
        eng = Engagement(id=new_id("eng"), tenant_id=demo.id,
                         name="Q4 NHI Baseline (synthetic)", mode="passive",
                         created_by="seed")
        s.add(eng)
        s.flush()
        scope_payload = {"sources": PILOT_SOURCES, "exclusions": []}
        sv = ScopeVersion(id=new_id("scv"), tenant_id=demo.id, engagement_id=eng.id, version=1,
                          roe_ref="ROE-synthetic-demo-v1 (passive import only)",
                          sources_json=scope_payload, exclusions_json=[],
                          check_ids_json=PILOT_CHECK_IDS, scope_hash=digest_of(scope_payload),
                          approved_by="seed", approved_at=utcnow(), created_by="seed")
        s.add(sv)
        s.add(MachineToken(id=new_id("mtk"), tenant_id=demo.id,
                           label="demo-ci-pipeline", token_hash=sha256_hex("demo-ci-token-synthetic"),
                           enabled=True))
        # dormant active-proof proposal (demonstrates DC16/DC17 two-person flow; D06 blocks execution)
        s.add(Proposal(
            id=new_id("prp"), tenant_id=demo.id, run_id=None, kind="active_proof",
            template="aws.iam_role_trust_probe", template_version="1.0.0",
            title="Sandbox: verify external trust exploitability for role VendorDeploy (SYNTHETIC)",
            payload_json={"role": "arn:aws:iam::111122223333:role/VendorDeploy",
                          "environment": "sandbox-only", "max_duration_s": 300},
            expected_effects=["One AssumeRole call against the sandbox account",
                              "No persistence, no data access, no alerts suppressed"],
            rollback="No state mutated; sandbox session auto-expires",
            action_digest=digest_of({"template": "aws.iam_role_trust_probe", "v": "1.0.0",
                                     "role": "VendorDeploy", "window": "pilot"}),
            scope_hash=sv.scope_hash, status="pending",
            execution_window_s=900, created_by="seed-analyst",
            created_at=utcnow(), expires_at=utcnow() + timedelta(days=7)))
    append_audit(demo.id, "seed", "tenant.create", "tenant", demo.id, {"synthetic": True})
    append_audit(att.id, "seed", "tenant.create", "tenant", att.id, {"synthetic": True})
    append_audit(platform.id, "seed", "tenant.create", "tenant", platform.id, {"synthetic": True})
    return {"seeded": True, "tenant_id": demo.id, "tenant_b_id": att.id,
            "platform_tenant_id": platform.id,
            "users": len(USERS) + len(PLATFORM_USERS) + 1, "checks": len(PILOT_CHECK_IDS)}
