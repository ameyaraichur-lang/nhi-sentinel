"""Governance acceptance tests: AT30 exceptions lifecycle, AT42 offboarding, OP08 retention.

TestClient has ONE cookie jar: log in immediately before each user's requests."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, text

import pytest

from nhi_sentinel.core.db import (
    AuditEntry, Connector, EvidenceArtifact, RiskException, Tenant, session_scope, utcnow,
)
from nhi_sentinel.governance import decide_exception, expire_exceptions, purge_expired

from .conftest import ANALYST, APPROVER1, login


def _a_finding_id(client, tenant_a: str) -> str:
    resp = client.get("/v1/findings?limit=1")
    assert resp.status_code == 200 and resp.json()["total"] >= 1, "fixture run must produce findings"
    return resp.json()["items"][0]["finding_id"]


def test_AT30__exception_request_accept_expire_reopens(client, full_run_id):
    analyst = login(client, ANALYST)
    finding_id = _a_finding_id(client, analyst["tenant_id"])
    created = client.post("/v1/exceptions", headers=analyst["headers"], json={
        "finding_id": finding_id, "justification": "Compensating controls reviewed with owner",
        "compensating_controls": "Compensating control: egress allowlist enforced",
        "expiry_days": 30})
    assert created.status_code == 201, created.text
    exc = created.json()
    assert exc["status"] == "pending"

    approver = login(client, APPROVER1, role="approver")
    pending = client.get("/v1/exceptions?status=pending")
    assert any(e["exception_id"] == exc["exception_id"] for e in pending.json())

    decided = client.post(f"/v1/exceptions/{exc['exception_id']}/decisions",
                          headers=approver["headers"],
                          json={"decision": "accept", "reason": "Risk owner approved with expiry"})
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "accepted"
    assert decided.json()["finding_workflow_status"] == "accepted"

    again = client.post(f"/v1/exceptions/{exc['exception_id']}/decisions",
                        headers=approver["headers"],
                        json={"decision": "deny", "reason": "second decision attempt"})
    assert again.status_code == 422, "double decision must fail"

    # accepted risk expiry reopens the finding review (DC20)
    with session_scope() as s:
        row = s.get(RiskException, exc["exception_id"])
        row.expires_at = utcnow() - timedelta(days=1)
    with session_scope() as s:
        assert expire_exceptions(s) >= 1
    detail = client.get(f"/v1/findings/{finding_id}").json()
    assert detail["workflow_status"] == "reopened"


def test_AT30__exception_decision_by_requester_is_rejected(client, full_run_id):
    """SC05: the requester can neither reach the decide endpoint (role gate) nor pass the
    service-level self-approval guard."""
    analyst = login(client, ANALYST)
    finding_id = _a_finding_id(client, analyst["tenant_id"])
    created = client.post("/v1/exceptions", headers=analyst["headers"], json={
        "finding_id": finding_id, "justification": "Requester must not decide own exception",
        "expiry_days": 30})
    assert created.status_code == 201

    decided = client.post(f"/v1/exceptions/{created.json()['exception_id']}/decisions",
                          headers=analyst["headers"],
                          json={"decision": "accept", "reason": "self approval attempt"})
    assert decided.status_code == 403  # analyst lacks approval:decide entirely

    # service-level guard: even a caller matching the requester id fails
    with session_scope() as s:
        with pytest.raises(PermissionError, match="self-approval"):
            decide_exception(s, tenant_id=analyst["tenant_id"],
                             exception_id=created.json()["exception_id"],
                             decider_id=analyst["user_id"],
                             decision="accept", reason="service-level self approval")


def test_AT42__offboarding_revokes_access_purges_and_ledgers(client, full_run_id):
    admin = login(client, "admin@demo.nhi", role="tenant_admin")
    tenant_id = admin["tenant_id"]
    settings = client.get("/v1/tenant-settings").json()
    assert settings["status"] == "active"

    wrong = client.post("/v1/tenant-offboarding", headers=admin["headers"],
                        json={"confirmation": "wrong-name", "reason": "confirmation mismatch test"})
    assert wrong.status_code == 422
    assert wrong.json()["error"]["code"] == "CONFIRMATION_MISMATCH"

    with session_scope() as s:
        arts_before = s.execute(select(EvidenceArtifact).where(
            EvidenceArtifact.tenant_id == tenant_id)).scalars().all()
    assert arts_before

    offboard = client.post("/v1/tenant-offboarding", headers=admin["headers"],
                           json={"confirmation": "Northwind Logistics (SYNTHETIC DEMO)",
                                 "reason": "contract ended (AT42)"})
    assert offboard.status_code == 202, offboard.text
    assert offboard.json()["status"] == "offboarded"
    assert offboard.json()["ledger_entries"] >= len(arts_before)

    # sessions revoked server-side (OP20)
    me = client.get("/v1/me")
    assert me.status_code == 401

    # connectors revoked, evidence purged behind tombstones, audit chain survives (SC15)
    with session_scope() as s:
        conns = s.execute(select(Connector).where(
            Connector.tenant_id == tenant_id)).scalars().all()
        assert conns and all(c.enabled is False and c.preflight_state == "revoked"
                             for c in conns)
        arts = s.execute(select(EvidenceArtifact).where(
            EvidenceArtifact.tenant_id == tenant_id)).scalars().all()
        assert all(a.retention_state == "purged" and a.content_json == {} for a in arts)
    from nhi_sentinel.core.audit import verify_chain  # outside the transaction: no nesting
    verdict = verify_chain(tenant_id)
    if not verdict["valid"]:  # diagnostic dump for the intermittent-fork investigation
        with session_scope() as s:
            rows = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id)
                             .order_by(text("rowid"))).scalars().all()
        for i, e in enumerate(rows):
            print(f"  [{i:02d}] {e.action:<28} prev={e.prev_hash[:10]} hash={e.entry_hash[:10]}")
    assert verdict["valid"] is True, verdict

    # offboarding is idempotent-rejected
    with session_scope() as s:
        with pytest.raises(ValueError, match="already offboarded"):
            from nhi_sentinel.governance import offboard_tenant
            offboard_tenant(s, tenant_id=tenant_id, reason="second attempt")


def test_OP08__retention_purge_respects_legal_hold(client):
    from nhi_sentinel.core.db import new_id
    with session_scope() as s:
        t = s.execute(select(Tenant)).scalars().first()
        t.legal_hold = False
        art = EvidenceArtifact(id=new_id("art"), tenant_id=t.id, kind="observation",
                               producer="test", content_json={"probe": "retention"},
                               sha256="0" * 64, signature="0" * 64,
                               received_at=utcnow() - timedelta(days=31))
        s.add(art)
        s.flush()
        art_id = art.id

        purged = purge_expired(s, retention_days=30)
        assert purged >= 1
        after = s.get(EvidenceArtifact, art_id)
        assert after.retention_state == "purged" and after.content_json == {}
        assert after.sha256, "manifest hash survives purge (tombstone)"


def test_OP08__legal_hold_blocks_purge(client):
    from nhi_sentinel.core.db import new_id
    with session_scope() as s:
        t = s.execute(select(Tenant)).scalars().first()
        t.legal_hold = True
        art = EvidenceArtifact(id=new_id("art"), tenant_id=t.id, kind="observation",
                               producer="test", content_json={"probe": "hold"},
                               sha256="1" * 64, signature="1" * 64,
                               received_at=utcnow() - timedelta(days=31))
        s.add(art)
        s.flush()
        art_id = art.id
        assert purge_expired(s, retention_days=30) >= 0
        after = s.get(EvidenceArtifact, art_id)
        assert after.retention_state == "active" and after.content_json != {},             "legal hold must block purge"
        t.legal_hold = False

