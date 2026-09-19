"""Governance services: risk exceptions (DC20/AT30), retention purge (OP08/AT26),
tenant offboarding (OP20/AT42) with tombstone ledger."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, text

from .reports.core_guard import assert_tenant
from .core.audit import append_audit
from .core.db import (
    EvidenceArtifact, Finding, OffboardLedger, RiskException, Session as DbSession, Tenant,
    User, new_id, session_scope, utcnow,
)


# --- risk exceptions (DC20: expiry reopens review; original severity untouched) ---------

def create_exception(session, *, tenant_id: str, finding_id: str, requester_id: str,
                     justification: str, compensating_controls: str, expiry_days: int) -> RiskException:
    finding = session.get(Finding, finding_id)
    assert_tenant(finding, tenant_id)
    if finding.workflow_status == "resolved":
        raise ValueError("resolved findings close only via retest (PS15)")
    exc = RiskException(
        id=new_id("exc"), tenant_id=tenant_id, finding_id=finding.id,
        requester_id=requester_id, justification=justification[:2000],
        compensating_controls=compensating_controls[:2000],
        status="pending", expires_at=utcnow() + timedelta(days=expiry_days))
    session.add(exc)
    session.flush()
    return exc


def decide_exception(session, *, tenant_id: str, exception_id: str, decider_id: str,
                     decision: str, reason: str) -> RiskException:
    exc = session.get(RiskException, exception_id)
    assert_tenant(exc, tenant_id)
    if exc.requester_id == decider_id:
        raise PermissionError("no self-approval of risk exceptions (SC05)")
    if exc.status != "pending":
        raise ValueError(f"exception already {exc.status}")
    if exc.expires_at < utcnow():
        exc.status = "expired"
        raise ValueError("exception request already expired")
    exc.status = "accepted" if decision == "accept" else "denied"
    exc.approver_id = decider_id
    exc.decision_reason = reason[:1000]
    exc.decided_at = utcnow()
    finding = session.get(Finding, exc.finding_id)
    if decision == "accept":
        finding.workflow_status = "accepted"
        finding.exception_id = exc.id
    return exc


def expire_exceptions(session) -> int:
    """Accepted risks expire: reopen the finding review (DC20/PS15)."""
    expired = session.execute(select(RiskException).where(
        RiskException.status == "accepted", RiskException.expires_at < utcnow())).scalars().all()
    n = 0
    for exc in expired:
        exc.status = "expired"
        finding = session.get(Finding, exc.finding_id)
        if finding is not None and finding.workflow_status == "accepted":
            finding.workflow_status = "reopened"
        n += 1
    return n


# --- retention purge (OP08: deletion ledger prevents restore resurrection) --------------

def purge_expired(session, *, retention_days: int = 30) -> int:
    """Purge artifact CONTENT past raw-retention, keeping signed manifests as tombstones.
    Legal hold blocks purge (OP08/D13)."""
    cutoff = utcnow() - timedelta(days=retention_days)
    stale = session.execute(select(EvidenceArtifact).where(
        EvidenceArtifact.retention_state == "active",
        EvidenceArtifact.received_at < cutoff)).scalars().all()
    purged = 0
    for art in stale:
        tenant = session.get(Tenant, art.tenant_id)
        if tenant is not None and tenant.legal_hold:
            continue  # documented hold
        art.content_json = {}
        art.retention_state = "purged"
        session.add(OffboardLedger(id=new_id("tmb"), tenant_id=art.tenant_id,
                                   object_type="evidence_content", object_id=art.id,
                                   reason="retention-purge"))
        purged += 1
    return purged


# --- tenant offboarding (OP20/AT42) -------------------------------------------------------

def offboard_tenant(session, *, tenant_id: str, reason: str) -> dict:
    """Revoke access, stop schedules, purge evidence content behind tombstones, keep the
    audit chain (integrity evidence survives offboarding)."""
    from .core.db import Connector, Session as DbSession, Subscription
    tenant = session.get(Tenant, tenant_id)
    if tenant.status == "offboarded":
        raise ValueError("tenant already offboarded")
    tenant.status = "offboarded"
    ledger = 0

    for conn in session.execute(select(Connector).where(
            Connector.tenant_id == tenant_id)).scalars():
        conn.enabled = False
        conn.preflight_state = "revoked"
    for sub in session.execute(select(Subscription).where(
            Subscription.tenant_id == tenant_id)).scalars():
        sub.enabled = False
    for sess in session.execute(select(DbSession).where(
            DbSession.tenant_id == tenant_id, DbSession.revoked_at.is_(None))).scalars():
        sess.revoked_at = utcnow()

    for art in session.execute(select(EvidenceArtifact).where(
            EvidenceArtifact.tenant_id == tenant_id,
            EvidenceArtifact.retention_state == "active")).scalars():
        art.content_json = {}
        art.retention_state = "purged"
        session.add(OffboardLedger(id=new_id("tmb"), tenant_id=tenant_id,
                                   object_type="evidence_content", object_id=art.id,
                                   reason="offboarding"))
        ledger += 1
    session.add(OffboardLedger(id=new_id("tmb"), tenant_id=tenant_id,
                               object_type="tenant", object_id=tenant_id,
                               reason="offboarding"))
    ledger += 1
    append_audit(tenant_id, "system:offboarding", "tenant.offboarded", "tenant", tenant_id,
                 {"reason": reason[:300], "ledger_entries": ledger}, session=session)
    return {"status": "offboarded", "ledger_entries": ledger}
