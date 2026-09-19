"""AT17 evidence custody + append-only audit chain: any tamper must be detectable.

The DB is throwaway per session, so the tamper/deletion tests mutate freely."""
from __future__ import annotations

import time
from sqlalchemy import func, select, text

from nhi_sentinel.core.db import AuditEntry, EvidenceArtifact, session_scope

from .conftest import ANALYST, AUDITOR, login


def test_AT17__evidence_signature_detects_content_tamper(client, full_run_id):
    analyst = login(client, ANALYST)
    tenant_a = analyst["tenant_id"]

    with session_scope() as s:
        art_id = s.execute(select(EvidenceArtifact.id).where(
            EvidenceArtifact.tenant_id == tenant_a,
            EvidenceArtifact.run_id == full_run_id).order_by(EvidenceArtifact.id)
        ).scalars().first()
    assert art_id, "expected collected evidence artifacts"

    first = client.get(f"/v1/evidence/{art_id}")
    assert first.status_code == 200, first.text
    assert first.json()["signature_valid"] is True, "fresh artifact must verify"

    # Flip a byte in the stored content directly in the DB (simulated storage tamper).
    with session_scope() as s:
        art = s.get(EvidenceArtifact, art_id)
        content = art.content_json
        if isinstance(content, dict):
            tampered = dict(content)
            tampered["__qa_tamper__"] = "flipped-byte"
        elif isinstance(content, list):
            tampered = list(content) + ["__qa_tamper__:flipped-byte"]
        else:
            tampered = f"{content}#tampered"
        art.content_json = tampered  # attribute reassignment marks the column dirty

    second = client.get(f"/v1/evidence/{art_id}")
    assert second.status_code == 200
    assert second.json()["signature_valid"] is False, "tampered artifact must fail verification"
    assert second.json()["content"] == tampered, "the tampered bytes are what gets served"


def test_AT17__audit_chain_verification_detects_deleted_entry(client):
    """Deletion tamper is exercised on a THROWAWAY tenant chain: this test deliberately
    breaks a chain, and later modules (alphabetically after this file) must still see an
    intact tenant-A chain."""
    from nhi_sentinel.core.audit import append_audit, verify_chain
    from nhi_sentinel.core.db import Tenant
    auditor = login(client, AUDITOR, role="auditor")
    tenant_a = auditor["tenant_id"]

    with session_scope() as s:
        throwaway = s.execute(select(Tenant).where(Tenant.id != tenant_a)).scalars().first()
        tenant_b = throwaway.id
    append_audit(tenant_b, "qa-tamper", "chain.entry", "test", "1", {})
    append_audit(tenant_b, "qa-tamper", "chain.entry", "test", "2", {})
    append_audit(tenant_b, "qa-tamper", "chain.entry", "test", "3", {})

    verified = verify_chain(tenant_b)
    assert verified["valid"] is True, f"fresh chain must verify: {verified}"

    # Delete the middle entry of the throwaway chain -> verification must flag it.
    with session_scope() as s:
        rows = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_b)
                         .order_by(text("rowid"))).scalars().all()
        victim = rows[len(rows) // 2]
        s.delete(victim)

    broken = verify_chain(tenant_b)
    assert broken["valid"] is False, "deleting a chain entry must break verification"
    assert broken["broken_at"], "verification must report where the chain broke"

    # tenant A's production chain is untouched and still verifies
    assert verify_chain(tenant_a)["valid"] is True


def chain_neighborhood(tenant_id: str, broken_at: str | None) -> str:
    """Human-readable prev->entry links around a break, for failure diagnostics."""
    from nhi_sentinel.core.db import session_scope as scope
    with scope() as s:
        rows = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tenant_id)
                         .order_by(text("rowid"))).scalars().all()
    links = [(r.id[-6:], r.action, (r.prev_hash or "genesis")[-6:], r.entry_hash[-6:])
             for r in rows]
    if broken_at:
        idx = next((i for i, r in enumerate(rows) if r.id == broken_at), None)
        if idx is not None:
            links = links[max(0, idx - 2):idx + 3]
    return f"chain={links}"
