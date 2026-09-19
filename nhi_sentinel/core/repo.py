"""Tenant-scoped data access. Every read/write is bound to tenant_id (SC01/SC02, AT01).

SnapshotView is the read-only facade checks consume during N04 — assembled from the run's
validated snapshots only. It carries completeness metadata so checks can return `unknown`
instead of pass on missing evidence (G25, AT08, AT16).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select

from ..contracts import SnapshotState
from .db import (
    AgentRecord, CheckResult, Connector, CredentialMeta, EvidenceArtifact, Finding,
    GraphEdge, Identity, OwnershipAssertion, Run, Snapshot, session_scope,
)
from .db import new_id, utcnow


class TenantViolation(LookupError):
    """Raised when an object is not visible to the requesting tenant (=> HTTP 404 upstream)."""


def scoped_get(session, model, tenant_id: str, object_id: str):
    obj = session.get(model, object_id)
    if obj is None or getattr(obj, "tenant_id", tenant_id) != tenant_id:
        raise TenantViolation(object_id)
    return obj


# --- Finding service (DC12, EX09: only the finding service commits evaluated states) ---

def upsert_finding(session, *, tenant_id: str, run_id: str, result: CheckResult,
                   title: str, summary: str, severity: str, assurance: str,
                   severity_rationale: str) -> Finding:
    """Dedup key: tenant + check family + canonical target + condition signature (DC12).
    Preserves occurrence history; a re-observation bumps occurrences and updates facts."""
    dedup_key = f"{tenant_id}|{result.check_id}|{result.target_key}|{result.facts.get('condition_signature', '')}"
    existing = session.execute(
        select(Finding).where(Finding.tenant_id == tenant_id, Finding.dedup_key == dedup_key)
    ).scalars().first()
    if existing:
        existing.revision += 1
        existing.occurrence_count += 1
        existing.updated_at = utcnow()
        existing.latest_result_id = result.id
        existing.facts = result.facts
        existing.evidence_refs_json = result.evidence_refs_json
        existing.run_id = run_id
        # PS01/DC13: new observation does not silently change evidence truth (severity/assurance
        # stay until policy re-evaluates); reopening is explicit workflow.
        if existing.workflow_status == "resolved":
            existing.workflow_status = "reopened"
        return existing
    finding = Finding(
        id=new_id("fnd"), tenant_id=tenant_id, run_id=run_id, check_id=result.check_id,
        check_version=result.check_version, target_id=result.target_id, target_key=result.target_key,
        dedup_key=dedup_key, title=title, summary=summary, severity=severity, assurance=assurance,
        workflow_status="open", evidence_refs_json=result.evidence_refs_json, facts=result.facts,
        severity_rationale=severity_rationale, latest_result_id=result.id, first_seen=utcnow(),
        updated_at=utcnow(),
    )
    session.add(finding)
    session.flush()
    return finding


def merge_proof_outcome(session, finding: Finding, proof_status: str) -> None:
    """G04/AT09: failed or denied proof must NOT erase a config-supported finding.
    Contradictions create a revision requiring analyst review; error != disproven."""
    if proof_status == "contradicted":
        finding.assurance = "contradicted"
        finding.revision += 1
    elif proof_status in ("denied", "failed", "timeout", "error"):
        finding.assurance = "config_supported"  # unchanged; recorded in facts
        finding.facts = {**finding.facts, "proof_attempt": proof_status}
    elif proof_status == "confirmed":
        finding.assurance = "test_supported"
        finding.revision += 1


# --- SnapshotView -----------------------------------------------------------------

@dataclass
class SnapshotView:
    """Read-only normalized view over one run's snapshots (N04 input)."""

    tenant_id: str
    run_id: str
    snapshots: list[Snapshot] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    credentials: list[CredentialMeta] = field(default_factory=list)
    ownership: list[OwnershipAssertion] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    agents: list[AgentRecord] = field(default_factory=list)
    artifacts: dict[str, EvidenceArtifact] = field(default_factory=dict)

    def grants(self) -> list[dict]:
        """Entra app grants travel inside signed collection artifacts (OAU checks)."""
        out: list[dict] = []
        for a in self.artifacts.values():
            if a.kind == "collection.grants":
                out.extend(a.content_json if isinstance(a.content_json, list) else [])
        return out

    def by_source(self, source: str) -> list[Snapshot]:
        return [s for s in self.snapshots if s.source == source]

    def snapshot_state(self, source: str) -> SnapshotState | None:
        snaps = self.by_source(source)
        if not snaps:
            return None
        if any(s.state == SnapshotState.PARTIAL.value for s in snaps):
            return SnapshotState.PARTIAL
        return SnapshotState(snaps[0].state)

    def source_complete(self, source: str) -> bool:
        state = self.snapshot_state(source)
        return state == SnapshotState.COMPLETE

    def identities_for(self, provider: str) -> list[Identity]:
        return [i for i in self.identities if i.provider == provider]

    def identity_by_key(self, provider: str, authority: str, native_id: str) -> Identity | None:
        for i in self.identities:
            if i.provider == provider and i.authority == authority and i.native_id == native_id:
                return i
        return None

    def ownership_for(self, identity_id: str) -> list[OwnershipAssertion]:
        return [o for o in self.ownership if o.identity_id == identity_id]

    def verified_owner(self, identity_id: str) -> OwnershipAssertion | None:
        for o in self.ownership_for(identity_id):
            if o.verified_at is not None and (o.valid_to is None or o.valid_to > utcnow()):
                return o
        return None

    def credentials_for(self, identity_id: str) -> list[CredentialMeta]:
        return [c for c in self.credentials if c.identity_id == identity_id]

    def agent_by_native(self, native_id: str) -> AgentRecord | None:
        return next((a for a in self.agents if a.native_id == native_id), None)

    def agent_children(self, native_id: str) -> list[AgentRecord]:
        return [a for a in self.agents if a.parent_native_id == native_id]

    def edges_from(self, src_id: str, rel: str | None = None) -> list[GraphEdge]:
        return [e for e in self.edges if e.src_id == src_id and (rel is None or e.relationship == rel)]


def load_snapshot_view(tenant_id: str, run_id: str, session=None) -> SnapshotView:
    """Builds the view inside the ambient session when provided (nested session_scope under
    BEGIN IMMEDIATE would self-deadlock on the write lock)."""
    if session is not None:
        return _load_view(session, tenant_id, run_id)
    with session_scope() as s:
        return _load_view(s, tenant_id, run_id)


def _load_view(s, tenant_id: str, run_id: str) -> SnapshotView:
    snaps = s.execute(select(Snapshot).where(
        Snapshot.tenant_id == tenant_id, Snapshot.run_id == run_id)).scalars().all()
    snap_ids = [x.id for x in snaps]
    identities = s.execute(select(Identity).where(Identity.tenant_id == tenant_id)).scalars().all()
    creds = s.execute(select(CredentialMeta).where(CredentialMeta.tenant_id == tenant_id)).scalars().all()
    ownership = s.execute(select(OwnershipAssertion).where(
        OwnershipAssertion.tenant_id == tenant_id)).scalars().all()
    edges = s.execute(select(GraphEdge).where(
        GraphEdge.tenant_id == tenant_id,
        GraphEdge.snapshot_id.in_(snap_ids or ["-"]))).scalars().all()
    agents = s.execute(select(AgentRecord).where(
        AgentRecord.tenant_id == tenant_id)).scalars().all()
    artifacts = {}
    if snap_ids:
        rows = s.execute(select(EvidenceArtifact).where(
            EvidenceArtifact.tenant_id == tenant_id,
            EvidenceArtifact.snapshot_id.in_(snap_ids))).scalars().all()
        artifacts = {a.id: a for a in rows}
    view = SnapshotView(tenant_id=tenant_id, run_id=run_id)
    view.snapshots, view.identities, view.credentials = list(snaps), list(identities), list(creds)
    view.ownership, view.edges, view.agents = list(ownership), list(edges), list(agents)
    view.artifacts = artifacts
    return view


def connector_map(tenant_id: str) -> dict[str, Connector]:
    with session_scope() as s:
        rows = s.execute(select(Connector).where(Connector.tenant_id == tenant_id)).scalars().all()
        s.expunge_all()
        return {c.connector_type: c for c in rows}
