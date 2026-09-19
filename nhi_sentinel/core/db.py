"""Persistence layer. PostgreSQL is the blueprint target (SC01 RLS, EX08 indexes); this slice
runs on SQLite with tenant scoping enforced in the repository layer and negative-tested (AT01).
Every child row carries tenant_id; every repository method is tenant-bound (defense in depth).
"""
from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
    create_engine, event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from ..config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # stored naive-UTC (DC08: RFC3339 UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """DC01. kill_flag implements the SC18 independent tenant-level stop."""

    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    region: Mapped[str] = mapped_column(String(40), default="eu-central-1")
    plan: Mapped[str] = mapped_column(String(40), default="pilot")
    retention_policy_version: Mapped[str] = mapped_column(String(20), default="1.0")
    kill_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default="active")  # active|offboarded (OP20)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)   # OP08: blocks purge
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(30))
    password_hash: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Session(Base):
    """SC03: server-side session, HttpOnly cookie, no localStorage tokens."""

    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    user_id: Mapped[str] = mapped_column(String(40), index=True)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Engagement(Base):
    """DC02."""

    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(120))
    mode: Mapped[str] = mapped_column(String(20), default="passive")
    status: Mapped[str] = mapped_column(String(20), default="active")
    readiness_accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # AT20 SLA clock start
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScopeVersion(Base):
    """DC02 immutable approved scope; no wildcard expansion (E6/OP17)."""

    __tablename__ = "scope_versions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    roe_ref: Mapped[str] = mapped_column(String(200))
    sources_json: Mapped[dict] = mapped_column(JSON, default=dict)
    exclusions_json: Mapped[list] = mapped_column(JSON, default=list)
    check_ids_json: Mapped[list] = mapped_column(JSON, default=list)
    scope_hash: Mapped[str] = mapped_column(String(80))
    approved_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (UniqueConstraint("engagement_id", "version", name="uq_scope_version"),)


class Connector(Base):
    """Registered source (API27/28). Import connectors read signed fixture snapshots only."""

    __tablename__ = "connectors"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    connector_type: Mapped[str] = mapped_column(String(40))
    display_name: Mapped[str] = mapped_column(String(120))
    credential_ref: Mapped[str] = mapped_column(String(120), default="import:broker-ref")  # never a secret
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    preflight_state: Mapped[str] = mapped_column(String(20), default="not_run")  # AT24 readiness gate
    last_complete_sync: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_state: Mapped[str] = mapped_column(String(30), default="never_run")
    capability_manifest_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    """DC03. revision is used for optimistic concurrency on commands (API08)."""

    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    engagement_id: Mapped[str] = mapped_column(String(40), index=True)
    scope_version_id: Mapped[str] = mapped_column(String(40))
    epoch: Mapped[int] = mapped_column(Integer, default=1)
    parent_run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), default="passive")
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    kill_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    versions_json: Mapped[dict] = mapped_column(JSON, default=dict)
    budget_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (Index("ix_runs_tenant_state", "tenant_id", "state"),)


class Task(Base):
    """DC04 durable task attempt; unique (run,node,partition,input_hash) per EX08."""

    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    node: Mapped[str] = mapped_column(String(10))
    partition: Mapped[str] = mapped_column(String(60), default="-")
    input_hash: Mapped[str] = mapped_column(String(80), default="0")
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    lease_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    lease_expires: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deadline: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    result_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("run_id", "node", "partition", "input_hash", name="uq_logical_task"),
    )


class Snapshot(Base):
    """DC09: completeness is computed, never assumed; partial never implies deletion."""

    __tablename__ = "snapshots"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    source: Mapped[str] = mapped_column(String(40))
    connector_id: Mapped[str] = mapped_column(String(40))
    scope_hash: Mapped[str] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(20), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expected_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    seen_count: Mapped[int] = mapped_column(Integer, default=0)
    completeness: Mapped[float | None] = mapped_column(Float, nullable=True)
    page_errors_json: Mapped[list] = mapped_column(JSON, default=list)
    manifest_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Identity(Base):
    """DC05 canonical key tenant/provider/authority/native_id (EX08 unique)."""

    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    authority: Mapped[str] = mapped_column(String(80), default="default")
    native_id: Mapped[str] = mapped_column(String(200))
    display_name: Mapped[str] = mapped_column(String(200))  # untrusted text; render escaped
    id_type: Mapped[str] = mapped_column(String(40), default="service_identity")
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", "authority", "native_id", name="uq_canonical_identity"),
    )


class OwnershipAssertion(Base):
    """DC06: multiple assertions; verified owner separate from candidate; model never overwrites."""

    __tablename__ = "ownership_assertions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    identity_id: Mapped[str] = mapped_column(String(40), index=True)
    owner_email: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(30))
    source: Mapped[str] = mapped_column(String(60))
    purpose: Mapped[str] = mapped_column(String(300), default="")
    asserted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CredentialMeta(Base):
    """DC07: keyed HMAC fingerprint only; no raw key/token ever normalized."""

    __tablename__ = "credential_meta"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    identity_id: Mapped[str] = mapped_column(String(40), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="enabled")
    created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fingerprint_hmac: Mapped[str] = mapped_column(String(80))
    source: Mapped[str] = mapped_column(String(40))
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. rotation_policy_days


class GraphEdge(Base):
    """DC10 temporal edge; both endpoints same tenant; assurance from evidence."""

    __tablename__ = "graph_edges"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(40), index=True)
    src_id: Mapped[str] = mapped_column(String(40), index=True)
    dst_id: Mapped[str] = mapped_column(String(40), index=True)
    relationship: Mapped[str] = mapped_column(String(40))
    conditions_json: Mapped[dict] = mapped_column(JSON, default=dict)
    assurance: Mapped[str] = mapped_column(String(30), default="config")
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class EvidenceArtifact(Base):
    """DC15 signed manifest; sha256 over exact stored bytes; tamper must be detectable (AT17)."""

    __tablename__ = "evidence_artifacts"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    kind: Mapped[str] = mapped_column(String(40), default="observation")
    producer: Mapped[str] = mapped_column(String(80))
    object_version: Mapped[int] = mapped_column(Integer, default=1)
    content_json: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(80))
    signature: Mapped[str] = mapped_column(String(120))
    redaction_version: Mapped[str] = mapped_column(String(20), default="1.0")
    collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    retention_state: Mapped[str] = mapped_column(String(30), default="active")


class CheckResult(Base):
    """DC11 immutable execution record; fail without evidence cannot become a finding (EX04)."""

    __tablename__ = "check_results"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(40))
    check_id: Mapped[str] = mapped_column(String(20))
    check_version: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[str] = mapped_column(String(40))
    target_key: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(20))
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Finding(Base):
    """DC12: only the finding service writes these (EX09 writer separation)."""

    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    check_id: Mapped[str] = mapped_column(String(20))
    check_version: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[str] = mapped_column(String(40), index=True)
    target_key: Mapped[str] = mapped_column(String(240))
    dedup_key: Mapped[str] = mapped_column(String(240))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="undetermined", index=True)
    assurance: Mapped[str] = mapped_column(String(30), default="config_supported")
    workflow_status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    severity_rationale: Mapped[str] = mapped_column(Text, default="")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    assignee_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    exception_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    latest_result_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "dedup_key", name="uq_finding_dedup"),
        Index("ix_findings_triage", "tenant_id", "severity", "workflow_status", "updated_at"),
    )


class SeverityDecision(Base):
    """DC14: OPA-style deterministic decision persisted with policy version + input hash (AT12)."""

    __tablename__ = "severity_decisions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    finding_id: Mapped[str] = mapped_column(String(40), index=True)
    policy_version: Mapped[str] = mapped_column(String(20))
    input_hash: Mapped[str] = mapped_column(String(80))
    impact: Mapped[str | None] = mapped_column(String(20), nullable=True)
    exposure: Mapped[str | None] = mapped_column(String(20), nullable=True)
    effective_privilege: Mapped[str | None] = mapped_column(String(20), nullable=True)
    path_certainty: Mapped[str | None] = mapped_column(String(20), nullable=True)
    credential_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    decision: Mapped[str] = mapped_column(String(20))
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Proposal(Base):
    """DC16 proof proposal (dormant in pilot) and other approval-bound actions."""

    __tablename__ = "proposals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    kind: Mapped[str] = mapped_column(String(40), default="active_proof")
    template: Mapped[str] = mapped_column(String(80))
    template_version: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    expected_effects: Mapped[list] = mapped_column(JSON, default=list)
    rollback: Mapped[str] = mapped_column(String(300), default="")
    action_digest: Mapped[str] = mapped_column(String(80))
    scope_hash: Mapped[str] = mapped_column(String(80), default="")
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    execution_window_s: Mapped[int] = mapped_column(Integer, default=900)
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class Approval(Base):
    """DC17: two distinct humans for active proof; proposer cannot approve (SC05)."""

    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    proposal_id: Mapped[str] = mapped_column(String(40), index=True)
    proposal_digest: Mapped[str] = mapped_column(String(80))
    actor_id: Mapped[str] = mapped_column(String(40))
    actor_role: Mapped[str] = mapped_column(String(30))
    decision: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(500))
    policy_version: Mapped[str] = mapped_column(String(20), default="1.0")
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Report(Base):
    """DC19: released artifact immutable; signature bound to exact revision digest."""

    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    template: Mapped[str] = mapped_column(String(40), default="baseline_v1")
    content_json: Mapped[dict] = mapped_column(JSON, default=dict)
    claims_json: Mapped[list] = mapped_column(JSON, default=list)
    limitations_json: Mapped[list] = mapped_column(JSON, default=list)
    grounding_json: Mapped[dict] = mapped_column(JSON, default=dict)
    revision_digest: Mapped[str] = mapped_column(String(80), default="")
    created_by: Mapped[str] = mapped_column(String(40))
    reviewer_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    review_record: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentRecord(Base):
    """DC22 registry lifecycle + observed agents; delegation depth bounded."""

    __tablename__ = "agent_records"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    native_id: Mapped[str] = mapped_column(String(120))
    display_name: Mapped[str] = mapped_column(String(200))
    sponsor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(300), nullable=True)
    runtime: Mapped[str | None] = mapped_column(String(80), nullable=True)
    capabilities_json: Mapped[list] = mapped_column(JSON, default=list)
    parent_native_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    lifecycle: Mapped[str] = mapped_column(String(20), default="active")
    registered: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    registry_version: Mapped[int] = mapped_column(Integer, default=1)
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    __table_args__ = (UniqueConstraint("tenant_id", "native_id", name="uq_agent_native"),)


class ToolInvocation(Base):
    """DC21 gateway ledger: reserved/dispatched/completed/failed/unknown."""

    __tablename__ = "tool_invocations"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    invocation_id: Mapped[str] = mapped_column(String(60))
    tool: Mapped[str] = mapped_column(String(80))
    tool_version: Mapped[str] = mapped_column(String(80), default="pinned")
    args_hash: Mapped[str] = mapped_column(String(80), default="")
    policy_decision: Mapped[str] = mapped_column(String(20), default="allowed")
    approval_ref: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="reserved")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "invocation_id", name="uq_invocation"),)


class EventOutbox(Base):
    """DC18: outbox row committed in the same transaction as the mutation (OP05)."""

    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    run_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    type: Mapped[str] = mapped_column(String(60))
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "run_id", "sequence", name="uq_event_seq"),)


class AuditEntry(Base):
    """SC15 append-only audit with hash chain; verification walks the chain."""

    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    actor_id: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(80))
    object_type: Mapped[str] = mapped_column(String(40))
    object_id: Mapped[str] = mapped_column(String(80))
    detail_json: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(80), default="")
    entry_hash: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


_engine = None
_engine_lock = threading.Lock()
_SessionFactory = None


def get_engine():
    global _engine, _SessionFactory
    with _engine_lock:
        if _engine is None:
            url = get_settings().db_url
            _engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
            if url.startswith("sqlite"):
                @event.listens_for(_engine, "connect")
                def _fk_on(dbapi_conn, _):  # pragma: no cover
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA foreign_keys=ON")
                    cur.execute("PRAGMA journal_mode=WAL")
                    cur.execute("PRAGMA busy_timeout=30000")
                    cur.close()
                    # BEGIN IMMEDIATE: take the write lock at transaction start so the busy
                    # handler queues contention instead of failing on read->write upgrade
                    # (SQLAlchemy pysqlite serializable recipe; engine loop + API write concurrently)
                    dbapi_conn.isolation_level = None

                @event.listens_for(_engine, "begin")
                def _begin_immediate(dbapi_conn):  # pragma: no cover
                    dbapi_conn.exec_driver_sql("BEGIN IMMEDIATE")
            Base.metadata.create_all(_engine)
            _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


@contextmanager
def session_scope():
    """Transactional scope; commit on success, rollback on error (OP05)."""
    get_engine()
    s = _SessionFactory()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def reset_db() -> None:
    global _engine, _SessionFactory
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _SessionFactory = None


class RiskException(Base):
    """DC20 time-bounded risk acceptance. No permanent accept default; expiry reopens."""

    __tablename__ = "risk_exceptions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    finding_id: Mapped[str] = mapped_column(String(40), index=True)
    requester_id: Mapped[str] = mapped_column(String(40))
    justification: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending|accepted|denied|expired
    approver_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ExportJob(Base):
    """API23/DC21: audited export of a released artifact with server-side sanitization."""

    __tablename__ = "export_jobs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    report_id: Mapped[str] = mapped_column(String(40), index=True)
    format: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20), default="complete")
    sha256: Mapped[str] = mapped_column(String(80), default="")
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[str] = mapped_column(Text, default="")  # sanitized export content
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Subscription(Base):
    """S00 continuous monitoring: cadence-driven runs with drift signature (OP01/OP18)."""

    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    engagement_id: Mapped[str] = mapped_column(String(40), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cadence_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_signature: Mapped[str | None] = mapped_column(String(80), nullable=True)


class MachineToken(Base):
    """API25 scoped machine identity for CI evaluations (no interactive session)."""

    __tablename__ = "machine_tokens"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    label: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(80), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class OffboardLedger(Base):
    """OP08/OP20 tombstone ledger: purged objects stay enumerated to survive restores."""

    __tablename__ = "offboard_ledger"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    object_type: Mapped[str] = mapped_column(String(40))
    object_id: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(String(40))  # retention-purge|offboarding
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WebhookEvent(Base):
    """API26 inbound integration webhook ledger. tenant_id is the RESERVED value 'webhooks':
    the tenant is never taken from the payload (per-integration secrets and tenant mappings
    arrive with certified integrations). (integration, event_id) dedups replays."""

    __tablename__ = "webhook_events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, default="webhooks")
    integration: Mapped[str] = mapped_column(String(60))
    event_id: Mapped[str] = mapped_column(String(200))
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    accepted: Mapped[bool] = mapped_column(Boolean, default=True)
    reject_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)

    __table_args__ = (UniqueConstraint("integration", "event_id", name="uq_webhook_event"),)


class Ticket(Base):
    """API39/OP18 outbound ticket DRAFT only. status stays 'drafted'; real delivery to an
    external tracker is a certified integration (no external calls from this slice)."""

    __tablename__ = "tickets"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)
    finding_id: Mapped[str] = mapped_column(String(40), index=True)
    destination: Mapped[str] = mapped_column(String(60))
    subject: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="drafted", index=True)
    idempotency_key: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key", name="uq_ticket_idempotency"),)


class SupportGrant(Base):
    """SC23/AT33: time-boxed, revocable support elevation into ONE target tenant.
    Every tenant view under a grant writes a 'support.access' audit entry."""

    __tablename__ = "support_grants"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True)  # the TARGET tenant
    support_user_id: Mapped[str] = mapped_column(String(40), index=True)
    reason: Mapped[str] = mapped_column(String(500))
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
