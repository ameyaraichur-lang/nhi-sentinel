"""Typed request/response contracts (pydantic). Wire shapes mirror DC01-DC22 and API Contracts sheet."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import (
    AgentLifecycle, Assurance, CheckStatus, RunState, Severity, WorkflowStatus,
)


class ORMBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- API01 -----------------------------------------------------------------
class Me(ORMBase):
    user_id: str
    email: str
    display_name: str
    role: str
    tenant_id: str
    tenant_name: str
    csrf_token: str
    capabilities: list[str]


class LoginRequest(BaseModel):
    email: str
    password: str


# --- API02 engagements / scope ---------------------------------------------
class EngagementCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    mode: Literal["passive"] = "passive"


class ScopeVersionCreate(BaseModel):
    roe_ref: str = Field(min_length=3, max_length=200)
    sources: list[str] = Field(min_length=1)
    check_ids: list[str] = Field(min_length=1)
    exclusions: list[str] = []
    change_rationale: str = Field(min_length=3, max_length=500)


# --- API06 runs --------------------------------------------------------------
class RunCreate(BaseModel):
    engagement_id: str
    scope_version: int
    connector_ids: list[str] = []   # optional subset filter; approved scope is authoritative
    check_ids: list[str] = []
    mode: Literal["passive"] = "passive"
    budget: dict[str, int] = Field(default_factory=dict)


class RunCommand(BaseModel):
    command: Literal["pause", "resume", "cancel"]
    reason: str = Field(min_length=3, max_length=300)


class RunStop(BaseModel):
    reason: str = Field(min_length=3, max_length=300)


# --- API14/15 findings -------------------------------------------------------
class FindingPatch(BaseModel):
    workflow_status: WorkflowStatus | None = None
    assignee_id: str | None = None
    reason: str = Field(min_length=3, max_length=500)


class FindingOut(ORMBase):
    finding_id: str
    check_id: str
    check_version: str
    target_id: str
    target_key: str
    title: str
    severity: Severity
    assurance: Assurance
    workflow_status: WorkflowStatus
    dedup_key: str
    revision: int
    occurrence_count: int
    summary: str
    evidence_refs: list[str]
    facts: dict[str, Any]
    severity_rationale: str
    assignee_id: str | None
    first_seen: datetime
    updated_at: datetime


# --- API18/19 approvals ------------------------------------------------------
class ApprovalRequest(BaseModel):
    proposal_id: str
    proposal_digest: str
    decision: Literal["approve", "deny"]
    reason: str = Field(min_length=3, max_length=500)
    reauth_password: str  # SC05/UX10: sensitive approval requires fresh re-authentication


# --- API21/22 reports --------------------------------------------------------
class ReportCreate(BaseModel):
    run_id: str
    template: Literal["baseline_v1"] = "baseline_v1"


class Claim(BaseModel):
    claim_id: str
    section: str
    text: str
    evidence_refs: list[str] = []
    finding_ids: list[str] = []
    ai_generated: bool = False


class ReleaseRequest(BaseModel):
    revision_digest: str
    review_record: str = Field(min_length=10, max_length=1000)
    reauth_password: str


class ClaimFeedback(BaseModel):
    claim_id: str
    reference: str = Field(min_length=3, max_length=500)
    comment: str = Field(min_length=3, max_length=1000)


# --- API29 ownership ---------------------------------------------------------
class OwnerAttestation(BaseModel):
    owner_email: str
    role: Literal["business", "technical"]
    purpose: str = Field(min_length=3, max_length=300)
    review_expiry_days: int = Field(default=180, ge=30, le=365)


# --- API30/32 agents ---------------------------------------------------------
class AgentCommand(BaseModel):
    command: Literal["approve_activation", "suspend", "retire"]
    reason: str = Field(min_length=3, max_length=300)
    registry_version: int


# --- Envelopes ----------------------------------------------------------------
class ErrorEnvelope(BaseModel):
    """EX07 error envelope: no stack traces, no secrets, correlation id."""

    error: dict[str, Any]


class EventEnvelope(BaseModel):
    """DC18/EX06 SSE event. UI replay updates views only, never invokes tools."""

    schema_version: str = "1.0"
    event_id: str
    tenant_id: str
    run_id: str
    task_id: str | None = None
    sequence: int
    type: str
    timestamp: datetime
    payload: dict[str, Any]


# --- Score (PS06-PS11) ---------------------------------------------------------
class DimensionScore(ORMBase):
    dimension: str
    weight: float
    eligible: int
    assessed: int
    passing: int
    pass_rate: float | None
    completeness: float | None
    status: Literal["measured", "unavailable"]
    unavailable_reason: str | None = None


class ScoreCard(ORMBase):
    run_id: str
    policy_version: str
    dimensions: list[DimensionScore]
    observed_scope_score: float | None
    aggregate_status: Literal["measured", "unavailable"]
    aggregate_reason: str | None = None
    weights_total: float
