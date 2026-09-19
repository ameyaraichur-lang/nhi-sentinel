"""Canonical enums and state machines (Data Contracts DC01-DC22, Contract Examples EX01/EX02)."""
from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """SC04 role model (viewer..tenant_admin). Platform Admin has no automatic evidence access."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    APPROVER = "approver"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"
    TENANT_ADMIN = "tenant_admin"
    SUPPORT = "support"  # SC23/AT33: platform support; no read caps without an audited grant


class RunState(StrEnum):
    """DC03 run states / EX01 transitions. Terminal: cancelled, partial, succeeded, failed."""

    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked"
    WAITING_APPROVAL = "waiting_approval"
    PAUSE_REQUESTED = "pause_requested"
    PAUSED = "paused"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    PARTIAL = "partial"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


RUN_TERMINAL = {RunState.CANCELLED, RunState.PARTIAL, RunState.SUCCEEDED, RunState.FAILED}

# EX01 legal transitions
RUN_TRANSITIONS: dict[RunState, set[RunState]] = {
    RunState.QUEUED: {RunState.RUNNING, RunState.CANCELLED},
    RunState.RUNNING: {
        RunState.BLOCKED, RunState.WAITING_APPROVAL, RunState.PAUSE_REQUESTED,
        RunState.CANCEL_REQUESTED, RunState.PARTIAL, RunState.SUCCEEDED, RunState.FAILED,
    },
    RunState.BLOCKED: {RunState.QUEUED, RunState.CANCELLED, RunState.FAILED},
    RunState.WAITING_APPROVAL: {RunState.QUEUED, RunState.PARTIAL, RunState.SUCCEEDED, RunState.CANCELLED},
    RunState.PAUSE_REQUESTED: {RunState.PAUSED, RunState.CANCEL_REQUESTED},
    RunState.PAUSED: {RunState.QUEUED, RunState.CANCELLED},
    RunState.CANCEL_REQUESTED: {RunState.CANCELLED},
}


class TaskState(StrEnum):
    """EX02 task/attempt states. Max attempts bounded by DC04."""

    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    RETRY_SCHEDULED = "retry_scheduled"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


TASK_TERMINAL = {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.UNKNOWN, TaskState.SKIPPED, TaskState.CANCELLED}


class CheckStatus(StrEnum):
    """DC11 result states. Unknown/error require a reason and are never pass."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


STATUSES_REQUIRING_REASON = {CheckStatus.UNKNOWN, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE}


class Severity(StrEnum):
    """PS02-PS04 bands. Severity is a deterministic policy decision, never an LLM output."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNDETERMINED = "undetermined"


class Assurance(StrEnum):
    """DC13 evidence assurance, separate from lifecycle (PS01)."""

    CONFIG_SUPPORTED = "config_supported"
    TEST_SUPPORTED = "test_supported"
    INCONCLUSIVE = "inconclusive"
    CONTRADICTED = "contradicted"


class WorkflowStatus(StrEnum):
    """DC13/PS15 lifecycle. Disappearing from a partial scan cannot close a finding."""

    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    REOPENED = "reopened"


class SnapshotState(StrEnum):
    """DC09 snapshot lifecycle; partial collection never implies deletion (G25/AT08)."""

    PENDING = "pending"
    COMPLETE = "complete"
    PARTIAL = "partial"
    INVALID = "invalid"


class ReportStatus(StrEnum):
    """DC19 report lifecycle."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    RELEASED = "released"
    SUPERSEDED = "superseded"


class ProposalStatus(StrEnum):
    """DC16/DC22 approval proposal lifecycle (dormant active proof in pilot)."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REDEEMED = "redeemed"
    REVOKED = "revoked"


class AgentLifecycle(StrEnum):
    """DC22 agent registry lifecycle."""

    DRAFTED = "drafted"
    APPROVED = "approved"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class EdgeType(StrEnum):
    """DC10 graph edge vocabulary."""

    OWNS = "owns"
    AUTHENTICATES_AS = "authenticates_as"
    CAN_ASSUME = "can_assume"
    CAN_ACCESS = "can_access"
    DELEGATES_TO = "delegates_to"
    ISSUED_BY = "issued_by"


class ConnectorType(StrEnum):
    """CN01-CN16 release classes; pilot = import/read-only passive."""

    AWS_IAM = "aws_iam"                # CN01
    ENTRA = "entra"                    # CN02
    GITHUB = "github"                  # CN03
    AGENT_REGISTRY = "agent_registry"  # CN04 signed JSON import
    SECRET_SCANNER = "secret_scanner"  # CN05 optional offline scan
