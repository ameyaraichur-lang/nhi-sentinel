"""Deterministic check contract (AR11, Check Catalog sheet).

Checks are pure functions over a validated SnapshotView. They never touch customer
resources, never fetch network data, and must return one of the DC11 statuses with
evidence references for every non-pass outcome requiring support. Each check declares
the score dimension it feeds (PS06-PS08: one boolean control-set outcome per target).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts import CheckStatus
from ..core.repo import SnapshotView

DIMENSIONS = ("ownership", "credential_hygiene", "least_privilege", "lifecycle", "detection")


@dataclass
class CheckOutcome:
    target_id: str                      # canonical identity id or deterministic target key
    target_key: str                     # human-stable key (dedup input)
    status: CheckStatus
    evidence_refs: list[str] = field(default_factory=list)   # SnapshotView.artifacts ids
    facts: dict = field(default_factory=dict)
    reason: str | None = None


class Check:
    id: str = ""
    version: str = "1.0.0"
    title: str = ""
    description: str = ""
    dimension: str = ""                 # one of DIMENSIONS
    applies_to: tuple[str, ...] = ()    # sources whose snapshots it reads

    def run(self, view: SnapshotView) -> list[CheckOutcome]:
        raise NotImplementedError

    # helpers ------------------------------------------------------------------
    def outcome(self, *, target_id: str, target_key: str, status: CheckStatus,
                evidence_refs=None, facts=None, reason=None) -> CheckOutcome:
        if status in (CheckStatus.UNKNOWN, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE) and not reason:
            raise ValueError(f"{self.id}: {status.value} requires a reason (DC11)")
        if status == CheckStatus.FAIL and not (evidence_refs or facts):
            raise ValueError(f"{self.id}: fail requires evidence refs or facts (EX04)")
        return CheckOutcome(
            target_id=target_id, target_key=target_key, status=status,
            evidence_refs=list(evidence_refs or []), facts=dict(facts or {}), reason=reason,
        )

    def artifacts_for(self, view: SnapshotView, *kinds: str) -> list[str]:
        return sorted(a.id for a in view.artifacts.values() if a.kind in kinds)


REGISTRY: dict[str, Check] = {}


def register(cls: type[Check]) -> type[Check]:
    inst = cls()
    if not inst.id or inst.dimension not in DIMENSIONS:
        raise ValueError(f"check {cls.__name__} misconfigured (id/dimension)")
    REGISTRY[inst.id] = inst
    return cls


def enabled_checks(check_ids: list[str]) -> list[Check]:
    """Only certified, registered checks can run (AT15: unsupported domains are not runnable)."""
    out = []
    for cid in check_ids:
        if cid in REGISTRY:
            out.append(REGISTRY[cid])
    return out
