"""CI gate (API25, AT29) and S00 continuous scheduler (OP01/OP18, B30).

CI verdicts: fail on new blocking evaluated findings; unknown (fail-closed for protected
deployments) when coverage is partial or the latest run is not finalized; pass otherwise.
Scheduler: cadence-driven runs per engagement subscription; successful no-change scans are
recorded quietly; drift raises a signature event (OP18)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from .contracts import RunState
from .core.db import (
    Engagement, Finding, MachineToken, Run, ScopeVersion, Snapshot, Subscription,
    new_id, session_scope, utcnow,
)
from .core.repo import TenantViolation
from .worker import engine

BLOCKING_SEVERITIES = ("critical", "high")


# --- CI gate --------------------------------------------------------------------------

def resolve_machine_token(token: str) -> MachineToken:
    from .core.security import sha256_hex
    with session_scope() as s:
        mt = s.execute(select(MachineToken).where(
            MachineToken.token_hash == sha256_hex(token),
            MachineToken.enabled.is_(True))).scalars().first()
        if mt is None:
            raise TenantViolation("machine token")
        s.expunge(mt)
        return mt


def evaluate(tenant_id: str, *, since=None, protected: bool = True) -> dict:
    with session_scope() as s:
        run = s.execute(select(Run).where(
            Run.tenant_id == tenant_id,
            Run.state.in_([RunState.PARTIAL.value, RunState.SUCCEEDED.value,
                           RunState.WAITING_APPROVAL.value]))
            .order_by(Run.created_at.desc())).scalars().first()
        if run is None:
            return {"verdict": "unknown", "reason": "no finalized run available",
                    "protected": protected, "blocking_findings": []}
        snaps = s.execute(select(Snapshot).where(
            Snapshot.tenant_id == tenant_id, Snapshot.run_id == run.id)).scalars().all()
        blocking = s.execute(select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.run_id == run.id,
            Finding.severity.in_(BLOCKING_SEVERITIES),
            Finding.workflow_status.in_(["open", "reopened", "triaged"]))).scalars().all()
        if since is not None:
            blocking = [f for f in blocking if f.first_seen and f.first_seen > since]
        partial = [sn.source for sn in snaps if sn.state == "partial"]
        if blocking:
            return {"verdict": "fail", "protected": protected,
                    "evaluated_run_id": run.id,
                    "blocking_findings": [{"finding_id": f.id, "check_id": f.check_id,
                                           "severity": f.severity, "target_key": f.target_key}
                                          for f in blocking],
                    "reason": f"{len(blocking)} new blocking evaluated findings (AT29)"}
        if partial:
            if protected:
                return {"verdict": "unknown", "protected": protected,
                        "evaluated_run_id": run.id, "partial_sources": partial,
                        "blocking_findings": [],
                        "reason": "coverage partial; protected deployments default fail-closed"}
            return {"verdict": "pass", "protected": protected, "evaluated_run_id": run.id,
                    "partial_sources": partial, "blocking_findings": [],
                    "reason": "no blocking findings; unknown tolerated by repo-owner config"}
        return {"verdict": "pass", "protected": protected, "evaluated_run_id": run.id,
                "blocking_findings": [], "reason": "no new blocking evaluated findings"}


# --- S00 scheduler ----------------------------------------------------------------------

def create_subscription(session, *, tenant_id: str, engagement_id: str, cadence_hours: int = 24) -> Subscription:
    eng = session.get(Engagement, engagement_id)
    if eng is None or eng.tenant_id != tenant_id:
        raise TenantViolation(engagement_id)
    sub = Subscription(id=new_id("sub"), tenant_id=tenant_id, engagement_id=engagement_id,
                       enabled=True, cadence_hours=max(1, cadence_hours), last_run_at=utcnow())
    session.add(sub)
    session.flush()
    return sub


def run_due_subscriptions(now=None) -> int:
    """One scheduler pass: kick a new epoch run for every due subscription (S00)."""
    now = now or utcnow()
    started = 0
    with session_scope() as s:
        subs = s.execute(select(Subscription).where(Subscription.enabled.is_(True))).scalars().all()
        s.expunge_all()
    for sub in subs:
        due_at = (sub.last_run_at or now) + timedelta(hours=sub.cadence_hours)
        if now < due_at:
            continue
        with session_scope() as s:
            live = s.get(Subscription, sub.id)
            if live is None or not live.enabled:
                continue
            eng = s.get(Engagement, live.engagement_id)
            if eng is None:
                continue
            sv = s.execute(select(ScopeVersion).where(
                ScopeVersion.tenant_id == eng.tenant_id,
                ScopeVersion.engagement_id == eng.id)
                .order_by(ScopeVersion.version.desc())).scalars().first()
            if sv is None or sv.approved_at is None:
                continue  # readiness gate: schedule stays quiet until scope approved (AT24)
            prev_epoch = 0
            if live.last_run_id:
                prev = s.get(Run, live.last_run_id)
                prev_epoch = prev.epoch if prev else 0
            run = Run(id=new_id("run"), tenant_id=eng.tenant_id, engagement_id=eng.id,
                      scope_version_id=sv.id, epoch=prev_epoch + 1,
                      parent_run_id=live.last_run_id, mode="passive",
                      state=RunState.QUEUED.value, versions_json={"engine": "1.0.0"},
                      budget_json={}, created_by="system:s00")
            s.add(run)
            s.flush()
            live.last_run_id = run.id
            live.last_run_at = utcnow()
            run_id, tenant_id = run.id, eng.tenant_id
        engine.create_run_tasks(tenant_id, run_id)
        started += 1
    return started


def record_signatures() -> int:
    """OP18: successful no-change scans are recorded quietly; drift raises a signature."""
    events = 0
    with session_scope() as s:
        subs = s.execute(select(Subscription).where(Subscription.enabled.is_(True))).scalars().all()
        s.expunge_all()
    for sub in subs:
        with session_scope() as s:
            live = s.get(Subscription, sub.id)
            if live is None:
                continue
            # latest evaluated run for this engagement: parked at the gate or finalized
            run = s.execute(select(Run).where(
                Run.tenant_id == live.tenant_id, Run.engagement_id == live.engagement_id,
                Run.state.in_([RunState.WAITING_APPROVAL.value, RunState.PARTIAL.value,
                               RunState.SUCCEEDED.value]))
                .order_by(Run.created_at.desc())).scalars().first()
            if run is None:
                continue
            findings = s.execute(select(Finding).where(
                Finding.tenant_id == live.tenant_id, Finding.run_id == run.id)
                .order_by(Finding.dedup_key)).scalars().all()
            signature = __import__("hashlib").sha256(
                "|".join(f.dedup_key for f in findings).encode()).hexdigest()[:32]
            if live.last_signature == signature:
                continue
            from .core.events import emit
            is_first = live.last_signature is None
            emit(s, live.tenant_id, run.id,
                 "run.drift" if not is_first else "run.no_change",
                 {"signature": signature, "findings": len(findings)})
            live.last_signature = signature
            events += 1
    return events
