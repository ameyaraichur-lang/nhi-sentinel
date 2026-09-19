"""Control API part 1: auth, overview, engagements/scope, connectors, runs + SSE,
support elevation (SC23/AT33)."""
from __future__ import annotations

import asyncio
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..worker import engine
from ..contracts import RunState
from ..contracts.models import (
    EngagementCreate, LoginRequest, RunCommand, RunCreate, RunStop, ScopeVersionCreate,
)
from ..core.audit import append_audit
from ..core.auth import SESSION_COOKIE, login as do_login, logout, me_view
from ..core.db import (
    Connector, Engagement, Finding, Identity, Proposal, Report, Run, ScopeVersion,
    Session as DbSession, Snapshot, SupportGrant, Task, Tenant, new_id, session_scope, utcnow,
)
from ..core.events import replay, sse_format
from ..core.repo import scoped_get
from ..core.security import digest_of, sha256_hex
from .deps import guard, tenant_of, user_id

router = APIRouter(prefix="/v1")


# --- auth -----------------------------------------------------------------------

@router.post("/auth/login")
def api_login(body: LoginRequest, response: Response):
    token, csrf, user = do_login(body.email, body.password)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", path="/")
    append_audit(user.tenant_id, user.id, "auth.login", "user", user.id, {})
    from ..core.auth import me_view as _mv
    # build Me view directly (no request-scoped session needed beyond tenant name)
    from ..core.db import Tenant
    with session_scope() as s:
        tenant = s.get(Tenant, user.tenant_id)
    from ..core.auth import CAPABILITIES
    from ..contracts import Role
    return {
        "user_id": user.id, "email": user.email, "display_name": user.display_name,
        "role": user.role, "tenant_id": user.tenant_id,
        "tenant_name": tenant.name if tenant else "unknown", "csrf_token": csrf,
        "capabilities": sorted(CAPABILITIES.get(Role(user.role), set())),
    }


@router.post("/auth/logout")
def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        logout(sha256_hex(token))
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/me")
def api_me(principal=Depends(guard("read:overview"))):
    user, sess = principal
    return me_view(user, sess)


# --- overview (UI01 Mission Control) ---------------------------------------------

def _overview_payload(s, tid: str) -> dict:
    """UI01 Mission Control view for one tenant (shared with support elevation, SC23)."""
    runs = s.execute(select(Run).where(Run.tenant_id == tid)
                     .order_by(Run.created_at.desc()).limit(10)).scalars().all()
    sev_rows = s.execute(
        select(Finding.severity, func.count(Finding.id)).where(Finding.tenant_id == tid)
        .group_by(Finding.severity)).all()
    connectors = s.execute(select(Connector).where(Connector.tenant_id == tid)).scalars().all()
    identity_count = s.execute(
        select(func.count(Identity.id)).where(Identity.tenant_id == tid)).scalar() or 0
    reports_awaiting = s.execute(select(func.count(Report.id)).where(
        Report.tenant_id == tid, Report.status.in_(["draft", "in_review"]))).scalar() or 0
    proposals_pending = s.execute(select(func.count(Proposal.id)).where(
        Proposal.tenant_id == tid, Proposal.status == "pending")).scalar() or 0
    return {
        "tenant": {"id": tid, "synthetic": True},
        "runs": [{"run_id": r.id, "state": r.state, "mode": r.mode,
                  "created_at": r.created_at.isoformat() + "Z"} for r in runs],
        "findings_by_severity": {sev: n for sev, n in sev_rows},
        "connectors": [{"connector_id": c.id, "type": c.connector_type,
                        "name": c.display_name, "state": c.last_state,
                        "last_complete_sync": c.last_complete_sync.isoformat() + "Z"
                        if c.last_complete_sync else None} for c in connectors],
        "identity_count": identity_count,
        "reports_awaiting_release": reports_awaiting,
        "proposals_pending": proposals_pending,
    }


@router.get("/overview")
def api_overview(principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        return _overview_payload(s, tid)


# --- support elevation (SC23/AT33) --------------------------------------------------

class SupportGrantCreate(BaseModel):
    tenant_id: str
    minutes: int = Field(ge=5, le=240)
    reason: str = Field(min_length=3, max_length=500)


def _grant_active(grant: SupportGrant) -> bool:
    return grant.revoked_at is None and grant.expires_at > utcnow()


@router.post("/support-grants", status_code=201)
def api_create_support_grant(body: SupportGrantCreate,
                             principal=Depends(guard("support:elevate"))):
    """SC23: time-boxed support elevation into ONE tenant. Only the support role holds
    'support:elevate'; the grant is audited in the TARGET tenant's chain."""
    uid = user_id(principal)
    with session_scope() as s:
        target = s.get(Tenant, body.tenant_id)
        if target is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "tenant not found",
                                             "retryable": False})
        grant = SupportGrant(id=new_id("spt"), tenant_id=target.id, support_user_id=uid,
                             reason=body.reason[:500], granted_at=utcnow(),
                             expires_at=utcnow() + timedelta(minutes=body.minutes))
        s.add(grant)
        s.flush()
        append_audit(target.id, uid, "support.grant", "tenant", target.id,
                     {"minutes": body.minutes, "reason": body.reason[:200],
                      "grant_id": grant.id}, session=s)
        return {"grant_id": grant.id, "tenant_id": grant.tenant_id,
                "support_user_id": grant.support_user_id, "reason": grant.reason,
                "granted_at": grant.granted_at.isoformat() + "Z",
                "expires_at": grant.expires_at.isoformat() + "Z", "status": "active"}


@router.get("/support/tenant-overview")
def api_support_tenant_overview(tenant_id: str, principal=Depends(guard("support:elevate"))):
    """SC23/AT33: support view of one tenant's overview. Requires the support role AND an
    active, unexpired, non-revoked SupportGrant for that tenant; every call (granted or
    denied) writes a 'support.access' audit entry into the target tenant's chain."""
    uid = user_id(principal)
    with session_scope() as s:
        target = s.get(Tenant, tenant_id)
        grants = s.execute(select(SupportGrant).where(
            SupportGrant.tenant_id == tenant_id,
            SupportGrant.support_user_id == uid)).scalars().all() if target else []
        allowed = target is not None and any(_grant_active(g) for g in grants)
    if target is None:
        raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "tenant not found",
                                         "retryable": False})
    if not allowed:
        # committed in its own transaction BEFORE raising (a raise inside session_scope
        # would roll the denial record back - see api_attempt_execution for the pattern)
        append_audit(tenant_id, uid, "support.access", "tenant", tenant_id,
                     {"granted": False, "why": "no active support grant"})
        raise HTTPException(403, detail={"code": "SUPPORT_GRANT_REQUIRED",
                                         "message": "Support access requires an active grant "
                                                    "for this tenant (SC23).",
                                         "retryable": False})
    with session_scope() as s:
        payload = _overview_payload(s, tenant_id)
        append_audit(tenant_id, uid, "support.access", "tenant", tenant_id,
                     {"granted": True}, session=s)
        return payload


# --- engagements / scope (API02/03) ------------------------------------------------

@router.post("/engagements", status_code=201)
def api_create_engagement(body: EngagementCreate, principal=Depends(guard("engagement:create"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        eng = Engagement(id=new_id("eng"), tenant_id=tid, name=body.name, mode=body.mode,
                         created_by=uid)
        s.add(eng)
        append_audit(tid, uid, "engagement.create", "engagement", eng.id, {"name": body.name}, session=s)
        return {"engagement_id": eng.id, "version": 0, "status": eng.status}


@router.get("/engagements")
def api_list_engagements(principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Engagement).where(Engagement.tenant_id == tid)).scalars().all()
        return [{"engagement_id": e.id, "name": e.name, "mode": e.mode, "status": e.status}
                for e in rows]


@router.get("/engagements/{engagement_id}")
def api_get_engagement(engagement_id: str, principal=Depends(guard("read:overview"))):
    """AT20/OF03: readiness acceptance time + baseline latency disclosure."""
    tid = tenant_of(principal)
    with session_scope() as s:
        eng = scoped_get(s, Engagement, tid, engagement_id)
        latency = None
        if eng.readiness_accepted_at:
            run = s.execute(select(Run).where(
                Run.tenant_id == tid, Run.engagement_id == eng.id,
                Run.finished_at.is_not(None))
                .order_by(Run.finished_at)).scalars().first()
            if run is not None:
                latency = round((run.finished_at - eng.readiness_accepted_at).total_seconds() / 3600.0, 2)
        return {"engagement_id": eng.id, "name": eng.name, "mode": eng.mode,
                "status": eng.status,
                "readiness_accepted_at": eng.readiness_accepted_at.isoformat() + "Z"
                if eng.readiness_accepted_at else None,
                "baseline_latency_hours": latency,
                "note": "clock starts at accepted readiness; pauses disclosed separately (AT20)"}


@router.post("/engagements/{engagement_id}/scope-versions", status_code=201)
def api_create_scope(engagement_id: str, body: ScopeVersionCreate,
                     principal=Depends(guard("scope:create"))):
    tid, uid = tenant_of(principal), user_id(principal)
    from ..checks.base import REGISTRY
    unknown = [c for c in body.check_ids if c not in REGISTRY]
    if unknown:
        raise HTTPException(422, detail={"code": "UNCERTIFIED_CHECKS",
                                         "message": f"checks not certified: {unknown}",
                                         "retryable": False})
    with session_scope() as s:
        eng = scoped_get(s, Engagement, tid, engagement_id)
        current = s.execute(select(func.max(ScopeVersion.version)).where(
            ScopeVersion.engagement_id == eng.id)).scalar() or 0
        scope_payload = {"sources": body.sources, "exclusions": body.exclusions}
        sv = ScopeVersion(
            id=new_id("scv"), tenant_id=tid, engagement_id=eng.id, version=current + 1,
            roe_ref=body.roe_ref[:200], sources_json=scope_payload,
            exclusions_json=body.exclusions, check_ids_json=body.check_ids,
            scope_hash=digest_of(scope_payload), approved_by=uid, approved_at=utcnow(),
            created_by=uid)
        s.add(sv)
        append_audit(tid, uid, "scope.version", "scope", sv.id,
                     {"version": sv.version, "sources": body.sources}, session=s)
        return {"scope_version_id": sv.id, "version": sv.version, "scope_hash": sv.scope_hash,
                "approved": True}


# --- connectors (API04/05) ----------------------------------------------------------

@router.get("/connectors")
def api_list_connectors(principal=Depends(guard("read:connectors"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Connector).where(Connector.tenant_id == tid)).scalars().all()
        return [{"connector_id": c.id, "type": c.connector_type, "name": c.display_name,
                 "enabled": c.enabled, "state": c.last_state,
                 "last_complete_sync": c.last_complete_sync.isoformat() + "Z"
                 if c.last_complete_sync else None,
                 "revision": c.revision,
                 "capabilities": sorted(c.capability_manifest_json.get("read", []))} for c in rows]


@router.post("/connectors/{connector_id}/preflight")
def api_connector_preflight(connector_id: str, principal=Depends(guard("connector:preflight"))):
    """Read-only connectivity/capability test: fixture presence + schema validation (API05)."""
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        conn = scoped_get(s, Connector, tid, connector_id)
    from ..connectors import get_adapter
    from ..connectors.base import CollectionContext, FixtureError
    try:
        adapter = get_adapter(conn.connector_type, CollectionContext(
            tenant_id=tid, run_id="preflight", scope_hash="preflight",
            connector_id=conn.id, source=conn.connector_type))
        result, page_errors = adapter.collect()
    except FixtureError as exc:
        with session_scope() as s:
            live = s.get(Connector, conn.id)
            live.last_state = "preflight_failed"
            live.preflight_state = "failed"
        append_audit(tid, uid, "connector.preflight", "connector", conn.id, {"ok": False})
        return {"connector_id": conn.id, "ok": False, "error": str(exc)[:300]}
    with session_scope() as s:
        live = s.get(Connector, conn.id)
        live.preflight_state = "passed"
        # AT20/OF02: the baseline SLA clock starts when every enabled connector is ready
        remaining = s.execute(select(func.count(Connector.id)).where(
            Connector.tenant_id == tid, Connector.enabled.is_(True),
            Connector.preflight_state != "passed")).scalar()
        if not remaining:
            for eng in s.execute(select(Engagement).where(
                    Engagement.tenant_id == tid, Engagement.status == "active",
                    Engagement.readiness_accepted_at.is_(None))).scalars():
                eng.readiness_accepted_at = utcnow()
    append_audit(tid, uid, "connector.preflight", "connector", conn.id,
                 {"ok": True, "identities": len(result.identities)})
    return {"connector_id": conn.id, "ok": True, "source": conn.connector_type,
            "identities_seen": len(result.identities), "page_errors": page_errors,
            "note": "read-only preflight against approved import payload (no live calls)"}


# --- runs (API06-10) ------------------------------------------------------------------

@router.post("/runs", status_code=202)
def api_create_run(body: RunCreate, principal=Depends(guard("run:create"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        eng = scoped_get(s, Engagement, tid, body.engagement_id)
        sv = s.execute(select(ScopeVersion).where(
            ScopeVersion.tenant_id == tid, ScopeVersion.engagement_id == eng.id,
            ScopeVersion.version == body.scope_version)).scalars().first()
        if sv is None:
            raise HTTPException(404, detail={"code": "NOT_FOUND",
                                             "message": "scope version not found", "retryable": False})
        if body.mode != "passive":
            raise HTTPException(422, detail={"code": "MODE_UNSUPPORTED",
                                             "message": "Active mode is not certified in pilot (D06).",
                                             "retryable": False})
        # AT24 readiness gate: collection may not start past a failed/missing preflight
        approved_sources = sv.sources_json.get("sources", [])
        not_ready = [c.connector_type for c in s.execute(
            select(Connector).where(Connector.tenant_id == tid,
                                    Connector.connector_type.in_(approved_sources))).scalars()
            if c.preflight_state != "passed"]
        if not_ready:
            raise HTTPException(422, detail={
                "code": "PREFLIGHT_REQUIRED",
                "message": "Run blocked: connectors must pass read-only preflight first (AT24).",
                "retryable": False,
                "details": {"connectors": not_ready}})
        # no hidden scope expansion (OP17): request lists must be subsets of approved scope
        unknown_sources = [c for c in body.connector_ids if c not in approved_sources]
        unknown_checks = [c for c in body.check_ids if c not in sv.check_ids_json]
        if unknown_sources or unknown_checks:
            raise HTTPException(422, detail={
                "code": "OUT_OF_SCOPE",
                "message": "Requested connectors/checks are outside the approved scope.",
                "retryable": False,
                "details": {"unknown_sources": unknown_sources,
                            "unknown_checks": unknown_checks}})
        run = Run(id=new_id("run"), tenant_id=tid, engagement_id=eng.id, scope_version_id=sv.id,
                  epoch=1, mode=body.mode, state=RunState.QUEUED.value,
                  versions_json={"engine": "1.0.0", "sev_policy": "sev-baseline-1.0.0",
                                 "score_policy": "score-1.0.0"},
                  budget_json={"model_calls": 0, "fanout_per_run": 4, **body.budget},
                  created_by=uid)
        s.add(run)
        s.flush()
        run_id = run.id
        append_audit(tid, uid, "run.create", "run", run_id, {"mode": body.mode}, session=s)
    engine.create_run_tasks(tid, run_id)
    with session_scope() as s:
        run = s.get(Run, run_id)
        return {"run_id": run_id, "state": run.state, "revision": run.revision}


@router.get("/runs")
def api_list_runs(principal=Depends(guard("read:runs"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Run).where(Run.tenant_id == tid)
                         .order_by(Run.created_at.desc())).scalars().all()
        return [{"run_id": r.id, "engagement_id": r.engagement_id, "state": r.state,
                 "mode": r.mode, "epoch": r.epoch, "created_at": r.created_at.isoformat() + "Z",
                 "finished_at": r.finished_at.isoformat() + "Z" if r.finished_at else None}
                for r in rows]


@router.get("/runs/{run_id}")
def api_get_run(run_id: str, principal=Depends(guard("read:runs"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        run = scoped_get(s, Run, tid, run_id)
        tasks = s.execute(select(Task).where(Task.run_id == run_id)
                          .order_by(Task.created_at)).scalars().all()
        snaps = s.execute(select(Snapshot).where(Snapshot.tenant_id == tid,
                                                 Snapshot.run_id == run_id)).scalars().all()
        return {
            "run_id": run.id, "state": run.state, "mode": run.mode, "epoch": run.epoch,
            "revision": run.revision, "kill_requested": run.kill_requested,
            "engagement_id": run.engagement_id,
            "error": run.error, "versions": run.versions_json, "budget": run.budget_json,
            "created_at": run.created_at.isoformat() + "Z",
            "finished_at": run.finished_at.isoformat() + "Z" if run.finished_at else None,
            "tasks": [{"task_id": t.id, "node": t.node, "partition": t.partition,
                       "state": t.state, "attempt": t.attempt, "skip_reason": t.skip_reason,
                       "error": t.error} for t in tasks],
            "coverage": [{"snapshot_id": sn.id, "source": sn.source, "state": sn.state,
                          "seen": sn.seen_count, "expected": sn.expected_count,
                          "completeness": sn.completeness, "page_errors": sn.page_errors_json}
                         for sn in snaps],
        }


@router.post("/runs/{run_id}/commands")
def api_run_command(run_id: str, body: RunCommand, request: Request,
                    principal=Depends(guard("run:command"))):
    tid, uid = tenant_of(principal), user_id(principal)
    expected = request.headers.get("If-Match")
    if expected is None:
        raise HTTPException(428, detail={"code": "PRECONDITION_REQUIRED",
                                         "message": "If-Match revision required.", "retryable": False})
    out = engine.run_command(tid, run_id, body.command, int(expected), uid)
    append_audit(tid, uid, f"run.{body.command}", "run", run_id, {"reason": body.reason})
    return out


@router.post("/runs/{run_id}/stop")
def api_run_stop(run_id: str, body: RunStop, principal=Depends(guard("run:stop"))):
    tid, uid = tenant_of(principal), user_id(principal)
    out = engine.emergency_stop(tid, run_id, uid)
    append_audit(tid, uid, "run.stop", "run", run_id, {"reason": body.reason})
    return out


@router.get("/runs/{run_id}/events")
async def api_run_events(run_id: str, request: Request,
                         principal=Depends(guard("read:runs")),
                         last_event_id: str | None = Query(default=None, alias="Last-Event-ID")):
    """API10/UX16: tenant-bound SSE with sequence replay; replay mutates UI views only (EX06)."""
    tid = tenant_of(principal)
    cursor = int(last_event_id or request.headers.get("last-event-id") or 0)

    async def stream():
        seq = cursor
        idle = 0
        while idle < 1200:
            if await request.is_disconnected():
                return
            rows = replay(tid, run_id, after_sequence=seq)
            if rows:
                idle = 0
                for ev in rows:
                    yield sse_format(ev)
                    seq = ev.sequence
            else:
                idle += 1
                yield ": keep-alive\n\n"
                await asyncio.sleep(0.5)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
