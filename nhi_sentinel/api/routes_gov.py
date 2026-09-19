"""Control API part 3: governance surfaces — exceptions (API17/40), exports (API23),
subscriptions (S00), CI evaluations (API25), assistant (API24), offboarding (OP20)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..assistant import answer as assistant_answer
from ..exports import build_export
from ..governance import (
    create_exception, decide_exception, expire_exceptions, offboard_tenant, purge_expired,
)
from ..scheduler import create_subscription, evaluate, record_signatures, run_due_subscriptions
from ..core.audit import append_audit
from ..core.db import (
    Finding, RiskException, Run, ScopeVersion, Tenant, User, new_id, session_scope, utcnow,
)
from ..core.repo import TenantViolation
from ..core.security import sha256_hex
from .deps import guard, tenant_of, user_id

router = APIRouter(prefix="/v1")


class ExceptionCreate(BaseModel):
    finding_id: str
    justification: str = Field(min_length=10, max_length=2000)
    compensating_controls: str = Field(default="", max_length=2000)
    expiry_days: int = Field(default=90, ge=30, le=365)


class ExceptionDecision(BaseModel):
    decision: str  # accept|deny
    reason: str = Field(min_length=3, max_length=1000)


class ExportCreate(BaseModel):
    report_id: str
    format: str = "csv"  # csv|json


class SubscriptionCreate(BaseModel):
    engagement_id: str
    cadence_hours: int = Field(default=24, ge=1, le=24 * 30)


class AssistantQuery(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    object_refs: list[dict] = []


class OffboardRequest(BaseModel):
    confirmation: str  # exact tenant name
    reason: str = Field(min_length=3, max_length=500)


def _exception_out(e: RiskException) -> dict:
    return {"exception_id": e.id, "finding_id": e.finding_id,
            "justification": e.justification, "compensating_controls": e.compensating_controls,
            "status": e.status, "requester_id": e.requester_id, "approver_id": e.approver_id,
            "decision_reason": e.decision_reason,
            "expires_at": e.expires_at.isoformat() + "Z",
            "created_at": e.created_at.isoformat() + "Z"}


@router.post("/exceptions", status_code=201)
def api_create_exception(body: ExceptionCreate, principal=Depends(guard("finding:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        try:
            exc = create_exception(s, tenant_id=tid, finding_id=body.finding_id,
                                   requester_id=uid, justification=body.justification,
                                   compensating_controls=body.compensating_controls,
                                   expiry_days=body.expiry_days)
        except ValueError as exc_:
            raise HTTPException(422, detail={"code": "INVALID_STATE", "message": str(exc_),
                                             "retryable": False})
        except TenantViolation:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        append_audit(tid, uid, "exception.create", "exception", exc.id,
                     {"finding": body.finding_id, "expiry_days": body.expiry_days}, session=s)
        return _exception_out(exc)


@router.get("/exceptions")
def api_list_exceptions(status: str | None = None, principal=Depends(guard("read:findings"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        q = select(RiskException).where(RiskException.tenant_id == tid)
        if status:
            q = q.where(RiskException.status == status)
        rows = s.execute(q.order_by(RiskException.created_at.desc())).scalars().all()
        s.expunge_all()
        return [_exception_out(e) for e in rows]


@router.post("/exceptions/{exception_id}/decisions")
def api_decide_exception(exception_id: str, body: ExceptionDecision,
                         principal=Depends(guard("approval:decide"))):
    tid, uid = tenant_of(principal), user_id(principal)
    if body.decision not in ("accept", "deny"):
        raise HTTPException(422, detail={"code": "VALIDATION", "message": "decision must be accept|deny",
                                         "retryable": False})
    with session_scope() as s:
        try:
            exc = decide_exception(s, tenant_id=tid, exception_id=exception_id,
                                   decider_id=uid, decision=body.decision, reason=body.reason)
        except PermissionError as exc_:
            raise HTTPException(403, detail={"code": "SELF_APPROVAL", "message": str(exc_),
                                             "retryable": False})
        except ValueError as exc_:
            raise HTTPException(422, detail={"code": "INVALID_STATE", "message": str(exc_),
                                             "retryable": False})
        except TenantViolation:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        append_audit(tid, uid, "exception.decision", "exception", exc.id,
                     {"decision": body.decision}, session=s)
        out = _exception_out(exc)
        finding = s.get(Finding, exc.finding_id)
        out["finding_workflow_status"] = finding.workflow_status if finding else None
        return out


# --- exports (API23) ------------------------------------------------------------------

@router.post("/exports", status_code=202)
def api_create_export(body: ExportCreate, principal=Depends(guard("finding:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        try:
            job = build_export(s, tenant_id=tid, report_id=body.report_id,
                               fmt=body.format, created_by=uid)
        except ValueError as exc_:
            raise HTTPException(422, detail={"code": "EXPORT_NOT_RELEASED", "message": str(exc_),
                                             "retryable": False})
        except TenantViolation:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        append_audit(tid, uid, "export.create", "export", job.id,
                     {"format": job.format, "sha256": job.sha256[:16]}, session=s)
        return {"export_job_id": job.id, "status": job.status, "format": job.format,
                "sha256": job.sha256, "finding_count": job.finding_count}


@router.get("/exports/{export_job_id}")
def api_get_export(export_job_id: str, principal=Depends(guard("read:reports"))):
    tid = tenant_of(principal)
    from ..core.db import ExportJob
    with session_scope() as s:
        job = s.get(ExportJob, export_job_id)
        if job is None or job.tenant_id != tid:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        return {"export_job_id": job.id, "status": job.status, "format": job.format,
                "sha256": job.sha256, "finding_count": job.finding_count,
                "download_url": f"/v1/exports/{job.id}/download",
                "note": "content formula-sanitized server-side (SC21)"}


@router.get("/exports/{export_job_id}/download")
def api_download_export(export_job_id: str, principal=Depends(guard("read:reports"))):
    tid = tenant_of(principal)
    from fastapi.responses import Response
    from ..core.db import ExportJob
    with session_scope() as s:
        job = s.get(ExportJob, export_job_id)
        if job is None or job.tenant_id != tid:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        media = "text/csv" if job.format == "csv" else "application/json"
        filename = f"findings-{job.report_id[:16]}.{job.format}"
    return Response(content=job.payload, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# --- subscriptions (S00) ----------------------------------------------------------------

@router.get("/subscriptions")
def api_list_subscriptions(principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    from ..core.db import Subscription
    with session_scope() as s:
        rows = s.execute(select(Subscription).where(Subscription.tenant_id == tid)).scalars().all()
        return [{"subscription_id": x.id, "engagement_id": x.engagement_id,
                 "enabled": x.enabled, "cadence_hours": x.cadence_hours,
                 "last_run_id": x.last_run_id, "last_run_at": x.last_run_at.isoformat() + "Z"
                 if x.last_run_at else None} for x in rows]


@router.post("/subscriptions", status_code=201)
def api_create_subscription(body: SubscriptionCreate, principal=Depends(guard("settings:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        try:
            sub = create_subscription(s, tenant_id=tid, engagement_id=body.engagement_id,
                                      cadence_hours=body.cadence_hours)
        except TenantViolation:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "engagement not found",
                                             "retryable": False})
        append_audit(tid, uid, "subscription.create", "subscription", sub.id,
                     {"cadence_hours": sub.cadence_hours}, session=s)
        return {"subscription_id": sub.id, "engagement_id": sub.engagement_id,
                "cadence_hours": sub.cadence_hours, "enabled": sub.enabled}


@router.patch("/subscriptions/{subscription_id}")
def api_patch_subscription(subscription_id: str, body: dict,
                           principal=Depends(guard("settings:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    from ..core.db import Subscription
    with session_scope() as s:
        sub = s.get(Subscription, subscription_id)
        if sub is None or sub.tenant_id != tid:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        if "enabled" in body:
            sub.enabled = bool(body["enabled"])
        if "cadence_hours" in body:
            sub.cadence_hours = max(1, int(body["cadence_hours"]))
        append_audit(tid, uid, "subscription.update", "subscription", sub.id,
                     {"enabled": sub.enabled, "cadence_hours": sub.cadence_hours}, session=s)
        return {"subscription_id": sub.id, "enabled": sub.enabled,
                "cadence_hours": sub.cadence_hours}


# --- assistant (API24) --------------------------------------------------------------------

@router.post("/assistant/queries")
def api_assistant_query(body: AssistantQuery, principal=Depends(guard("assistant:query"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        result = assistant_answer(s, tenant_id=tid, question=body.question,
                                  object_refs=body.object_refs)
        return {"answer": result.answer, "citations": result.citations,
                "ai_generated": result.ai_generated, "model": result.model,
                "limitations": result.limitations}


# --- CI evaluations (API25) — machine identity, no session ----------------------------------

@router.post("/ci/evaluations")
async def api_ci_evaluation(request: Request):
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        raise HTTPException(401, detail={"code": "UNAUTHENTICATED",
                                         "message": "X-API-Key required for CI evaluations.",
                                         "retryable": False})
    from ..scheduler import resolve_machine_token
    try:
        token = resolve_machine_token(api_key)
    except TenantViolation:
        raise HTTPException(401, detail={"code": "INVALID_TOKEN", "message": "unknown API key",
                                         "retryable": False})
    import json as _json
    raw = await request.body()
    try:
        body = _json.loads(raw or b"{}")
    except Exception:
        body = {}
    since_raw = body.get("since")
    since = None
    if since_raw:
        from ..connectors.base import parse_ts
        since = parse_ts(since_raw)
    verdict = evaluate(token.tenant_id, since=since,
                       protected=bool(body.get("protected", True)))
    append_audit(token.tenant_id, "machine:ci", "ci.evaluation", "tenant", token.tenant_id,
                 {"verdict": verdict["verdict"]})
    return verdict


# --- offboarding (OP20) ------------------------------------------------------------------

@router.post("/tenant-offboarding", status_code=202)
def api_offboard_tenant(body: OffboardRequest, principal=Depends(guard("settings:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        tenant = s.get(Tenant, tid)
        if body.confirmation != tenant.name:
            raise HTTPException(422, detail={
                "code": "CONFIRMATION_MISMATCH",
                "message": "Type the exact tenant name to confirm offboarding.",
                "retryable": False})
        result = offboard_tenant(s, tenant_id=tid, reason=body.reason)
        return result


# --- scheduler maintenance (invoked by the app loop; exposed for operators/tests) -----------

@router.post("/scheduler/tick")
def api_scheduler_tick(principal=Depends(guard("settings:update"))):
    started = run_due_subscriptions()
    expired = 0
    purged = 0
    events = record_signatures()
    with session_scope() as s:
        expired = expire_exceptions(s)
    with session_scope() as s:
        purged = purge_expired(s)
    return {"subscriptions_started": started, "signatures_recorded": events,
            "exceptions_expired": expired, "artifacts_purged": purged}
