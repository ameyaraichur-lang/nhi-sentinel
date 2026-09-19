"""Control API part 2: identities, findings, graph, proposals/approvals, evidence, reports,
agents, audit, scores, snapshots, tenant settings."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select, text

from ..worker import engine
from ..contracts import AgentLifecycle, RunState, WorkflowStatus
from ..contracts.models import (
    AgentCommand, ApprovalRequest, FindingPatch, OwnerAttestation, ReleaseRequest,
    ReportCreate,
)
from ..core.audit import append_audit, verify_chain, walk_chain
from ..core.db import (
    AgentRecord, Approval, AuditEntry, CheckResult, CredentialMeta, EvidenceArtifact, Finding,
    GraphEdge, Identity, OwnershipAssertion, Proposal, Report, Run, ScopeVersion, Snapshot,
    Tenant, User, new_id, session_scope, utcnow,
)
from ..core.repo import load_snapshot_view, scoped_get
from ..core.security import digest_of, hmac_obj, verify_artifact, verify_password
from ..policies.score import compute_score
from ..reports.builder import release_report, validate_grounding
from .deps import guard, tenant_of, user_id

router = APIRouter(prefix="/v1")

MAX_PAGE = 100


def _page(limit: int) -> int:
    return max(1, min(limit, MAX_PAGE))


# --- identities (API11/12/29) ---------------------------------------------------------

@router.get("/identities")
def api_list_identities(principal=Depends(guard("read:identities")),
                        limit: int = 50, offset: int = 0, provider: str | None = None):
    tid = tenant_of(principal)
    with session_scope() as s:
        q = select(Identity).where(Identity.tenant_id == tid)
        if provider:
            q = q.where(Identity.provider == provider)
        total = s.execute(select(func.count()).select_from(q.subquery())).scalar()
        rows = s.execute(q.order_by(Identity.provider, Identity.native_id)
                         .limit(_page(limit)).offset(offset)).scalars().all()
        items = []
        for i in rows:
            verified = s.execute(select(OwnershipAssertion).where(
                OwnershipAssertion.tenant_id == tid,
                OwnershipAssertion.identity_id == i.id)).scalars().all()
            items.append({
                "identity_id": i.id, "provider": i.provider, "native_id": i.native_id,
                "display_name": i.display_name, "id_type": i.id_type,
                "owner_business": next((a.owner_email for a in verified if a.role == "business"), None),
                "owner_technical": next((a.owner_email for a in verified if a.role == "technical"), None),
                "first_seen": i.first_seen.isoformat() + "Z", "last_seen": i.last_seen.isoformat() + "Z",
            })
        return {"total": total, "limit": _page(limit), "offset": offset, "items": items,
                "note": "display names are untrusted source text and render escaped (VD13)"}


@router.get("/identities/{identity_id}")
def api_get_identity(identity_id: str, principal=Depends(guard("read:identities"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        ident = scoped_get(s, Identity, tid, identity_id)
        creds = s.execute(select(CredentialMeta).where(
            CredentialMeta.tenant_id == tid, CredentialMeta.identity_id == ident.id)).scalars().all()
        owners = s.execute(select(OwnershipAssertion).where(
            OwnershipAssertion.tenant_id == tid,
            OwnershipAssertion.identity_id == ident.id)).scalars().all()
        findings = s.execute(select(Finding).where(
            Finding.tenant_id == tid, Finding.target_id == ident.id)).scalars().all()
        return {
            "identity_id": ident.id, "provider": ident.provider, "authority": ident.authority,
            "native_id": ident.native_id, "display_name": ident.display_name,
            "id_type": ident.id_type, "attributes": ident.attributes_json,
            "credentials": [{"kind": c.kind, "status": c.status,
                             "expires_at": c.expires_at.isoformat() + "Z" if c.expires_at else None,
                             "last_rotated_at": c.last_rotated_at.isoformat() + "Z"
                             if c.last_rotated_at else None,
                             "fingerprint": c.fingerprint_hmac[:12] + "..."} for c in creds],
            "ownership_assertions": [{"owner_email": o.owner_email, "role": o.role,
                                      "source": o.source, "verified": o.verified_at is not None}
                                     for o in owners],
            "findings": [{"finding_id": f.id, "check_id": f.check_id, "severity": f.severity,
                          "status": f.workflow_status} for f in findings],
            "note": "secret values are never stored or shown (DC07/UI07)",
        }


@router.put("/identities/{identity_id}/owners")
def api_attest_owner(identity_id: str, body: OwnerAttestation, request: Request,
                     principal=Depends(guard("owner:attest"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        ident = scoped_get(s, Identity, tid, identity_id)
        assertion = OwnershipAssertion(
            id=new_id("own"), tenant_id=tid, identity_id=ident.id,
            owner_email=body.owner_email, role=body.role, source=f"user:{uid}",
            purpose=body.purpose, asserted_at=utcnow(),
            verified_at=utcnow(),
            valid_to=utcnow() + __import__("datetime").timedelta(days=body.review_expiry_days))
        s.add(assertion)
        s.flush()
        append_audit(tid, uid, "identity.attest_owner", "identity", ident.id,
                     {"owner": body.owner_email, "role": body.role}, session=s)
        return {"assertion_id": assertion.id, "identity_id": ident.id, "status": "verified"}


# --- graph (API13) ---------------------------------------------------------------------

@router.get("/graph/paths")
def api_graph_paths(source: str, target: str, max_hops: int = 4, max_paths: int = 10,
                    run_id: str | None = None, principal=Depends(guard("read:identities"))):
    tid = tenant_of(principal)
    max_hops = min(max_hops, 6)
    max_paths = min(max_paths, 20)
    with session_scope() as s:
        edges = s.execute(select(GraphEdge).where(GraphEdge.tenant_id == tid)).scalars().all()
    adj: dict[str, list] = {}
    for e in edges:
        adj.setdefault(e.src_id, []).append(e)
    paths, truncated = [], False

    def dfs(node: str, path: list, hops: int):
        nonlocal truncated
        if len(paths) >= max_paths:
            truncated = truncated or True
            return
        if node == target and path:
            paths.append(list(path))
            return
        if hops >= max_hops:
            return
        for e in adj.get(node, []):
            if e.id in {p["edge_id"] for p in path}:
                continue
            path.append({"edge_id": e.id, "relationship": e.relationship,
                         "conditions": e.conditions_json,
                         "certainty": "config-evaluated" if not (e.conditions_json or {}).get(
                             "unsupported") else "possible",
                         "dst": e.dst_id})
            dfs(e.dst_id, path, hops + 1)
            path.pop()

    import time
    started = time.time()
    dfs(source, [], 0)
    if time.time() - started > 5:
        raise HTTPException(503, detail={"code": "QUERY_DEADLINE", "message": "graph query deadline",
                                         "retryable": True})
    return {"paths": paths, "truncated": truncated, "max_hops": max_hops,
            "note": "bounded paths; conditions and certainty per edge (UI08)"}


# --- findings (API14/15/16/35) ------------------------------------------------------------

@router.get("/findings")
def api_list_findings(principal=Depends(guard("read:findings")), severity: str | None = None,
                      status: str | None = None, limit: int = 50, offset: int = 0):
    tid = tenant_of(principal)
    with session_scope() as s:
        q = select(Finding).where(Finding.tenant_id == tid)
        if severity:
            q = q.where(Finding.severity == severity)
        if status:
            q = q.where(Finding.workflow_status == status)
        total = s.execute(select(func.count()).select_from(q.subquery())).scalar()
        rows = s.execute(q.order_by(Finding.updated_at.desc())
                         .limit(_page(limit)).offset(offset)).scalars().all()
        return {"total": total, "items": [_finding_out(f) for f in rows]}


def _finding_out(f: Finding) -> dict:
    return {
        "finding_id": f.id, "check_id": f.check_id, "check_version": f.check_version,
        "target_id": f.target_id, "target_key": f.target_key, "title": f.title,
        "severity": f.severity, "assurance": f.assurance, "workflow_status": f.workflow_status,
        "revision": f.revision, "occurrence_count": f.occurrence_count, "summary": f.summary,
        "evidence_refs": f.evidence_refs_json, "facts": _redacted_facts(f.facts or {}),
        "severity_rationale": f.severity_rationale, "assignee_id": f.assignee_id,
        "first_seen": f.first_seen.isoformat() + "Z", "updated_at": f.updated_at.isoformat() + "Z",
    }


def _redacted_facts(facts: dict) -> dict:
    """SC11: standard inputs pass through; anything secret-looking is stripped."""
    from ..core.security import redact_dict
    redacted, _ = redact_dict(facts)
    return redacted


@router.get("/findings/{finding_id}")
def api_get_finding(finding_id: str, principal=Depends(guard("read:findings"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        f = scoped_get(s, Finding, tid, finding_id)
        revisions = s.execute(select(CheckResult).where(
            CheckResult.tenant_id == tid, CheckResult.target_id == f.target_id,
            CheckResult.check_id == f.check_id)).scalars().all()
        out = _finding_out(f)
        out["history"] = [{"result_id": r.id, "status": r.status,
                           "run_id": r.run_id,
                           "observed_at": r.observed_at.isoformat() + "Z"} for r in revisions]
        return out


@router.patch("/findings/{finding_id}")
def api_patch_finding(finding_id: str, body: FindingPatch, request: Request,
                      principal=Depends(guard("finding:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    if_match = request.headers.get("If-Match")
    with session_scope() as s:
        f = scoped_get(s, Finding, tid, finding_id)
        if if_match is not None and int(if_match) != f.revision:
            raise HTTPException(409, detail={"code": "REVISION_CONFLICT",
                                             "message": "Finding was modified concurrently.",
                                             "retryable": False,
                                             "details": {"current_revision": f.revision}})
        if body.workflow_status is not None:
            if body.workflow_status == WorkflowStatus.RESOLVED:
                raise HTTPException(422, detail={
                    "code": "RESOLUTION_REQUIRES_RETEST",
                    "message": "Resolution requires a fresh complete retest (PS15/API16).",
                    "retryable": False})
            f.workflow_status = body.workflow_status.value
        if body.assignee_id is not None:
            f.assignee_id = body.assignee_id
        f.revision += 1
        f.updated_at = utcnow()
        append_audit(tid, uid, "finding.update", "finding", f.id,
                     {"status": f.workflow_status, "reason": body.reason}, session=s)
        return _finding_out(f)


@router.post("/findings/{finding_id}/retests")
def api_request_retest(finding_id: str, principal=Depends(guard("finding:retest"))):
    """API16: creates a scoped passive retest run in a new epoch (PS15)."""
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        f = scoped_get(s, Finding, tid, finding_id)
        source_run = s.get(Run, f.run_id)
        if source_run is None or source_run.tenant_id != tid:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "source run unavailable",
                                             "retryable": False})
        sv = s.get(ScopeVersion, source_run.scope_version_id)
        retest = Run(id=new_id("run"), tenant_id=tid, engagement_id=source_run.engagement_id,
                     scope_version_id=sv.id, epoch=source_run.epoch + 1,
                     parent_run_id=source_run.id, mode="passive", state=RunState.QUEUED.value,
                     versions_json=source_run.versions_json, budget_json=source_run.budget_json,
                     created_by=uid)
        s.add(retest)
        s.flush()
        append_audit(tid, uid, "finding.retest", "finding", f.id, {"run_id": retest.id}, session=s)
    engine.create_run_tasks(tid, retest.id)
    return {"retest_run_id": retest.id, "parent_finding": finding_id,
            "note": "closure requires fresh complete retest evidence (PS15)"}


@router.post("/findings/bulk-assign")
def api_bulk_assign(body: dict, principal=Depends(guard("finding:bulk_assign"))):
    """UX19: explicit IDs, max 100, per-item result ledger (API35)."""
    tid, uid = tenant_of(principal), user_id(principal)
    finding_ids = body.get("finding_ids") or []
    assignee = body.get("assignee_id")
    if not finding_ids or not assignee or len(finding_ids) > 100:
        raise HTTPException(422, detail={"code": "VALIDATION",
                                         "message": "finding_ids (1..100) and assignee_id required.",
                                         "retryable": False})
    results = []
    with session_scope() as s:
        for fid in finding_ids:
            try:
                f = scoped_get(s, Finding, tid, fid)
                f.assignee_id = assignee
                f.revision += 1
                results.append({"finding_id": fid, "ok": True})
            except Exception:
                results.append({"finding_id": fid, "ok": False, "error": "not visible in scope"})
        append_audit(tid, uid, "finding.bulk_assign", "finding", ",".join(finding_ids[:5]),
                     {"count": len(finding_ids), "assignee": assignee}, session=s)
    return {"results": results, "assigned": sum(1 for r in results if r["ok"])}


# --- proposals + approvals (API18/19, DC16/DC17, AT05) ---------------------------------

@router.get("/proposals")
def api_list_proposals(principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Proposal).where(Proposal.tenant_id == tid)
                         .order_by(Proposal.created_at.desc())).scalars().all()
        return [_proposal_out(p, s) for p in rows]


def _proposal_out(p: Proposal, s) -> dict:
    approvals = s.execute(select(Approval).where(Approval.tenant_id == p.tenant_id,
                                                 Approval.proposal_id == p.id)).scalars().all()
    return {
        "proposal_id": p.id, "kind": p.kind, "title": p.title, "template": p.template,
        "template_version": p.template_version, "status": p.status,
        "action_digest": p.action_digest, "expected_effects": p.expected_effects,
        "rollback": p.rollback, "payload": p.payload_json,
        "created_by": p.created_by,
        "expires_at": p.expires_at.isoformat() + "Z",
        "approvals": [{"actor_id": a.actor_id, "decision": a.decision, "reason": a.reason,
                       "decided_at": a.decided_at.isoformat() + "Z"} for a in approvals],
        "required_approvals": 2,
    }


@router.get("/proposals/{proposal_id}")
def api_get_proposal(proposal_id: str, principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        p = scoped_get(s, Proposal, tid, proposal_id)
        return _proposal_out(p, s)


@router.post("/approvals")
def api_submit_approval(body: ApprovalRequest, principal=Depends(guard("approval:decide"))):
    """API19/DC17: distinct-actor, digest-bound, expiring, re-authenticated decisions.
    One execution reservation exists even when both approvals land (AT05)."""
    tid, uid, role = tenant_of(principal), user_id(principal), principal[0].role
    with session_scope() as s:
        p = scoped_get(s, Proposal, tid, body.proposal_id)
        if p.action_digest != body.proposal_digest:
            raise HTTPException(409, detail={"code": "STALE_APPROVAL",
                                             "message": "The proposal changed. Review the new revision.",
                                             "retryable": False,
                                             "details": {"current_digest": p.action_digest[:16] + "..."}})
        if p.created_by == uid:
            raise HTTPException(403, detail={"code": "SELF_APPROVAL",
                                             "message": "Proposer cannot approve own action (SC05).",
                                             "retryable": False})
        if p.expires_at < utcnow() or p.status in ("expired", "revoked"):
            raise HTTPException(422, detail={"code": "PROPOSAL_EXPIRED",
                                             "message": "Proposal expired or revoked.",
                                             "retryable": False})
        existing = s.execute(select(Approval).where(
            Approval.tenant_id == tid, Approval.proposal_id == p.id)).scalars().all()
        if any(a.actor_id == uid for a in existing):
            raise HTTPException(422, detail={"code": "DUPLICATE_ACTOR",
                                             "message": "This actor already decided on the proposal.",
                                             "retryable": False})
        user = s.get(User, uid)
        if not verify_password(body.reauth_password, user.password_hash):
            raise HTTPException(401, detail={"code": "REAUTH_FAILED",
                                             "message": "Re-authentication failed for sensitive approval.",
                                             "retryable": False})
        decision = "approve" if body.decision == "approve" else "deny"
        s.add(Approval(id=new_id("apr"), tenant_id=tid, proposal_id=p.id,
                       proposal_digest=body.proposal_digest, actor_id=uid, actor_role=role,
                       decision=decision, reason=body.reason[:500], decided_at=utcnow()))
        if decision == "deny":
            p.status = "denied"
        elif len([a for a in existing if a.decision == "approve"]) + 1 >= 2:
            p.status = "approved"
        append_audit(tid, uid, "approval.decision", "proposal", p.id,
                     {"decision": decision, "digest_prefix": body.proposal_digest[:16]}, session=s)
        return {"proposal_id": p.id, "status": p.status,
                "note": "single-use redemption enforced at execution reservation (EX05)"}


@router.post("/proposals/{proposal_id}/execute")
def api_attempt_execution(proposal_id: str, principal=Depends(guard("approval:decide"))):
    """Demonstrates D06/AT05: even a fully-approved active proof cannot execute in pilot."""
    tid, uid = tenant_of(principal), user_id(principal)
    # validate + persist the revocation in its own transaction BEFORE raising, so the
    # HTTPException rollback cannot discard the recorded revocation (AT05 evidence)
    with session_scope() as s:
        p = scoped_get(s, Proposal, tid, proposal_id)
        if p.kind != "active_proof":
            raise HTTPException(422, detail={"code": "UNKNOWN_KIND", "message": "not executable",
                                             "retryable": False})
        if p.status != "approved":
            raise HTTPException(422, detail={"code": "NOT_APPROVED",
                                             "message": "Proposal lacks two-person approval.",
                                             "retryable": False})
        p.status = "revoked"
        append_audit(tid, uid, "proposal.execution_blocked", "proposal", p.id,
                     {"why": "active proof disabled in pilot (D06)"}, session=s)
    raise HTTPException(422, detail={
        "code": "ACTIVE_PROOF_DISABLED",
        "message": "Two approvals recorded, but active execution is disabled in pilot (D06). "
                   "Proposal marked revoked; approvals never become capability.",
        "retryable": False})


# --- evidence (API20) -------------------------------------------------------------------

@router.get("/evidence/{artifact_id}")
def api_get_evidence(artifact_id: str, principal=Depends(guard("read:evidence"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        art = scoped_get(s, EvidenceArtifact, tid, artifact_id)
        ok = verify_artifact(art.content_json, art.sha256, art.signature, art.redaction_version)
        return {
            "artifact_id": art.id, "kind": art.kind, "producer": art.producer,
            "sha256": art.sha256, "signature_valid": ok,
            "collected_at": art.collected_at.isoformat() + "Z" if art.collected_at else None,
            "received_at": art.received_at.isoformat() + "Z",
            "redaction_version": art.redaction_version,
            "retention_state": art.retention_state,
            "content": art.content_json,
            "note": "binary download would use separate signed short-lived URL (API25 boundary)",
        }


# --- reports (API21/22/36) ----------------------------------------------------------------

@router.post("/reports", status_code=202)
def api_create_report(body: ReportCreate, principal=Depends(guard("report:create"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        run = scoped_get(s, Run, tid, body.run_id)
        if run.state not in (RunState.PARTIAL.value, RunState.WAITING_APPROVAL.value,
                             RunState.SUCCEEDED.value, RunState.RUNNING.value):
            raise HTTPException(422, detail={"code": "RUN_NOT_READY",
                                             "message": f"run state {run.state} cannot assemble report",
                                             "retryable": False})
    from ..reports.builder import assemble_report
    with session_scope() as s:
        run = scoped_get(s, Run, tid, body.run_id)
        report_id = assemble_report(s, tenant_id=tid, run=run, created_by=uid)
        append_audit(tid, uid, "report.create", "report", report_id, {}, session=s)
        return {"report_id": report_id, "status": "draft"}


@router.get("/reports")
def api_list_reports(principal=Depends(guard("read:reports"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Report).where(Report.tenant_id == tid)
                         .order_by(Report.created_at.desc())).scalars().all()
        return [{"report_id": r.id, "run_id": r.run_id, "version": r.version, "status": r.status,
                 "created_by": r.created_by, "reviewer_id": r.reviewer_id,
                 "released_at": r.released_at.isoformat() + "Z" if r.released_at else None,
                 "signature": r.signature, "grounding": {
                     "claims_total": (r.grounding_json or {}).get("claims_total"),
                     "unsupported": len((r.grounding_json or {}).get("unsupported", []))} }
                for r in rows]


@router.get("/reports/{report_id}")
def api_get_report(report_id: str, principal=Depends(guard("read:reports"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        r = scoped_get(s, Report, tid, report_id)
        return {"report_id": r.id, "run_id": r.run_id, "version": r.version, "status": r.status,
                "content": r.content_json, "claims": r.claims_json,
                "limitations": r.limitations_json, "grounding": r.grounding_json,
                "revision_digest": r.revision_digest, "created_by": r.created_by,
                "reviewer_id": r.reviewer_id, "review_record": r.review_record,
                "signature": r.signature,
                "released_at": r.released_at.isoformat() + "Z" if r.released_at else None}


@router.post("/reports/{report_id}/release")
def api_release_report(report_id: str, body: ReleaseRequest, principal=Depends(guard("report:release"))):
    tid, uid = tenant_of(principal), user_id(principal)
    user = principal[0]
    if not verify_password(body.reauth_password, user.password_hash):
        raise HTTPException(401, detail={"code": "REAUTH_FAILED",
                                         "message": "Re-authentication failed.", "retryable": False})
    from ..core.repo import TenantViolation
    try:
        with session_scope() as s:
            r = scoped_get(s, Report, tid, report_id)
            if r.revision_digest != body.revision_digest:
                raise HTTPException(409, detail={"code": "STALE_REVISION",
                                                 "message": "Report revision changed; review the current draft.",
                                                 "retryable": False})
            released = release_report(s, tenant_id=tid, report_id=report_id,
                                      reviewer_id=uid, review_record=body.review_record)
            append_audit(tid, uid, "report.release", "report", report_id,
                         {"digest": released.revision_digest[:16], "reviewer": uid}, session=s)
            report_id = released.id
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "RELEASE_BLOCKED", "message": str(exc),
                                         "retryable": False})
    except TenantViolation:
        raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found", "retryable": False})
    engine.complete_external_gate(tid, released_run_id(tid, report_id), "G02", True,
                                  f"released by {uid}")
    return {"report_id": report_id, "status": "released",
            "note": "signature bound to exact revision; claim feedback never mutates it (UX23)"}


def released_run_id(tenant_id: str, report_id: str) -> str:
    with session_scope() as s:
        r = s.get(Report, report_id)
        if r is None or r.tenant_id != tenant_id:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        return r.run_id


@router.post("/reports/{report_id}/claim-feedback")
def api_claim_feedback(report_id: str, principal=Depends(guard("read:reports")),
                       claim_id: str = "", reference: str = "", comment: str = ""):
    """API36/UX28: flagging creates a review task; the released report is immutable."""
    tid, uid = tenant_of(principal), user_id(principal)
    if not claim_id or not reference or not comment:
        raise HTTPException(422, detail={"code": "VALIDATION", "message": "claim_id, reference, comment required",
                                         "retryable": False})
    with session_scope() as s:
        r = scoped_get(s, Report, tid, report_id)
        claim_ids = {c["claim_id"] for c in (r.claims_json or [])}
        if claim_id not in claim_ids:
            raise HTTPException(404, detail={"code": "CLAIM_NOT_FOUND",
                                             "message": "claim not in this report", "retryable": False})
        append_audit(tid, uid, "report.claim_feedback", "report", report_id,
                     {"claim_id": claim_id, "reference": reference}, session=s)
        return {"status": "review_task_created", "report_status": r.status,
                "note": "released report unchanged; correction creates a revision (UX23/AT13)"}


# --- agents (API30/31/32) -----------------------------------------------------------------

@router.get("/agents")
def api_list_agents(principal=Depends(guard("read:agents"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(AgentRecord).where(AgentRecord.tenant_id == tid)
                         .order_by(AgentRecord.native_id)).scalars().all()
        return {"items": [{
            "agent_row_id": a.id, "native_id": a.native_id, "display_name": a.display_name,
            "sponsor": a.sponsor, "purpose": a.purpose, "runtime": a.runtime,
            "capabilities": a.capabilities_json, "parent_native_id": a.parent_native_id,
            "lifecycle": a.lifecycle, "registered": a.registered,
            "expires_at": a.expires_at.isoformat() + "Z" if a.expires_at else None,
            "registry_version": a.registry_version,
            "shadow": not a.registered,
        } for a in rows],
            "note": "shadow agent = observed identity absent from a COMPLETE registry (UI17)"}


@router.post("/agents/{agent_row_id}/commands")
def api_agent_command(agent_row_id: str, body: AgentCommand, principal=Depends(guard("agent:command"))):
    tid, uid = tenant_of(principal), user_id(principal)
    with session_scope() as s:
        a = scoped_get(s, AgentRecord, tid, agent_row_id)
        if not a.registered:
            raise HTTPException(422, detail={"code": "OBSERVED_ONLY",
                                             "message": "Observed-but-unregistered agents cannot be "
                                                        "commanded; register first.",
                                             "retryable": False})
        if body.registry_version != a.registry_version:
            raise HTTPException(409, detail={"code": "REVISION_CONFLICT",
                                             "message": "Registry changed.", "retryable": False,
                                             "details": {"current_version": a.registry_version}})
        if body.command == "approve_activation":
            if a.lifecycle != AgentLifecycle.DRAFTED.value:
                raise HTTPException(422, detail={"code": "INVALID_STATE",
                                                 "message": "only drafted agents activate", "retryable": False})
            a.lifecycle = AgentLifecycle.ACTIVE.value
        elif body.command == "suspend":
            a.lifecycle = AgentLifecycle.SUSPENDED.value
        else:
            a.lifecycle = AgentLifecycle.RETIRED.value
        a.registry_version += 1
        append_audit(tid, uid, f"agent.{body.command}", "agent", a.id, {"reason": body.reason}, session=s)
        return {"agent_row_id": a.id, "lifecycle": a.lifecycle,
                "note": "suspension revokes leases and child delegation (DC22)"}


# --- audit (API33) ---------------------------------------------------------------------

@router.get("/audit-events")
def api_audit_events(principal=Depends(guard("read:audit")), limit: int = 100, offset: int = 0):
    tid = tenant_of(principal)
    from ..core.db import AuditEntry
    with session_scope() as s:
        rows = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tid)
                         .order_by(AuditEntry.created_at.desc())
                         .limit(_page(limit) * 5).offset(offset)).scalars().all()
        return {"items": [{"id": a.id, "actor": a.actor_id, "action": a.action,
                           "object": f"{a.object_type}:{a.object_id}",
                           "detail": a.detail_json, "entry_hash": a.entry_hash[:16],
                           "prev_hash": a.prev_hash[:16],
                           "at": a.created_at.isoformat() + "Z"} for a in rows]}


@router.get("/audit-verify")
def api_audit_verify(principal=Depends(guard("read:audit"))):
    tid = tenant_of(principal)
    return verify_chain(tid)


def _audit_entry_out(a: AuditEntry) -> dict:
    """Same entry shape as /v1/audit-events items (API33 export parity)."""
    return {"id": a.id, "actor": a.actor_id, "action": a.action,
            "object": f"{a.object_type}:{a.object_id}",
            "detail": a.detail_json, "entry_hash": a.entry_hash[:16],
            "prev_hash": a.prev_hash[:16],
            "at": a.created_at.isoformat() + "Z"}


@router.get("/audit-events/export")
def api_audit_export(principal=Depends(guard("read:audit"))):
    """API33: signed audit export. signature = HMAC over {tenant_id, head, count} so a third
    party can hold the entries and re-verify against the server later."""
    tid = tenant_of(principal)
    with session_scope() as s:
        entries = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tid)
                            .order_by(text("rowid"))).scalars().all()
        s.expunge_all()
    walked = walk_chain(entries)
    head = walked["head"]
    count = len(entries)
    signature = hmac_obj({"tenant_id": tid, "head": head, "count": count})
    return {"tenant_id": tid, "entries": [_audit_entry_out(a) for a in entries],
            "head": head, "count": count, "signature": signature,
            "chain_valid": walked["valid"],
            "note": "entries in chain (insertion) order; head/count signed, not the bytes"}


@router.get("/audit-events/export/verify")
def api_audit_export_verify(signature: str = "", count: int = 0,
                            principal=Depends(guard("read:audit"))):
    """API33: recompute the chain and the export signature server-side. The walk is confined
    to the exported entry count, so appending newer audit entries never invalidates an older
    export - but tampering with any exported entry breaks both chain and signature."""
    tid = tenant_of(principal)
    with session_scope() as s:
        entries = s.execute(select(AuditEntry).where(AuditEntry.tenant_id == tid)
                            .order_by(text("rowid"))).scalars().all()
        s.expunge_all()
    window = count if count and count > 0 else len(entries)
    walked = walk_chain(entries, limit=window)
    recomputed_head = walked["head"]
    signature_valid = False
    if signature:
        expected = hmac_obj({"tenant_id": tid, "head": recomputed_head, "count": window})
        import hmac as _hmac
        signature_valid = _hmac.compare_digest(expected, signature)
    valid = walked["valid"] and (signature_valid if signature else True)
    return {"valid": valid, "signature_valid": signature_valid,
            "recomputed_head": recomputed_head, "count": window,
            "chain_valid": walked["valid"], "broken_at": walked["broken_at"]}


# --- scores + snapshots ---------------------------------------------------------------

@router.get("/scores")
def api_scores(run_id: str, principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        run = scoped_get(s, Run, tid, run_id)
        results = s.execute(select(CheckResult).where(
            CheckResult.tenant_id == tid, CheckResult.run_id == run.id)).scalars().all()
        view = load_snapshot_view(tid, run.id, session=s)
        card = compute_score(view, results)
        return card.model_dump(mode="json")


@router.get("/snapshots")
def api_snapshots(run_id: str | None = None, principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        q = select(Snapshot).where(Snapshot.tenant_id == tid)
        if run_id:
            q = q.where(Snapshot.run_id == run_id)
        rows = s.execute(q.order_by(Snapshot.ended_at.desc())).scalars().all()
        return [{"snapshot_id": x.id, "run_id": x.run_id, "source": x.source, "state": x.state,
                 "seen": x.seen_count, "expected": x.expected_count,
                 "completeness": x.completeness, "page_errors": x.page_errors_json,
                 "collected_at": x.collected_at.isoformat() + "Z" if x.collected_at else None}
                for x in rows]


# --- tenant settings (API37 subset: emergency kill flag; retention read-only in pilot) ---

@router.get("/tenant-settings")
def api_get_tenant_settings(principal=Depends(guard("read:overview"))):
    tid = tenant_of(principal)
    with session_scope() as s:
        t = s.get(Tenant, tid)
        return {"tenant_id": tid, "region": t.region, "plan": t.plan,
                "kill_flag": t.kill_flag, "status": t.status, "legal_hold": t.legal_hold,
                "retention_policy_version": t.retention_policy_version,
                "synthetic": t.synthetic}


@router.patch("/tenant-settings")
def api_tenant_settings(body: dict, principal=Depends(guard("settings:update"))):
    tid, uid = tenant_of(principal), user_id(principal)
    reason = body.get("reason", "")
    if len(reason) < 3:
        raise HTTPException(422, detail={"code": "VALIDATION", "message": "reason required",
                                         "retryable": False})
    with session_scope() as s:
        t = s.get(Tenant, tid)
        before = {"kill_flag": t.kill_flag}
        if "kill_flag" in body:
            t.kill_flag = bool(body["kill_flag"])
        after = {"kill_flag": t.kill_flag}
        append_audit(tid, uid, "tenant.settings", "tenant", tid,
                     {"before": before, "after": after, "reason": reason}, session=s)
        return {"tenant_id": tid, "before": before, "after": after,
                "note": "tenant kill flag blocks new dispatch for every run (SC18)"}
