"""Node handlers (Orchestration sheet N00-N17). Deterministic services; LLM optional and
wrapped by validators (AR03/AR13). Every mutation + its outbox event share one transaction."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select

from ..checks.base import REGISTRY as CHECK_REGISTRY, CheckOutcome, enabled_checks
from ..connectors import get_adapter
from ..connectors.base import FixtureError
from ..contracts import CheckStatus, RunState, SnapshotState
from ..core.db import (
    AgentRecord, CheckResult, Connector, CredentialMeta, EvidenceArtifact, Engagement,
    Finding, GraphEdge, Identity, OwnershipAssertion, Run, ScopeVersion, Snapshot, Task,
    new_id, session_scope, utcnow,
)
from ..core.events import emit
from ..core.repo import load_snapshot_view, upsert_finding
from ..core.security import sign_artifact
from ..policies.score import compute_score
from ..policies.severity import decide_severity, inputs_from_facts
from . import graph


@dataclass
class NodeResult:
    status: str = "succeeded"                    # succeeded | failed | skipped
    skip_reason: str | None = None
    new_tasks: list[tuple[str, str]] = field(default_factory=list)  # (node, partition)
    error: str | None = None


@dataclass
class NodeCtx:
    session, run, task = None, None, None
    tenant_id: str = ""

    @property
    def scope(self) -> ScopeVersion:
        return self.session.get(ScopeVersion, self.run.scope_version_id)


# --- N00 scope & readiness ----------------------------------------------------

def n00_scope_readiness(ctx: NodeCtx) -> NodeResult:
    scope = ctx.scope
    if scope.approved_at is None:
        return NodeResult(status="failed", error="scope version not approved (OF02 readiness gate)")
    conn_map = {c.connector_type: c for c in ctx.session.execute(
        select(Connector).where(Connector.tenant_id == ctx.tenant_id)).scalars()}
    missing = [src for src in scope.sources_json.get("sources", []) if src not in conn_map]
    if missing:
        return NodeResult(status="failed", error=f"connectors not registered for: {', '.join(missing)}")
    disabled = [src for src in scope.sources_json.get("sources", [])
                if not conn_map[src].enabled]
    if disabled:
        return NodeResult(status="failed", error=f"connectors disabled: {', '.join(disabled)}")
    certified = enabled_checks(scope.check_ids_json)
    uncertified = [cid for cid in scope.check_ids_json if cid not in CHECK_REGISTRY]
    if uncertified:
        emit(ctx.session, ctx.tenant_id, ctx.run.id, "run.scope_uncertified_checks_excluded",
             {"excluded": uncertified})  # AT15: unsupported checks visibly excluded, never run
    if not certified:
        return NodeResult(status="failed", error="no certified checks in scope")
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "run.plan_ready", {
        "sources": scope.sources_json.get("sources", []),
        "checks": [c.id for c in certified],
        "mode": ctx.run.mode, "active_proof": False,
    })
    return NodeResult(new_tasks=[("N01", "-")])


# --- N01 plan -----------------------------------------------------------------

def n01_plan(ctx: NodeCtx) -> NodeResult:
    """LLM may propose a plan in later releases; the deterministic validator owns the DAG.
    Fallback (and pilot default): fixed plan template (AR03/N01 guard, AR13 fallback)."""
    scope = ctx.scope
    plan = {
        "planner": "deterministic-fallback/1.0",  # model_version recorded (UX06)
        "model_calls": 0, "token_budget": ctx.run.budget_json.get("model_tokens", 100000),
        "sources": scope.sources_json.get("sources", []),
        "check_ids": [c for c in scope.check_ids_json if c in CHECK_REGISTRY],
    }
    ctx.run.versions_json = {**ctx.run.versions_json, "plan": plan}
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "run.plan_validated", plan)
    partitions = [(f"N02:{src}", src) for src in plan["sources"]]
    checks = [(f"N04:{cid}", cid) for cid in plan["check_ids"]]
    return NodeResult(new_tasks=[("N02", p) for _, p in partitions] +
                                 [("N03", "-"), ("N05", "-")] + [("N04", p) for _, p in checks])


# --- N02 collect partition ------------------------------------------------------

def n02_collect(ctx: NodeCtx) -> NodeResult:
    source = ctx.task.partition
    if source not in ctx.scope.sources_json.get("sources", []):
        return NodeResult(status="failed", error="source outside approved scope (OP17: never expand)")  # noqa: E501
    connector = ctx.session.execute(
        select(Connector).where(Connector.tenant_id == ctx.tenant_id,
                                Connector.connector_type == source)).scalars().first()
    adapter = get_adapter(source, __import__(
        "nhi_sentinel.connectors.base", fromlist=["CollectionContext"]).CollectionContext(
        tenant_id=ctx.tenant_id, run_id=ctx.run.id, scope_hash=ctx.scope.scope_hash,
        connector_id=connector.id, source=source))
    try:
        result, page_errors = adapter.collect()
    except FixtureError as exc:
        # Collection source failure is a partial outcome, not a run crash (AR07 failure behavior)
        snap = Snapshot(id=new_id("snp"), tenant_id=ctx.tenant_id, run_id=ctx.run.id,
                        source=source, connector_id=connector.id, scope_hash=ctx.scope.scope_hash,
                        state=SnapshotState.INVALID.value, started_at=utcnow(), ended_at=utcnow(),
                        page_errors_json=[{"error": str(exc)}])
        ctx.session.add(snap)
        emit(ctx.session, ctx.tenant_id, ctx.run.id, "snapshot.invalid",
             {"source": source, "error": str(exc)})
        return NodeResult()  # run continues; INVALID snapshot shows as gap (AT08)

    persist_collection(ctx, result)
    return NodeResult()


def persist_collection(ctx: NodeCtx, result) -> None:
    """Persist normalized objects + signed artifacts. Incomplete scans never delete (AR14)."""
    snap_meta = result.snapshot
    snap = Snapshot(
        id=snap_meta["snapshot_id"], tenant_id=ctx.tenant_id, run_id=ctx.run.id,
        source=snap_meta["source"], connector_id=snap_meta["connector_id"],
        scope_hash=snap_meta["scope_hash"], state=snap_meta["state"],
        started_at=utcnow(), ended_at=utcnow(), expected_count=snap_meta.get("expected_count"),
        seen_count=snap_meta.get("seen_count", 0), completeness=snap_meta.get("completeness"),
        page_errors_json=snap_meta.get("page_errors", []),
        collected_at=_parse(snap_meta.get("collected_at")),
    )
    ctx.session.add(snap)
    ident_index: dict[str, str] = {}
    for ident in result.identities:
        row = ctx.session.execute(
            select(Identity).where(Identity.tenant_id == ctx.tenant_id,
                                   Identity.provider == snap_meta["source"],
                                   Identity.authority == ident["authority"],
                                   Identity.native_id == ident["native_id"])).scalars().first()
        if row is None:
            row = Identity(id=new_id("ide"), tenant_id=ctx.tenant_id, provider=snap_meta["source"],
                           authority=ident["authority"], native_id=ident["native_id"],
                           display_name=ident.get("display_name", ident["native_id"])[:200],
                           id_type=ident.get("id_type", "service_identity"),
                           attributes_json=ident.get("attributes", {}), first_seen=utcnow(),
                           last_seen=_parse(snap_meta.get("collected_at")) or utcnow())
            ctx.session.add(row)
            ctx.session.flush()
        else:
            row.last_seen = _parse(snap_meta.get("collected_at")) or utcnow()
            row.attributes_json = {**row.attributes_json, **ident.get("attributes", {})}
        ident_index[ident["native_id"]] = row.id

    for cred in result.credentials:
        native = cred["identity_native_id"]
        if native not in ident_index:
            continue
        from ..core.security import fingerprint_secret
        ctx.session.add(CredentialMeta(
            id=new_id("crd"), tenant_id=ctx.tenant_id, identity_id=ident_index[native],
            kind=cred.get("kind", "key"), status=cred.get("status", "enabled"),
            created_at=_parse(cred.get("created_at")), expires_at=_parse(cred.get("expires_at")),
            last_rotated_at=_parse(cred.get("last_rotated_at")),
            fingerprint_hmac=fingerprint_secret(f"{native}:{cred.get('kind')}", ctx.tenant_id),
            source=snap_meta["source"], attributes_json=cred.get("attributes", {})))

    for own in result.ownership:
        native = own["identity_native_id"]
        if native not in ident_index:
            continue
        ctx.session.add(OwnershipAssertion(
            id=new_id("own"), tenant_id=ctx.tenant_id, identity_id=ident_index[native],
            owner_email=own.get("owner_email", ""), role=own.get("role", "technical"),
            source=snap_meta["source"], purpose=own.get("purpose", ""),
            asserted_at=_parse(snap_meta.get("collected_at")) or utcnow(),
            verified_at=(_parse(snap_meta.get("collected_at")) or utcnow()) if own.get("verified") else None))

    for rel in result.relationships:
        if rel["src"] not in ident_index or rel["dst"] not in ident_index:
            continue
        ctx.session.add(GraphEdge(
            id=new_id("edg"), tenant_id=ctx.tenant_id, snapshot_id=snap.id,
            src_id=ident_index[rel["src"]], dst_id=ident_index[rel["dst"]],
            relationship=rel.get("relationship", "can_access"),
            conditions_json=rel.get("conditions", {}), assurance="config",
            evidence_refs_json=[], valid_from=_parse(snap_meta.get("collected_at"))))

    for agent in result.agents:
        existing = ctx.session.execute(
            select(AgentRecord).where(AgentRecord.tenant_id == ctx.tenant_id,
                                      AgentRecord.native_id == agent["native_id"])).scalars().first()
        payload = dict(
            display_name=agent.get("display_name", agent["native_id"])[:200],
            sponsor=agent.get("sponsor"), purpose=agent.get("purpose"), runtime=agent.get("runtime"),
            capabilities_json=agent.get("capabilities", []),
            parent_native_id=agent.get("parent_native_id"),
            lifecycle=agent.get("lifecycle", "active"), registered=bool(agent.get("registered", True)),
            expires_at=_parse(agent.get("expires_at")), attributes_json=agent.get("attributes", {}),
            snapshot_id=snap.id)
        if existing:
            for k, v in payload.items():
                setattr(existing, k, v)
        else:
            ctx.session.add(AgentRecord(id=new_id("agn"), tenant_id=ctx.tenant_id,
                                        run_id=ctx.run.id, native_id=agent["native_id"], **payload))

    for artifact in result.artifacts:
        content_hash, signature = sign_artifact(artifact["content"])
        ctx.session.add(EvidenceArtifact(
            id=artifact["artifact_id"], tenant_id=ctx.tenant_id, run_id=ctx.run.id,
            snapshot_id=snap.id, kind=artifact["kind"], producer=artifact["producer"],
            content_json=artifact["content"], sha256=content_hash, signature=signature,
            redaction_version=artifact["redaction_version"],
            collected_at=_parse(artifact.get("collected_at"))))

    # connector health (UI13): success requires complete normalization, not HTTP 200
    connector = ctx.session.get(Connector, snap_meta["connector_id"])
    if snap_meta["state"] == "complete":
        connector.last_complete_sync = utcnow()
        connector.last_state = "complete"
    else:
        connector.last_state = snap_meta["state"]
    emit(ctx.session, ctx.tenant_id, ctx.run.id,
         "snapshot.complete" if snap_meta["state"] == "complete" else "snapshot.partial",
         {"source": snap_meta["source"], "snapshot_id": snap.id,
          "seen": snap_meta.get("seen_count"), "expected": snap_meta.get("expected_count"),
          "completeness": snap_meta.get("completeness"),
          "page_errors": snap_meta.get("page_errors", [])})


def _parse(value):
    from ..connectors.base import parse_ts
    return parse_ts(value)


# --- N03 coverage -------------------------------------------------------------

def n03_normalize(ctx: NodeCtx) -> NodeResult:
    snaps = ctx.session.execute(select(Snapshot).where(
        Snapshot.tenant_id == ctx.tenant_id, Snapshot.run_id == ctx.run.id)).scalars().all()
    if not snaps:
        return NodeResult(status="failed", error="no snapshots produced by collection")
    coverage = [{
        "source": s.source, "state": s.state, "seen": s.seen_count,
        "expected": s.expected_count, "completeness": s.completeness,
        "page_errors": s.page_errors_json,
    } for s in snaps]
    ctx.run.versions_json = {**ctx.run.versions_json, "coverage": coverage}
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "run.coverage", {"coverage": coverage})
    return NodeResult()


# --- N04 check partition --------------------------------------------------------

def n04_checks(ctx: NodeCtx) -> NodeResult:
    check_id = ctx.task.partition
    check = CHECK_REGISTRY.get(check_id)
    if check is None:
        return NodeResult(status="skipped", skip_reason=f"check {check_id} not certified")
    view = load_snapshot_view(ctx.tenant_id, ctx.run.id, session=ctx.session)
    try:
        outcomes: list[CheckOutcome] = check.run(view)
    except Exception as exc:  # check defect -> quarantine, never silently pass (N04 guard)
        emit(ctx.session, ctx.tenant_id, ctx.run.id, "check.quarantined",
             {"check_id": check_id, "error": str(exc)[:300]})
        return NodeResult(status="skipped", skip_reason=f"check defect: {str(exc)[:200]}")
    count = 0
    for out in outcomes:
        ctx.session.add(CheckResult(
            id=new_id("res"), tenant_id=ctx.tenant_id, run_id=ctx.run.id,
            snapshot_id=_snapshot_for(view, check), check_id=check.id,
            check_version=check.version, target_id=out.target_id, target_key=out.target_key[:240],
            status=out.status.value,
            evidence_refs_json=out.evidence_refs,
            facts={**out.facts, "dimension": check.dimension},
            reason=out.reason, observed_at=utcnow()))
        count += 1
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "check.completed",
         {"check_id": check_id, "results": count})
    return NodeResult()


def _snapshot_for(view, check) -> str | None:
    for source in check.applies_to:
        snaps = view.by_source(source)
        if snaps:
            return snaps[0].id
    return None


# --- N05 path analysis -----------------------------------------------------------

def n05_paths(ctx: NodeCtx) -> NodeResult:
    """Bounded delegation-chain analysis for agent identities (AGI-006 input).
    Unsupported permission semantics => 'possible', never confirmed (AR12/G11)."""
    view = load_snapshot_view(ctx.tenant_id, ctx.run.id, session=ctx.session)
    chains = []
    by_native = {a.native_id: a for a in view.agents}
    for agent in view.agents:
        if not agent.parent_native_id:
            continue
        parent = by_native.get(agent.parent_native_id)
        chain = {
            "parent": agent.parent_native_id,
            "child": agent.native_id,
            "parent_caps": sorted(set(parent.capabilities_json)) if parent else None,
            "child_caps": sorted(set(agent.capabilities_json)),
            "certainty": "possible",
        }
        if parent and parent.capabilities_json:
            excess = sorted(set(agent.capabilities_json) - set(parent.capabilities_json))
            chain["excess_capabilities"] = excess
            chain["certainty"] = "config-evaluated"
        chains.append(chain)
    artifact = {
        "artifact_id": new_id("art"), "kind": "analysis.delegation_chains",
        "producer": "path-analysis/1.0", "collected_at": utcnow().isoformat() + "Z",
        "content": chains, "redaction_version": "1.0",
    }
    content_hash, signature = sign_artifact(artifact["content"])
    ctx.session.add(EvidenceArtifact(
        id=artifact["artifact_id"], tenant_id=ctx.tenant_id, run_id=ctx.run.id,
        snapshot_id=None, kind=artifact["kind"], producer=artifact["producer"],
        content_json=artifact["content"], sha256=content_hash, signature=signature,
        collected_at=utcnow()))
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "analysis.paths", {"chains": len(chains)})
    return NodeResult()


# --- N06 evidence validation + findings ---------------------------------------------

def n06_evidence(ctx: NodeCtx) -> NodeResult:
    """Verifier service: fail results must reference resolvable, signature-valid artifacts.
    Supported findings are committed here; severity stays undetermined until N12 (AR14)."""
    view = load_snapshot_view(ctx.tenant_id, ctx.run.id, session=ctx.session)
    results = ctx.session.execute(select(CheckResult).where(
        CheckResult.tenant_id == ctx.tenant_id, CheckResult.run_id == ctx.run.id)).scalars().all()
    promoted, rejected = 0, 0
    for res in results:
        if res.status == CheckStatus.FAIL.value:
            bad = [ref for ref in res.evidence_refs_json if ref not in view.artifacts]
            if bad:
                res.status = CheckStatus.UNKNOWN.value
                res.reason = f"evidence references unresolvable: {bad}; downgraded to unknown (EX04)"
                rejected += 1
                continue
            tampered = [ref for ref in res.evidence_refs_json
                        if not _artifact_ok(view.artifacts[ref])]
            if tampered:
                res.status = CheckStatus.ERROR.value
                res.reason = f"evidence signature/hash verification failed: {tampered} (DC15)"
                rejected += 1
                continue
            finding = upsert_finding(
                ctx.session, tenant_id=ctx.tenant_id, run_id=ctx.run.id, result=res,
                title=_title(res), summary=res.reason or _title(res),
                severity="undetermined", assurance="config_supported",
                severity_rationale="Pending policy evaluation (N12).")
            promoted += 1
        elif res.status in (CheckStatus.UNKNOWN.value, CheckStatus.ERROR.value) and not res.reason:
            res.reason = "missing reason normalized by verifier"
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "findings.evaluated",
         {"promoted": promoted, "rejected": rejected})
    if ctx.run.parent_run_id:
        parent = ctx.session.get(Run, ctx.run.parent_run_id)
        if parent is not None and parent.tenant_id == ctx.tenant_id:
            evaluate_retest_closure(ctx.session, ctx.tenant_id, ctx.run, parent)
    return NodeResult()


def evaluate_retest_closure(session, tenant_id: str, retest_run, parent_run) -> dict:
    """PS15/API16 retest closure. A parent-run finding is resolved ONLY when a fresh retest
    run shows no failing result for the same check_id + target_key AND the retest snapshots
    for that check's sources are COMPLETE. Still-failing findings - and findings whose
    relevant retest evidence is incomplete - stay open. Resolution is an explicit finding
    revision with a recorded reason (no silent edits).

    Runs inside the caller's ambient transaction (never opens a nested session_scope - see
    append_audit(..., session=s)). retest_run/parent_run only need an ``id`` attribute, so
    tests can pass lightweight stand-ins for Run rows. Parent identities are read from the
    parent run's immutable CheckResults because the dedup upsert re-points Finding.run_id to
    the retest run when a condition is re-observed."""
    retest_fails = {(r.check_id, r.target_key) for r in session.execute(
        select(CheckResult).where(CheckResult.tenant_id == tenant_id,
                                  CheckResult.run_id == retest_run.id,
                                  CheckResult.status == CheckStatus.FAIL.value)).scalars()}
    parent_fail_keys = {(r.check_id, r.target_key) for r in session.execute(
        select(CheckResult).where(CheckResult.tenant_id == tenant_id,
                                  CheckResult.run_id == parent_run.id,
                                  CheckResult.status == CheckStatus.FAIL.value)).scalars()}
    source_complete: dict[str, bool] = {}
    for sn in session.execute(select(Snapshot).where(
            Snapshot.tenant_id == tenant_id, Snapshot.run_id == retest_run.id)).scalars():
        source_complete[sn.source] = (source_complete.get(sn.source, True)
                                      and sn.state == SnapshotState.COMPLETE.value)

    def _relevant_sources_complete(check_id: str) -> bool:
        check = CHECK_REGISTRY.get(check_id)
        if check is None or not check.applies_to:
            return False  # relevance unknown -> conservative, never resolve (AT15)
        return all(source_complete.get(src, False) for src in check.applies_to)

    # the parent's findings: re-pointed rows now carry the retest run_id, new retest-only
    # observations never carry a parent fail key
    candidates = session.execute(select(Finding).where(
        Finding.tenant_id == tenant_id,
        Finding.run_id.in_([parent_run.id, retest_run.id]))).scalars().all()
    resolved = still_open = 0
    for f in candidates:
        if (f.check_id, f.target_key) not in parent_fail_keys:
            continue  # not a parent-run finding (e.g. a brand-new retest observation)
        if (f.check_id, f.target_key) in retest_fails:
            still_open += 1  # condition persists on fresh evidence (PS15)
            continue
        if f.workflow_status == "resolved":
            continue  # already closed by an earlier retest; never double counted
        if not _relevant_sources_complete(f.check_id):
            still_open += 1  # incomplete retest: absence of a fail is not proof (AT08)
            continue
        f.workflow_status = "resolved"
        f.revision += 1
        f.updated_at = utcnow()
        f.facts = {**(f.facts or {}),
                   "resolution_reason": f"resolved by retest run {retest_run.id} (PS15)"}
        resolved += 1
    emit(session, tenant_id, retest_run.id, "retest.evaluated",
         {"resolved": resolved, "still_open": still_open})
    return {"resolved": resolved, "still_open": still_open}


def _artifact_ok(artifact) -> bool:
    try:
        from ..core.security import verify_artifact
        return verify_artifact(artifact.content_json, artifact.sha256, artifact.signature,
                               artifact.redaction_version)
    except Exception:
        return False


def _title(res) -> str:
    return f"{res.check_id}: weakness confirmed on {res.target_key}"


# --- N07/G01/N08/N09: dormant proof branch -----------------------------------------------

def n07_proof_proposal(ctx: NodeCtx) -> NodeResult:
    return NodeResult(status="skipped",
                      skip_reason="Active proof disabled in pilot (D06); findings remain config-supported (PS01).")


# --- N12 severity ---------------------------------------------------------------------

def n12_severity(ctx: NodeCtx) -> NodeResult:
    from ..core.db import Finding, SeverityDecision
    findings = ctx.session.execute(select(Finding).where(
        Finding.tenant_id == ctx.tenant_id, Finding.run_id == ctx.run.id)).scalars().all()
    decided = 0
    for f in findings:
        inputs = inputs_from_facts(f.facts or {})
        decision = decide_severity(inputs, ctx.run.versions_json.get("sev_policy", "sev-baseline-1.0.0"))
        ctx.session.add(SeverityDecision(
            id=new_id("sev"), tenant_id=ctx.tenant_id, finding_id=f.id,
            policy_version=decision.policy_version,
            input_hash=digest_inputs(inputs),
            impact=inputs.get("impact"), exposure=inputs.get("exposure"),
            effective_privilege=inputs.get("effective_privilege"),
            path_certainty=inputs.get("path_certainty"),
            credential_state=inputs.get("credential_state"),
            decision=decision.severity.value, rationale=decision.rationale))
        f.severity = decision.severity.value
        f.severity_rationale = decision.rationale
        decided += 1
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "severity.evaluated",
         {"policy_version": "sev-baseline-1.0.0", "decisions": decided})
    return NodeResult()


def digest_inputs(inputs: dict) -> str:
    from ..core.security import digest_of
    return digest_of({"v": "sev-baseline-1.0.0", "inputs": inputs})


# --- N13/N14/N15 optional enrichment --------------------------------------------------

def n13_risk(ctx: NodeCtx) -> NodeResult:
    return NodeResult(status="skipped",
                      skip_reason="No approved loss assumptions supplied; qualitative register retained (PS12).")


def n14_control_mapping(ctx: NodeCtx) -> NodeResult:
    """PS13/PS14: mapping is evidence support, not attestation; unmapped is allowed and visible."""
    from ..core.db import Finding
    from .mappings import CONTROL_MAP
    findings = ctx.session.execute(select(Finding).where(
        Finding.tenant_id == ctx.tenant_id, Finding.run_id == ctx.run.id)).scalars().all()
    mapped = {}
    for f in findings:
        entry = CONTROL_MAP.get(f.check_id, {"status": "unmapped", "controls": [],
                                             "note": "No reviewed mapping; disclosed, not fabricated (G30)."})
        mapped[f.id] = entry
    artifact = {
        "artifact_id": new_id("art"), "kind": "analysis.control_mapping",
        "producer": "control-mapper/1.0", "collected_at": utcnow().isoformat() + "Z",
        "content": {"edition": "SOC2-2017-example (illustrative; licensed text validation required)",
                    "attack_mapping_policy": "Only supported behaviors; misconfiguration is prerequisite (PS14)",
                    "mappings": mapped},
        "redaction_version": "1.0",
    }
    content_hash, signature = sign_artifact(artifact["content"])
    ctx.session.add(EvidenceArtifact(
        id=artifact["artifact_id"], tenant_id=ctx.tenant_id, run_id=ctx.run.id, snapshot_id=None,
        kind=artifact["kind"], producer=artifact["producer"], content_json=artifact["content"],
        sha256=content_hash, signature=signature, collected_at=utcnow()))
    return NodeResult()


def n15_remediation(ctx: NodeCtx) -> NodeResult:
    """N15: drafts from vetted runbook lookup; unknown remedy needs a specialist (no auto writes)."""
    from ..core.db import Finding
    from .runbooks import RUNBOOKS
    findings = ctx.session.execute(select(Finding).where(
        Finding.tenant_id == ctx.tenant_id, Finding.run_id == ctx.run.id)).scalars().all()
    drafts = []
    for f in findings:
        rb = RUNBOOKS.get(f.check_id, {
            "steps": ["Escalate to specialist: no vetted runbook for " + f.check_id],
            "retest": "Scoped passive retest after change window",
            "owner_hint": f.facts.get("owner") or "Unassigned",
        })
        drafts.append({"finding_id": f.id, "check_id": f.check_id, "title": f.title,
                       **rb, "acceptance_criteria":
                           f"Fresh complete retest shows condition absent (PS15) for {f.target_key}"})
    artifact = {
        "artifact_id": new_id("art"), "kind": "analysis.remediation_drafts",
        "producer": "remediation-drafter/1.0", "collected_at": utcnow().isoformat() + "Z",
        "content": drafts, "redaction_version": "1.0",
    }
    content_hash, signature = sign_artifact(artifact["content"])
    ctx.session.add(EvidenceArtifact(
        id=artifact["artifact_id"], tenant_id=ctx.tenant_id, run_id=ctx.run.id, snapshot_id=None,
        kind=artifact["kind"], producer=artifact["producer"], content_json=artifact["content"],
        sha256=content_hash, signature=signature, collected_at=utcnow()))
    return NodeResult()


# --- N16 report assembly ----------------------------------------------------------------

def n16_report(ctx: NodeCtx) -> NodeResult:
    from ..reports.builder import assemble_report
    report_id = assemble_report(ctx.session, tenant_id=ctx.tenant_id, run=ctx.run,
                                created_by="system:run-engine")
    # G02 parks the run at waiting_approval until an independent reviewer releases (AT13)
    ctx.run.state = RunState.WAITING_APPROVAL.value
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "report.drafted",
         {"report_id": report_id, "awaiting": "independent review release (G02)"})
    return NodeResult(new_tasks=[("G02", "-")])


# --- N17 publish -------------------------------------------------------------------------

def n17_publish(ctx: NodeCtx) -> NodeResult:
    """N17: deterministic publish of the released report digest; idempotent (N17/DC19)."""
    from ..core.db import Report
    from ..core.security import digest_of
    report = ctx.session.execute(select(Report).where(
        Report.tenant_id == ctx.tenant_id, Report.run_id == ctx.run.id)
        .order_by(Report.version.desc())).scalars().first()
    if report is None or report.status != "released":
        return NodeResult(status="failed", error="publish requires a released report (DC19)")
    emit(ctx.session, ctx.tenant_id, ctx.run.id, "report.published",
         {"report_id": report.id, "version": report.version,
          "digest": report.revision_digest or digest_of(report.content_json)})
    return NodeResult()


# --- dispatch table ------------------------------------------------------------------------

HANDLERS = {
    "N00": n00_scope_readiness, "N01": n01_plan, "N02": n02_collect, "N03": n03_normalize,
    "N04": n04_checks, "N05": n05_paths, "N06": n06_evidence, "N07": n07_proof_proposal,
    "N12": n12_severity, "N13": n13_risk, "N14": n14_control_mapping, "N15": n15_remediation,
    "N16": n16_report, "N17": n17_publish,
}
