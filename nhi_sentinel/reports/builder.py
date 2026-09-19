"""Deterministic report assembly and grounding validation (N16, DC19, PS13/PS14, AT13).

Facts come only from evaluated canonical findings (drafts are structurally excluded:
quarantined/unknown check results were never promoted by N06). Every factual claim carries
evidence references; release is blocked while any claim is unsupported (G02/AT13).
Optional LLM narrative: disabled - the deterministic template is the fallback and the default."""
from __future__ import annotations

from sqlalchemy import select

from ..core.db import (
    CheckResult, EvidenceArtifact, Finding, Report, Run, new_id, utcnow,
)
from ..core.events import emit
from ..core.security import digest_of, hmac_obj
from ..policies.score import compute_score
from ..core.repo import load_snapshot_view

TEMPLATE_VERSION = "baseline_v1/1.0.0"


def assemble_report(session, *, tenant_id: str, run: Run, created_by: str) -> str:
    findings = session.execute(select(Finding).where(
        Finding.tenant_id == tenant_id, Finding.run_id == run.id)
        .order_by(Finding.severity, Finding.check_id)).scalars().all()
    results = session.execute(select(CheckResult).where(
        CheckResult.tenant_id == tenant_id, CheckResult.run_id == run.id)).scalars().all()
    view = load_snapshot_view(tenant_id, run.id, session=session)
    score = compute_score(view, results)

    claims: list[dict] = []
    sections: dict = {}

    def add_claim(section: str, text: str, evidence_refs=None, finding_ids=None) -> str:
        cid = f"claim-{len(claims) + 1:03d}"
        claims.append({"claim_id": cid, "section": section, "text": text,
                       "evidence_refs": list(evidence_refs or []),
                       "finding_ids": list(finding_ids or []), "ai_generated": False})
        return cid

    # Executive summary claims (counts must reconcile with finding rows - AT13)
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary_bits = [f"{n} {sev}" for sev, n in sorted(sev_counts.items())]
    artifact_ids = sorted(view.artifacts.keys())
    add_claim("executive_summary",
              ("The observed-scope assessment evaluated "
               f"{len(findings)} findings across {len(view.snapshots)} collected sources: "
               + (", ".join(summary_bits) if summary_bits else "no weaknesses met fail criteria") + "."),
              evidence_refs=artifact_ids)
    if score.aggregate_status == "unavailable":
        add_claim("posture_score",
                  f"The aggregate posture score is unavailable: {score.aggregate_reason}",
                  evidence_refs=artifact_ids)
    else:
        add_claim("posture_score",
                  f"The observed-scope posture score is {score.observed_scope_score} of 100 "
                  f"({score.aggregate_reason or 'all dimensions at or above the completeness gate'}).",
                  evidence_refs=artifact_ids)

    # Coverage claims per snapshot (partial collection is disclosed, never hidden - AT08)
    for snap in view.snapshots:
        state_line = (f"Source {snap.source} collection is {snap.state}"
                      + (f" with completeness {snap.completeness}" if snap.completeness is not None else "")
                      + (f"; {len(snap.page_errors_json)} page/collection errors recorded"
                         if snap.page_errors_json else "; no collection errors recorded") + ".")
        ref = [a.id for a in view.artifacts.values() if a.snapshot_id == snap.id]
        add_claim("scope_and_coverage", state_line, evidence_refs=sorted(ref))

    # Findings detail: every claim references its finding and its evidence
    for f in findings:
        add_claim("findings_detail",
                  f"Finding {f.check_id} on {f.target_key}: {f.summary} "
                  f"(severity {f.severity}, assurance {f.assurance}).",
                  evidence_refs=list(f.evidence_refs_json), finding_ids=[f.id])

    limitations = _limitations(view, score, findings)

    content = {
        "template": TEMPLATE_VERSION,
        "title": "NHI Sentinel baseline assessment (synthetic demo)",
        "run_id": run.id,
        "scope": run.versions_json.get("coverage", []),
        "executive_summary": {"finding_counts": sev_counts, "total": len(findings)},
        "posture_score": score.model_dump(mode="json"),
        "sections": {"claims": claims},
        "findings": [{
            "finding_id": f.id, "check_id": f.check_id, "target_key": f.target_key,
            "severity": f.severity, "assurance": f.assurance, "title": f.title,
            "summary": f.summary, "rationale": f.severity_rationale,
            "evidence_refs": f.evidence_refs_json,
        } for f in findings],
        "limitations": limitations,
    }
    grounding = validate_grounding(content, evidence_universe=_evidence_universe(view, results),
                                   finding_universe={f.id for f in findings})
    report = Report(
        id=new_id("rpt"), tenant_id=tenant_id, run_id=run.id, version=1, status="draft",
        template=TEMPLATE_VERSION, content_json=content, claims_json=claims,
        limitations_json=limitations, grounding_json=grounding,
        revision_digest=digest_of({"content": content, "claims": claims}),
        created_by=created_by, created_at=utcnow())
    session.add(report)
    session.flush()
    return report.id


def _evidence_universe(view, results) -> set[str]:
    ids = set(view.artifacts.keys())
    ids.update(r.id for r in results)
    return ids


def _limitations(view, score, findings) -> list[str]:
    lims = []
    for snap in view.snapshots:
        if snap.state != "complete":
            lims.append(f"Source {snap.source} snapshot is {snap.state}; "
                        "absence of findings there is not evidence of safety (AT08).")
    if score.aggregate_status == "unavailable":
        lims.append(f"Aggregate posture score withheld: {score.aggregate_reason}")
    lims.append("All pilot checks are passive; assurance is configuration-supported only (D06, PS01).")
    unmapped = [f.check_id for f in findings
                if (f.facts or {}).get("control_status") == "unmapped"]
    if unmapped:
        lims.append("Unmapped controls disclosed for: " + ", ".join(sorted(set(unmapped)))
                    + " (G30 - unmapped does not erase findings).")
    return lims


def validate_grounding(content: dict, evidence_universe: set[str], finding_universe: set[str]) -> dict:
    """AT13: unsupported claims, invalid citations, contradicted citations and count mismatches
    must block release. Returns grounding report persisted with the report."""
    unsupported = []
    claims = content.get("sections", {}).get("claims", [])
    for claim in claims:
        bad_ev = [r for r in claim.get("evidence_refs", []) if r not in evidence_universe]
        bad_f = [f for f in claim.get("finding_ids", []) if f not in finding_universe]
        if bad_ev or bad_f:
            unsupported.append({"claim_id": claim["claim_id"], "bad_evidence": bad_ev,
                                "bad_findings": bad_f})
    # reconcile executive summary counts with findings detail
    exec_counts = content.get("executive_summary", {}).get("finding_counts", {})
    recomputed: dict[str, int] = {}
    for f in content.get("findings", []):
        recomputed[f["severity"]] = recomputed.get(f["severity"], 0) + 1
    if exec_counts != recomputed:
        unsupported.append({"claim_id": "executive_summary",
                            "bad_evidence": ["count mismatch: "
                                             f"{exec_counts} != {recomputed}"], "bad_findings": []})
    return {"claims_total": len(claims),
            "claims_supported": len(claims) - len(unsupported),
            "unsupported": unsupported,
            "validated_at": utcnow().isoformat() + "Z",
            "validator": "grounding/1.0"}


def release_report(session, *, tenant_id: str, report_id: str, reviewer_id: str,
                   review_record: str) -> Report:
    """G02: independent review release. Factual defects block; signature binds the revision."""
    report = session.get(Report, report_id)
    from .core_guard import assert_tenant
    assert_tenant(report, tenant_id)
    if report.status not in ("draft", "in_review"):
        raise ValueError("only draft/in_review reports can be released")
    if report.created_by == reviewer_id or report.created_by.endswith(reviewer_id):
        raise ValueError("report release requires a reviewer other than the author (SC05)")
    grounding = report.grounding_json or {}
    if grounding.get("unsupported"):
        raise ValueError(f"report grounded check failed: {len(grounding['unsupported'])} "
                         "unsupported claims block release (AT13)")
    report.status = "released"
    report.reviewer_id = reviewer_id
    report.review_record = review_record[:1000]
    report.released_at = utcnow()
    report.signature = hmac_obj({"digest": report.revision_digest, "reviewer": reviewer_id})
    return report
