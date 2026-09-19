"""Deterministic assistant (API24/UX12/VD10): citation-backed answers over run data only.

No LLM in the pilot (AR13 fallback is the default): every answer is generated from the
canonical data store and carries citations the client can render and verify. It cannot
execute actions, approve anything, or fetch network content. An LLM provider hook exists
but is disabled by config; when enabled it may only REWRITE grounded sections (SC17/AT40
evals gate promotion)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from .core.db import CheckResult, Finding, Report, Run, Snapshot
from .policies.score import compute_score
from .core.repo import load_snapshot_view

MODEL = "deterministic-explainer/1.0"
LIMITATIONS = [
    "Answers are generated only from run data in this tenant; nothing is invented.",
    "This assistant cannot execute actions, approve, or change any object.",
    "AI-labeled summaries are aids, not evidence of correctness (UX06).",
]

INJECTION_MARKERS = ("ignore previous", "ignore all", "disregard", "reveal the secret",
                     "reveal secret", "system prompt", "execute", "run command")


@dataclass
class AssistantAnswer:
    answer: str
    citations: list[dict]
    ai_generated: bool = False
    model: str = MODEL
    limitations: list[str] = None

    def __post_init__(self):
        if self.limitations is None:
            self.limitations = LIMITATIONS


def answer(session, *, tenant_id: str, question: str, object_refs: list[dict] | None = None) -> AssistantAnswer:
    q = (question or "").lower().strip()
    refs = object_refs or []
    # untrusted input stays data: instructions inside the question are never followed (SC09)
    if any(m in q for m in INJECTION_MARKERS):
        return AssistantAnswer(
            "I can only answer questions about assessment data in this tenant. Instructions "
            "inside your message are treated as untrusted text, not commands (SC09).",
            citations=[])
    citations: list[dict] = []

    # object-scoped explanation
    for ref in refs:
        if ref.get("type") == "finding":
            f = session.get(Finding, ref.get("id"))
            if f is not None and f.tenant_id == tenant_id:
                citations.append({"type": "finding", "id": f.id, "label": f"{f.check_id} {f.target_key}"})
                return AssistantAnswer(
                    f"Finding {f.check_id} on {f.target_key}: {f.summary} "
                    f"Severity {f.severity} was decided by {f.severity_rationale} "
                    f"Evidence assurance is {f.assurance}; lifecycle status is {f.workflow_status}.",
                    citations=citations + [{"type": "evidence", "id": r, "label": r[:16]}
                                           for r in (f.evidence_refs_json or [])[:5]])

    if "score" in q or "posture" in q:
        run = session.execute(select(Run).where(Run.tenant_id == tenant_id)
                              .order_by(Run.created_at.desc())).scalars().first()
        if run is None:
            return AssistantAnswer("No runs exist yet, so no score can be reported.", citations=[])
        results = session.execute(select(CheckResult).where(
            CheckResult.tenant_id == tenant_id, CheckResult.run_id == run.id)).scalars().all()
        view = load_snapshot_view(tenant_id, run.id, session=session)
        card = compute_score(view, results)
        lines = []
        for d in card.dimensions:
            if d.status == "measured":
                lines.append(f"- {d.dimension}: {round((d.pass_rate or 0) * 100)}% pass, "
                             f"completeness {round((d.completeness or 0) * 100)}%")
            else:
                lines.append(f"- {d.dimension}: unavailable ({d.unavailable_reason})")
        verdict = (f"Observed-scope score {card.observed_scope_score}/100."
                   if card.aggregate_status == "measured"
                   else f"Aggregate withheld: {card.aggregate_reason}")
        citations.append({"type": "run", "id": run.id, "label": run.id})
        return AssistantAnswer(f"Posture score for run {run.id}:\n" + "\n".join(lines) +
                               f"\n{verdict}", citations=citations)

    if "finding" in q or "weakness" in q or "risk" in q:
        findings = session.execute(select(Finding).where(Finding.tenant_id == tenant_id)
                                   .order_by(Finding.severity, Finding.updated_at.desc())
                                   .limit(10)).scalars().all()
        if not findings:
            return AssistantAnswer("No evaluated findings exist yet in this tenant.", citations=[])
        for f in findings:
            citations.append({"type": "finding", "id": f.id, "label": f"{f.check_id} {f.target_key}"})
        summary_bits = [f"{n} {sev}" for sev, n in sorted(_count_by(findings, "severity").items())]
        return AssistantAnswer(
            f"Top evaluated findings ({len(findings)} shown): " + ", ".join(summary_bits) + ". "
            "Highest-impact items are listed first in citations - open one for its evidence chain.",
            citations=citations)

    if "coverage" in q or "collect" in q or "source" in q:
        run = session.execute(select(Run).where(Run.tenant_id == tenant_id)
                              .order_by(Run.created_at.desc())).scalars().first()
        if run is None:
            return AssistantAnswer("No runs exist yet.", citations=[])
        snaps = session.execute(select(Snapshot).where(
            Snapshot.tenant_id == tenant_id, Snapshot.run_id == run.id)).scalars().all()
        lines = [f"- {sn.source}: {sn.state}" +
                 (f", completeness {sn.completeness}" if sn.completeness is not None else "")
                 for sn in snaps]
        citations.append({"type": "run", "id": run.id, "label": run.id})
        return AssistantAnswer(f"Coverage for run {run.id}:\n" + "\n".join(lines) +
                               "\nPartial sources mean gaps are visible, not safe (AT08).",
                               citations=citations)

    return AssistantAnswer(
        "I can answer from assessment data only. Try asking about findings, the posture "
        "score, or collection coverage - optionally with an object selected.",
        citations=[])


def _count_by(items, key) -> dict:
    out: dict[str, int] = {}
    for i in items:
        out[getattr(i, key)] = out.get(getattr(i, key), 0) + 1
    return out
