"""PS06-PS11 posture score: measured pass rates per dimension with visible completeness.

Aggregates only when every dimension is measured (PS11) and weights sum to exactly 1.0
(G01/AT18). Missing inputs stay unavailable — never zero, never silently normalized."""
from __future__ import annotations

from ..contracts.models import DimensionScore, ScoreCard
from .severity import inputs_from_facts

WEIGHTS = {
    "ownership": 0.20,
    "credential_hygiene": 0.25,
    "least_privilege": 0.25,
    "lifecycle": 0.15,
    "detection": 0.15,
}
SCORE_POLICY_VERSION = "score-1.0.0"
CUSTOMER_WIDE_COMPLETENESS_GATE = 0.90  # PS07: proposed policy threshold, not a standard

_DIMENSION_LABELS = {
    "ownership": "Ownership",
    "credential_hygiene": "Credential hygiene",
    "least_privilege": "Least privilege",
    "lifecycle": "Lifecycle",
    "detection": "Detection",
}


def validate_weights(weights: dict[str, float]) -> None:
    total = round(sum(weights.values()), 6)
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"Score weights must total 1.0; got {total} (G01 correction)")


def _eligible_universe(dim: str, view) -> set[str]:
    """Observed eligible population per dimension (PS08: document the universe).
    Partial sources understate this -> completeness label becomes estimated."""
    if dim == "ownership":
        return {i.id for i in view.identities}
    if dim == "credential_hygiene":
        ids = {c.identity_id for c in view.credentials}
        # secret-candidate pseudo-targets join the hygiene universe
        for a in view.artifacts.values():
            if a.kind == "collection.secret_candidates":
                for sc in a.content_json:
                    ids.add(f"secret|{sc.get('repo')}|{sc.get('path')}")
        return ids
    if dim == "least_privilege":
        return {i.id for i in view.identities}
    if dim == "lifecycle":
        return {i.id for i in view.identities}
    return set()  # detection: agreed scenarios define eligible; none agreed in pilot


def compute_score(view, check_results: list) -> ScoreCard:
    """check_results: DB CheckResult rows for the run (status/facts/target)."""
    validate_weights(WEIGHTS)
    sources_partial = any(s.state == "partial" for s in view.snapshots)

    dims: list[DimensionScore] = []
    for dim, weight in WEIGHTS.items():
        if dim == "detection":
            # PS11: no agreed, exercised scenarios in pilot -> aggregate unavailable.
            dims.append(DimensionScore(
                dimension=_DIMENSION_LABELS[dim], weight=weight, eligible=0, assessed=0, passing=0,
                pass_rate=None, completeness=None, status="unavailable",
                unavailable_reason="No agreed detection scenarios exercised in pilot (PS11)."))
            continue
        universe = _eligible_universe(dim, view)
        results = [r for r in check_results
                   if r.status in ("pass", "fail") and _result_dimension(r) == dim]
        assessed_targets = {r.target_id for r in results}
        passing = len({r.target_id for r in results if r.status == "pass"})
        eligible = len(universe | assessed_targets)  # targets outside observed universe are visible too
        completeness = round(len(assessed_targets) / eligible, 4) if eligible else None
        dims.append(DimensionScore(
            dimension=_DIMENSION_LABELS[dim], weight=weight,
            eligible=eligible, assessed=len(assessed_targets), passing=passing,
            pass_rate=round(passing / len(assessed_targets), 4) if assessed_targets else None,
            completeness=completeness,
            status="measured" if assessed_targets else "unavailable",
            unavailable_reason=None if assessed_targets else "No applicable control-set results in observed scope.",
            ))
    measured = [d for d in dims if d.status == "measured"]
    complete_all = all(
        d.completeness is not None and d.completeness >= CUSTOMER_WIDE_COMPLETENESS_GATE
        for d in dims)
    if len(measured) < len(dims):
        missing = [d.dimension for d in dims if d.status != "measured"]
        card = ScoreCard(run_id=view.run_id, policy_version=SCORE_POLICY_VERSION, dimensions=dims,
                         observed_scope_score=None, aggregate_status="unavailable",
                         aggregate_reason=("Aggregate withheld: unmeasured dimensions: " + ", ".join(missing)
                                           + " (PS11 - show dimension results, never invent a score)."),
                         weights_total=round(sum(WEIGHTS.values()), 6))
        return card
    score = sum(d.pass_rate * d.weight for d in measured) * 100.0
    reason = None
    if sources_partial:
        reason = ("Provisional observed-scope score: at least one source snapshot is partial; "
                  "customer-wide completeness gate not evaluated (PS07/PS09).")
    elif not complete_all:
        reason = "Observed-scope score only; one or more dimensions below completeness gate (PS07)."
    return ScoreCard(run_id=view.run_id, policy_version=SCORE_POLICY_VERSION, dimensions=dims,
                     observed_scope_score=round(score, 1), aggregate_status="measured",
                     aggregate_reason=reason, weights_total=round(sum(WEIGHTS.values()), 6))


def _result_dimension(result) -> str:
    """Dimension carried on the result by the engine when persisting check outcomes."""
    return (result.facts or {}).get("dimension", "")
