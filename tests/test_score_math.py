"""AT18/G01 score math unit tests + PS02/PS03 severity policy decisions.

Pure policy tests: no DB, no client. Fake result rows are simple namespaces carrying
status/facts/target_id (the policy reads the dimension from facts['dimension'])."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from nhi_sentinel.contracts import Severity
from nhi_sentinel.policies.score import (
    SCORE_POLICY_VERSION,
    WEIGHTS,
    _result_dimension,
    compute_score,
    validate_weights,
)
from nhi_sentinel.policies.severity import decide_severity

DIMENSION_LABELS = {"Ownership", "Credential hygiene", "Least privilege", "Lifecycle", "Detection"}


def _view(run_id: str = "run_qa", identities=(), snapshots=()):
    """Minimal stand-in for SnapshotView (only the attributes compute_score reads)."""
    return SimpleNamespace(run_id=run_id, snapshots=list(snapshots), identities=list(identities),
                           credentials=[], ownership=[], edges=[], agents=[], artifacts={})


def _result(status: str, dimension: str, target_id: str = "t1", facts: dict | None = None):
    return SimpleNamespace(status=status, target_id=target_id,
                           facts={"dimension": dimension, **(facts or {})})


def _dim(card, label: str):
    return next(d for d in card.dimensions if d.dimension == label)


# --- G01 weights ------------------------------------------------------------------

def test_G01__shipped_weights_are_valid_and_total_one():
    validate_weights(WEIGHTS)  # must not raise
    assert round(sum(WEIGHTS.values()), 6) == 1.0
    assert set(WEIGHTS) <= {"ownership", "credential_hygiene", "least_privilege",
                            "lifecycle", "detection"}


def test_G01__weights_not_summing_to_one_raise():
    with pytest.raises(ValueError, match="1.0"):
        validate_weights({"ownership": 0.95, "lifecycle": 0.15})  # 1.10
    with pytest.raises(ValueError, match="1.0"):
        validate_weights({"ownership": 0.95, "credential_hygiene": 0.04})  # 0.99


# --- PS11 aggregation ----------------------------------------------------------------

def test_PS11__unmeasured_dimension_withholds_aggregate_score():
    card = compute_score(_view(), [])
    assert card.policy_version == SCORE_POLICY_VERSION
    assert card.weights_total == 1.0
    assert {d.dimension for d in card.dimensions} == DIMENSION_LABELS
    detection = _dim(card, "Detection")
    assert detection.status == "unavailable"
    assert detection.pass_rate is None and detection.completeness is None
    assert detection.unavailable_reason  # always explained, never silently zero
    assert card.aggregate_status == "unavailable"
    assert card.observed_scope_score is None
    assert "unmeasured dimensions" in card.aggregate_reason


def test_PS11__aggregate_reason_names_the_unmeasured_dimensions():
    view = _view(identities=[SimpleNamespace(id="ide_1")])
    card = compute_score(view, [_result("pass", "ownership", target_id="ide_1")])
    assert card.aggregate_status == "unavailable"
    assert "Detection" in card.aggregate_reason, "detection is never measured in pilot (PS11)"
    assert "Credential hygiene" in card.aggregate_reason


def test_PS08__zero_passing_is_zero_not_none():
    view = _view(identities=[SimpleNamespace(id="ide_1"), SimpleNamespace(id="ide_2")])
    results = [_result("fail", "ownership", target_id="ide_1"),
               _result("fail", "ownership", target_id="ide_2")]
    card = compute_score(view, results)
    ownership = _dim(card, "Ownership")
    assert ownership.status == "measured"
    assert ownership.assessed == 2 and ownership.passing == 0
    assert ownership.pass_rate == 0.0, "0/2 must be 0.0, never None or unavailable"
    assert card.aggregate_status == "unavailable"  # detection still unmeasured


def test_PS06__pass_rate_is_per_target_boolean_share():
    view = _view(identities=[SimpleNamespace(id="a"), SimpleNamespace(id="b")])
    results = [_result("pass", "least_privilege", target_id="a"),
               _result("fail", "least_privilege", target_id="b"),
               _result("fail", "least_privilege", target_id="b")]  # repeat observation
    card = compute_score(view, results)
    lp = _dim(card, "Least privilege")
    assert lp.assessed == 2 and lp.passing == 1
    assert lp.pass_rate == 0.5


def test_result_dimension_reads_facts():
    assert _result_dimension(_result("pass", "ownership")) == "ownership"
    assert _result_dimension(_result("pass", "x", facts={"dimension": "lifecycle"})) == "lifecycle"
    assert _result_dimension(SimpleNamespace(status="pass", facts=None)) == ""


# --- PS02/PS03 severity policy ---------------------------------------------------------

def test_PS02__missing_essential_inputs_yield_undetermined():
    decision = decide_severity({})
    assert decision.severity == Severity.UNDETERMINED
    assert set(decision.missing) == {"impact", "exposure", "effective_privilege"}
    assert "PS02" in decision.rationale


def test_PS03__confirmed_untrusted_path_to_critical_asset_is_critical():
    decision = decide_severity({
        "impact": "critical", "exposure": "untrusted", "effective_privilege": "elevated",
        "path_certainty": "confirmed",
    })
    assert decision.severity == Severity.CRITICAL
    assert "PS03" in decision.rationale


def test_PS03__exposed_enabled_privileged_credential_is_critical():
    decision = decide_severity({
        "impact": "critical", "exposure": "internal", "effective_privilege": "elevated",
        "credential_state": "exposed",
    })
    assert decision.severity == Severity.CRITICAL
    assert "PS03" in decision.rationale


def test_PS03__elevated_internal_reach_is_high_not_critical():
    decision = decide_severity({
        "impact": "high", "exposure": "internal", "effective_privilege": "elevated",
        "path_certainty": "none", "credential_state": "enabled",
    })
    assert decision.severity == Severity.HIGH


def test_PS04__bounded_hygiene_weakness_is_medium_or_low():
    medium = decide_severity({"impact": "moderate", "exposure": "internal",
                              "effective_privilege": "limited"})
    assert medium.severity == Severity.MEDIUM
    low = decide_severity({"impact": "low", "exposure": "constrained",
                           "effective_privilege": "limited"})
    assert low.severity == Severity.LOW
