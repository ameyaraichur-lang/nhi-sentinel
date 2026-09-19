"""AT27 golden outcome runner: binds the fixture corpus to check results of a full run.

Reads tests/golden/expected_outcomes.json generically (the fixtures/checks work packages own
its content). Supported shapes:
  - "expected": [{check_id, target_key_contains, status}, ...]
  - legacy placeholders: expected_fail_results / expected_pass_contains / expected_unknown_contains
  - "counts": {check_id: {status: min_count}} and/or "min_results_per_check": {check_id: min_total}
  - "min_total_results": int, "partial_sources": [source, ...]
  - "disabled_checks": {check_id: note} (or [check_id, ...]) — certified-but-disabled ids
"""
from __future__ import annotations

import json

from nhi_sentinel.checks.base import REGISTRY
from nhi_sentinel.seed import PILOT_CHECK_IDS

from .conftest import ANALYST, db_results, load_golden, login

_STATUS_FALLBACKS = (
    ("expected_fail_results", "fail"),
    ("expected_pass_contains", "pass"),
    ("expected_unknown_contains", "unknown"),
)


def _disabled_checks(data: dict) -> dict:
    """Normalize disabled_checks to {id: note} (accepts dict or list form)."""
    raw = data.get("disabled_checks") or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {str(k): "disabled" for k in raw}


def _expected_rows(data: dict) -> list[dict]:
    rows = []
    if isinstance(data.get("expected"), list):
        for row in data["expected"]:
            if isinstance(row, dict) and row.get("check_id"):
                rows.append({
                    "check_id": str(row["check_id"]),
                    "fragment": str(row.get("target_key_contains")
                                    or row.get("target") or row.get("fragment") or ""),
                    "status": str(row.get("status", "")).lower(),
                })
    for key, status in _STATUS_FALLBACKS:
        for entry in data.get(key) or []:
            if isinstance(entry, dict) and entry.get("check_id"):
                rows.append({
                    "check_id": str(entry["check_id"]),
                    "fragment": str(entry.get("target_key_contains")
                                    or entry.get("target") or entry.get("fragment") or ""),
                    "status": status,
                })
            elif isinstance(entry, str) and "|" in entry:  # "CHECK-ID|fragment" shorthand
                check_id, fragment = entry.split("|", 1)
                rows.append({"check_id": check_id.strip(), "fragment": fragment.strip(),
                             "status": status})
    return rows


def test_AT27__golden_expected_outcomes_match_full_run(client, full_run_id):
    data = load_golden()
    analyst = login(client, ANALYST)
    results = db_results(analyst["tenant_id"], full_run_id)
    assert results, "a full pass must persist check results"
    disabled = _disabled_checks(data)

    # every expected row must have a matching CheckResult with the expected status
    for row in _expected_rows(data):
        if row["check_id"] not in REGISTRY and row["check_id"] in disabled:
            continue  # expected outcomes of disabled checks cannot be observed
        candidates = [r for r in results if r["check_id"] == row["check_id"]]
        # prefer exact target_key matches; fall back to the documented contains-fragment
        exact = [r for r in candidates if r["target_key"] == row["fragment"]]
        matches = exact or [r for r in candidates
                            if row["fragment"].lower() in r["target_key"].lower()]
        assert matches, f"no CheckResult for {row['check_id']} with target_key containing " \
                        f"'{row['fragment']}'"
        statuses = {r["status"] for r in matches}
        assert row["status"] in statuses, \
            f"{row['check_id']} on '{row['fragment']}': expected status " \
            f"'{row['status']}', got {sorted(statuses)}"

    # per-check minimum counts, where provided
    counts = data.get("counts") or {}
    for check_id, per_status in counts.items():
        actual = {}
        for r in results:
            if r["check_id"] == check_id:
                actual[r["status"]] = actual.get(r["status"], 0) + 1
        for status, minimum in (per_status or {}).items():
            assert actual.get(status, 0) >= minimum, \
                f"{check_id}: expected >= {minimum} '{status}' results, got " \
                f"{actual.get(status, 0)} (all: {actual})"

    min_per_check = data.get("min_results_per_check") or {}
    for check_id, minimum in min_per_check.items():
        total = sum(1 for r in results if r["check_id"] == check_id)
        assert total >= minimum, \
            f"{check_id}: expected >= {minimum} results, got {total}"

    min_total = data.get("min_total_results")
    if min_total:
        assert len(results) >= min_total, \
            f"expected >= {min_total} total results, got {len(results)}"

    # disclosed partial sources must be observable as partial snapshots
    partial_sources = data.get("partial_sources") or []
    if partial_sources:
        snapshots = {s["source"]: s for s in client.get(
            "/v1/snapshots", params={"run_id": full_run_id}).json()}
        for source in partial_sources:
            snap = snapshots.get(source)
            assert snap is not None, f"no snapshot collected for source '{source}'"
            assert snap["state"] == "partial", \
                f"source '{source}' must be partial (disclosed gap), got {snap['state']}"


def test_AT27__entra_snapshot_is_partial_with_recorded_page_errors(client, full_run_id):
    """The matrix pins entra as a partial source (sign-in audit 403): a disclosed gap."""
    login(client, ANALYST)
    rows = client.get("/v1/snapshots", params={"run_id": full_run_id}).json()
    entra = [s for s in rows if s["source"] == "entra"]
    assert entra, "entra snapshot missing from the full run"
    assert all(s["state"] == "partial" for s in entra), \
        f"entra must be partial per the scenario matrix: {[(s['state'], s['page_errors']) for s in entra]}"
    assert any(s["page_errors"] for s in entra), "partial entra snapshot must record page errors"


def test_AT27__pilot_catalog_ids_registered_or_explicitly_disabled():
    """Every pilot check id is either a certified registry entry or explicitly disabled
    in expected_outcomes.json (never silently dropped)."""
    data = load_golden()
    disabled = _disabled_checks(data)
    missing = [cid for cid in PILOT_CHECK_IDS
               if cid not in REGISTRY and cid not in disabled]
    assert not missing, \
        f"pilot check ids neither registered nor disabled: {missing} " \
        f"(registered: {sorted(REGISTRY)}; disabled: {sorted(disabled)})"


def test_AT27__golden_file_is_parseable_and_disabled_checks_annotated():
    data = load_golden()
    assert isinstance(data, dict)
    assert "disabled_checks" in data, "golden file must carry the disabled_checks key"
    assert _disabled_checks(data), "disabled_checks must list at least AGI-012 with a note"
