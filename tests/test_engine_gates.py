"""AT07/G05/AT10 engine behavior: emergency stop halts dispatch; passive run parks at the
G02 release gate with skipped optional branches (N07/N13) propagated to their chains."""
from __future__ import annotations

from sqlalchemy import func, select

from nhi_sentinel.core.db import Snapshot, session_scope

from .conftest import ANALYST, get_run, login, run_full_pass, start_run

TASK_TERMINAL = {"succeeded", "failed", "unknown", "skipped", "cancelled"}


def _snapshot_count(tenant_id: str, run_id: str) -> int:
    with session_scope() as s:
        return s.execute(select(func.count()).select_from(Snapshot).where(
            Snapshot.tenant_id == tenant_id, Snapshot.run_id == run_id)).scalar() or 0


def test_AT07__emergency_stop_cancels_fresh_run_and_halts_dispatch(client):
    from nhi_sentinel.worker import engine

    analyst = login(client, ANALYST)
    tenant_a = analyst["tenant_id"]

    # Hold the engine dispatch lock so the background loop cannot tick between run
    # creation and the kill: the stop is race-free and the run never collects.
    with engine._dispatch_lock:
        run_id = start_run(client, analyst)
        out = engine.emergency_stop(tenant_a, run_id, "qa-operator")
    assert out["state"] == "cancelled"

    before = _snapshot_count(tenant_a, run_id)
    engine.run_until_quiescent()
    after = _snapshot_count(tenant_a, run_id)
    assert after == before, f"dispatch continued after emergency stop ({before} -> {after} snapshots)"

    run = get_run(client, analyst, run_id)
    assert run["state"] == "cancelled"
    assert run["kill_requested"] is True
    assert run["tasks"], "run tasks should be visible"
    assert all(t["state"] in TASK_TERMINAL for t in run["tasks"]), \
        "no task may still be dispatchable after the kill (SC18)"
    assert not any(t["node"].startswith("N02") and t["state"] == "succeeded"
                   for t in run["tasks"]), "no collection task may have run after the stop"


def test_G05_AT10__passive_run_parks_at_release_gate_with_skipped_optionals(client):
    analyst = login(client, ANALYST)
    run_id = run_full_pass(client, analyst)

    run = get_run(client, analyst, run_id)
    # parked at the human release gate, not finalized
    assert run["state"] == "waiting_approval"
    assert run["state"] not in ("succeeded", "partial", "failed")

    tasks = {t["node"]: t for t in run["tasks"]}
    g02 = tasks.get("G02")
    assert g02 is not None and g02["state"] == "pending", \
        "G02 (report release gate) must be parked pending (AT13)"

    # optional proof branch skipped with an explicit reason, chain propagated (AT10 fan-in)
    n07 = tasks.get("N07")
    assert n07 is not None and n07["state"] == "skipped"
    assert n07["skip_reason"], "N07 skip must carry a reason"
    assert "Active proof disabled" in n07["skip_reason"] or "D06" in n07["skip_reason"]
    for node in ("G01", "N08", "N09"):
        t = tasks.get(node)
        assert t is not None and t["state"] == "skipped", \
            f"{node}: dormant proof chain must be skipped"
        assert "skipped" in (t["skip_reason"] or "").lower()

    # optional risk-scenario branch skipped with reason
    n13 = tasks.get("N13")
    assert n13 is not None and n13["state"] == "skipped"
    assert n13["skip_reason"], "N13 skip must carry a reason (no invented loss assumptions)"

    # G05: check evaluation nodes ran on validated snapshots only; core path succeeded
    assert tasks["N00"]["state"] == "succeeded"
    assert tasks["N06"]["state"] == "succeeded"
    assert tasks["N12"]["state"] == "succeeded"


def test_AT07__run_state_visible_via_get_run(client):
    analyst = login(client, ANALYST)
    run_id = run_full_pass(client, analyst)
    run = get_run(client, analyst, run_id)
    for field in ("run_id", "state", "mode", "epoch", "revision", "kill_requested",
                  "tasks", "coverage", "created_at"):
        assert field in run, f"GET /v1/runs/{{id}} missing field {field}"
    assert run["run_id"] == run_id
    assert run["mode"] == "passive"
    # coverage snapshots visible with completeness metadata (DC09)
    assert run["coverage"], "coverage entries expected for the four pilot sources"
    for cov in run["coverage"]:
        assert {"source", "state", "seen", "expected", "completeness"} <= set(cov)
