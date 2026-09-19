"""Durable workflow engine (AR03, DC03/DC04, EX01/EX02, OP02/OP03, G05-G07, G12-G13).

- Tasks are durable rows; dispatch records a lease; terminal results commit with the
  events they emit in one transaction (OP05 outbox).
- Max attempts bounded with backoff (OP02); changed scope is a new epoch, never a retry (G06).
- Human gates (G01/G02) park as pending tasks; dedicated APIs complete them (G12: approvals
  never come from run counters; no automatic autonomy promotion).
- Skip propagation: a skipped optional branch marks its dormant downstream chain skipped so
  fan-in joins correctly (AT10). Draft/quarantined data never bypasses evaluation (G05).
- Kill/pause checked before every dispatch (SC18/AT07); pause stops dispatch only."""
from __future__ import annotations

import random
import threading
import time
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select

from ..config import get_settings
from ..contracts import RunState, SnapshotState, TaskState, RUN_TRANSITIONS, RUN_TERMINAL
from ..core.db import Run, Task, new_id, session_scope, utcnow
from ..core.events import emit
from . import graph, nodes

_dispatch_lock = threading.RLock()

HUMAN_GATES = {nid for nid, spec in graph.NODES.items() if spec.executor == "human_gate"}


class EngineError(RuntimeError):
    pass


# --- run lifecycle -----------------------------------------------------------------

def create_run_tasks(tenant_id: str, run_id: str) -> None:
    with session_scope() as s:
        run = s.get(Run, run_id)
        _assert_tenant(run, tenant_id)
        _add_task(s, run, "N00", "-")
        emit(s, tenant_id, run_id, "run.created", {"mode": run.mode, "epoch": run.epoch})
        run.state = RunState.QUEUED.value


def run_command(tenant_id: str, run_id: str, command: str, expected_revision: int, actor_id: str) -> dict:
    """API08: pause/resume/cancel with optimistic revision (UX07)."""
    with session_scope() as s:
        run = s.get(Run, run_id)
        _assert_tenant(run, tenant_id)
        if run.revision != expected_revision:
            from fastapi import HTTPException
            raise HTTPException(409, detail={"code": "REVISION_CONFLICT",
                                             "message": "Run was modified concurrently.",
                                             "retryable": False,
                                             "details": {"current_revision": run.revision}})
        if command == "pause":
            _transition(run, RunState.PAUSE_REQUESTED)
        elif command == "resume":
            _transition(run, RunState.QUEUED)
        elif command == "cancel":
            _transition(run, RunState.CANCEL_REQUESTED)
        run.revision += 1
        emit(s, tenant_id, run_id, "run.command", {"command": command, "actor": actor_id})
        return {"run_id": run_id, "state": run.state, "revision": run.revision,
                "note": "request acknowledged; pause/cancel settle when dispatch stops (EX01)"}


def emergency_stop(tenant_id: str, run_id: str, actor_id: str) -> dict:
    """API09/SC18: independent kill path; denies new dispatch immediately; cancels leases."""
    with session_scope() as s:
        run = s.get(Run, run_id)
        _assert_tenant(run, tenant_id)
        run.kill_requested = True
        outstanding = []
        terminal_vals = {st.value for st in TASK_TERMINAL_STATES()}
        for t in s.execute(select(Task).where(
                Task.run_id == run_id, Task.state.notin_(terminal_vals))).scalars():
            if t.state in (TaskState.LEASED.value, TaskState.RUNNING.value):
                t.state = TaskState.UNKNOWN.value
                outstanding.append({"task_id": t.id, "node": t.node})
            else:
                t.state = TaskState.CANCELLED.value
        if run.state not in RUN_TERMINAL:
            run.state = RunState.CANCELLED.value
            run.finished_at = utcnow()
        emit(s, tenant_id, run_id, "run.killed", {"actor": actor_id, "outstanding": outstanding})
    return {"run_id": run_id, "state": "cancelled", "outstanding_inflight": outstanding,
            "note": "already-sent provider calls may complete and are reconciled (UX08)"}


def TASK_TERMINAL_STATES():
    return {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.UNKNOWN,
            TaskState.SKIPPED, TaskState.CANCELLED}


def complete_external_gate(tenant_id: str, run_id: str, node: str, ok: bool, note: str) -> None:
    """Called by the report release API (G02) to unblock the parked run."""
    with session_scope() as s:
        task = s.execute(select(Task).where(Task.run_id == run_id, Task.node == node)).scalars().first()
        if task is None:
            raise EngineError(f"gate task {node} missing")
        task.state = TaskState.SUCCEEDED.value if ok else TaskState.SKIPPED.value
        task.skip_reason = None if ok else note
        run = s.get(Run, run_id)
        if run.state == RunState.WAITING_APPROVAL.value:
            run.state = RunState.RUNNING.value
        emit(s, tenant_id, run_id, "run.gate_released", {"node": node, "ok": ok, "note": note})


# --- scheduler -----------------------------------------------------------------------

def tick() -> int:
    """One scheduler pass; returns number of tasks executed/transitioned."""
    with _dispatch_lock:
        executed = 0
        executed += _settle_pause_cancel()
        for tenant_id, run_id in _dispatchable_runs():
            executed += _process_run(tenant_id, run_id)
        return executed


def _settle_pause_cancel() -> int:
    """EX01: pause_requested -> paused after dispatch stops; cancel_requested -> cancelled."""
    changed = 0
    with session_scope() as s:
        for run in s.execute(select(Run).where(Run.state.in_([
                RunState.PAUSE_REQUESTED.value, RunState.CANCEL_REQUESTED.value]))).scalars():
            if run.state == RunState.PAUSE_REQUESTED.value:
                run.state = RunState.PAUSED.value
            else:
                for t in s.execute(select(Task).where(
                        Task.run_id == run.id,
                        Task.state == TaskState.PENDING.value)).scalars():
                    t.state = TaskState.CANCELLED.value
                run.state = RunState.CANCELLED.value
                run.finished_at = utcnow()
            emit(s, run.tenant_id, run.id, "run.settled", {"state": run.state})
            changed += 1
    return changed


def _dispatchable_runs() -> list[tuple[str, str]]:
    with session_scope() as s:
        runs = s.execute(select(Run).where(
            Run.state.in_([RunState.QUEUED.value, RunState.RUNNING.value]))).scalars().all()
        s.expunge_all()
        return [(r.tenant_id, r.id) for r in runs]


def _process_run(tenant_id: str, run_id: str) -> int:
    from fastapi import HTTPException
    executed = 0
    try:
        with session_scope() as s:
            run = s.get(Run, run_id)
            if run is None or run.tenant_id != tenant_id:
                return 0
            if run.kill_requested:
                emergency_stop(tenant_id, run_id, "system:kill-flag")
                return 1
            if run.state == RunState.QUEUED.value:
                run.state = RunState.RUNNING.value
                run.started_at = run.started_at or utcnow()
                emit(s, tenant_id, run_id, "run.running", {})
            tasks = s.execute(select(Task).where(Task.run_id == run_id)).scalars().all()
            s.expunge_all()

        terminal_nodes = _terminal_node_set(tasks)
        for t in tasks:
            if t.state != TaskState.PENDING.value:
                continue
            base = t.node.split(":")[0]
            if base in HUMAN_GATES:
                continue  # parked; API completes the gate
            if graph.ready(base, terminal_nodes):
                executed += _execute_task(tenant_id, t)
        _maybe_finalize(tenant_id, run_id)
    except HTTPException:
        raise
    except Exception as exc:
        with session_scope() as s:
            run = s.get(Run, run_id)
            if run and run.state not in RUN_TERMINAL:
                run.state = RunState.FAILED.value
                run.error = f"engine error: {exc}"
                emit(s, tenant_id, run_id, "run.failed", {"error": str(exc)[:300]})
    return executed


def _terminal_node_set(tasks: list[Task]) -> set[str]:
    by_node: dict[str, list[Task]] = defaultdict(list)
    for t in tasks:
        by_node[t.node.split(":")[0]].append(t)
    return {nid for nid, ts in by_node.items() if all(_is_terminal(t) for t in ts)}


def _is_terminal(task: Task) -> bool:
    return TaskState(task.state) in TASK_TERMINAL_STATES()


def _execute_task(tenant_id: str, task: Task) -> int:
    settings = get_settings().bounds
    task_id = task.id
    with session_scope() as s:
        run = s.get(Run, task.run_id)
        if run is None or run.state not in (RunState.QUEUED.value, RunState.RUNNING.value):
            return 0
        # SC14 pre-dispatch recheck: kill flags, run authorization
        from ..core.db import Tenant
        tenant = s.get(Tenant, tenant_id)
        if tenant.kill_flag or run.kill_requested:
            t = s.get(Task, task_id)
            t.state = TaskState.CANCELLED.value
            emit(s, tenant_id, run.id, "task.cancelled", {"task_id": task_id, "why": "kill flag"})
            return 1
        base_node = task.node.split(":")[0]
        t = s.get(Task, task_id)  # attach a session-owned instance; the caller's is detached
        t.attempt += 1
        t.state = TaskState.RUNNING.value
        t.lease_id = new_id("lse")
        t.lease_expires = utcnow() + timedelta(seconds=settings.task_deadline_s)
        run_id, attempt = run.id, t.attempt
        emit(s, tenant_id, run_id, "task.state_changed",
             {"task_id": task_id, "node": task.node, "to": TaskState.RUNNING.value, "attempt": attempt})

    try:
        with session_scope() as s:
            run = s.get(Run, run_id)
            task = s.get(Task, task_id)
            ctx = nodes.NodeCtx()
            ctx.session, ctx.run, ctx.task, ctx.tenant_id = s, run, task, tenant_id
            result = nodes.HANDLERS[base_node](ctx)
    except Exception as exc:
        result = nodes.NodeResult(status="failed", error=f"{type(exc).__name__}: {exc}")

    with session_scope() as s:
        task = s.get(Task, task_id)
        run = s.get(Run, run_id)
        if task is None or task.state != TaskState.RUNNING.value:
            emit(s, tenant_id, run_id, "task.stale_lease_rejected",
                 {"task_id": task_id, "state": task.state if task else None})
            return 1  # stale lease (killed externally); holder may not commit (DC04)
        if result.status == "succeeded":
            task.state = TaskState.SUCCEEDED.value
        elif result.status == "skipped":
            task.state = TaskState.SKIPPED.value
            task.skip_reason = result.skip_reason
        elif attempt < settings.max_task_attempts:
            task.state = TaskState.RETRY_SCHEDULED.value
            task.error = result.error
            backoff = min(2 ** attempt + random.uniform(0, 0.5), 5.0)
            emit(s, tenant_id, run_id, "task.retry_scheduled",
                 {"task_id": task_id, "node": task.node, "attempt": attempt,
                  "error": (result.error or "")[:200]})
            _schedule_retry(task_id, backoff)
            return 1
        else:
            task.state = TaskState.FAILED.value
            task.error = result.error
        task.lease_id = None
        emit(s, tenant_id, run_id, "task.state_changed",
             {"task_id": task_id, "node": task.node, "to": task.state, "attempt": attempt})
        _on_terminal(s, run, task, result)
    return 1


def _on_terminal(session, run: Run, task: Task, result: nodes.NodeResult) -> None:
    base = task.node.split(":")[0]
    spec = graph.NODES[base]
    if result.status == "succeeded":
        if result.new_tasks:
            for node_id, partition in result.new_tasks:
                _add_task(session, run, node_id.split(":")[0], partition)
        else:
            for child in spec.next_nodes:
                if graph.NODES[child].fan_out is None:
                    _add_task(session, run, child, "-")
    elif result.status == "skipped":
        _propagate_skip(session, run, base, spec.next_nodes)


def _propagate_skip(session, run: Run, from_node: str, children: tuple[str, ...]) -> None:
    """Skipped optional branch: dormant downstream chain becomes skipped (AT10 fan-in)."""
    for child in children:
        if graph.NODES[child].fan_out:
            continue
        t = _add_task(session, run, child, "-")
        if t.state != TaskState.PENDING.value:
            continue  # already driven by another parent (join) or terminal
        if child in HUMAN_GATES or child not in nodes.HANDLERS:
            t.state = TaskState.SKIPPED.value
            t.skip_reason = f"upstream {from_node} skipped (dormant branch)"
            _propagate_skip(session, run, child, graph.NODES[child].next_nodes)


def _schedule_retry(task_id: str, delay: float) -> None:
    def _redo():
        time.sleep(delay)
        with session_scope() as s:
            t = s.get(Task, task_id)
            if t and t.state == TaskState.RETRY_SCHEDULED.value:
                t.state = TaskState.PENDING.value
    threading.Thread(target=_redo, daemon=True).start()


def _add_task(session, run: Run, base_node: str, partition: str) -> Task:
    existing = session.execute(
        select(Task).where(Task.run_id == run.id, Task.node == base_node,
                           Task.partition == partition)).scalars().first()
    if existing:
        return existing
    task = Task(id=new_id("tsk"), tenant_id=run.tenant_id, run_id=run.id,
                node=base_node, partition=partition, state=TaskState.PENDING.value)
    session.add(task)
    session.flush()
    return task


def _maybe_finalize(tenant_id: str, run_id: str) -> None:
    with session_scope() as s:
        run = s.get(Run, run_id)
        if run is None or run.state in RUN_TERMINAL or run.state == RunState.WAITING_APPROVAL.value:
            return
        tasks = s.execute(select(Task).where(Task.run_id == run_id)).scalars().all()
        if not tasks:
            return
        pending = [t for t in tasks if not _is_terminal(t)]
        retrying = [t for t in pending if t.state == TaskState.RETRY_SCHEDULED.value]
        terminal_nodes = _terminal_node_set(tasks)
        dispatchable = [t for t in pending if t.state == TaskState.PENDING.value
                        and t.node.split(":")[0] not in HUMAN_GATES
                        and graph.ready(t.node.split(":")[0], terminal_nodes)]
        if pending and not dispatchable and not retrying:
            return  # parked at a human gate; state drives the UI
        if pending:
            return
        from ..core.db import Snapshot
        snaps = s.execute(select(Snapshot).where(
            Snapshot.tenant_id == tenant_id, Snapshot.run_id == run_id)).scalars().all()
        failed = any(t.state == TaskState.FAILED.value for t in tasks)
        partial = any(snap.state == SnapshotState.PARTIAL.value for snap in snaps)
        if failed:
            run.state = RunState.FAILED.value
        elif partial:
            run.state = RunState.PARTIAL.value
        else:
            run.state = RunState.SUCCEEDED.value
        run.finished_at = utcnow()
        emit(s, tenant_id, run_id, "run.finalized", {"state": run.state})


def _transition(run: Run, target: RunState) -> None:
    current = RunState(run.state)
    if target not in RUN_TRANSITIONS.get(current, set()):
        from fastapi import HTTPException
        raise HTTPException(422, detail={"code": "INVALID_TRANSITION",
                                         "message": f"cannot move run from {current.value} to {target.value}",
                                         "retryable": False})
    run.state = target.value


def _assert_tenant(run, tenant_id: str) -> None:
    from ..core.repo import TenantViolation
    if run is None or run.tenant_id != tenant_id:
        raise TenantViolation(run.id if run else "?")


def run_until_quiescent(max_ticks: int = 200, interval_s: float = 0.05) -> int:
    """Test/demo helper: drive the engine to quiescence (incl. parked gates)."""
    total = 0
    for _ in range(max_ticks):
        done = tick()
        total += done
        if done == 0:
            time.sleep(interval_s)
            if tick() == 0:
                break
    return total
