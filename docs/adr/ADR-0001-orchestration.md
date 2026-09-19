# ADR-0001: Bespoke durable task engine for the vertical slice

**Status:** accepted for slice 0.1  ·  **Blueprint refs:** AR03, DC03/DC04, EX01/EX02, G06/G07/G13, BG08

The blueprint names LangGraph as the workflow coordinator. This slice implements a small
durable engine (`nhi_sentinel/worker/engine.py`) with the same contract surface:

- Runs and task attempts are durable DB rows with the EX01/EX02 state machines.
- Dispatch records a lease; only the lease holder may commit; stale completions are
  rejected and logged (`task.stale_lease_rejected`) — DC04/AT31 semantics.
- Retries are bounded task attempts with jitter backoff (OP02); a changed scope is a new
  epoch, never a retry (G06).
- Optional-branch skips propagate so fan-in joins correctly (AT10); human gates park runs
  in `waiting_approval` until an authorized API call completes them (G12: no autonomy
  promotion from counters).
- Kill flag is checked immediately before every dispatch (SC18/AT07).

**Why:** the pilot DAG has 18 nodes, deterministic executors, and no resumable LLM state.
LangGraph would add a checkpointing layer we would have to trust without using its core
value (resumable graph state for LLM-heavy branches). The engine is ~300 lines, fully
deterministic, and testable; the blueprint's LangGraph references remain valid for the
active-proof branch (N07–N09) where resumable LLM planning becomes real.

**Consequences:** crash-recovery between *process restarts* resumes from durable task rows
but in-flight handler state is not checkpointed (handlers are idempotent upserts). A move
to production multi-worker dispatch needs Postgres + `SELECT ... FOR UPDATE SKIP LOCKED`
leasing; the seam is `_dispatchable_runs`/`_execute_task`.
