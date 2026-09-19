"""AT25/UX16 subset: SSE run event stream with monotonic sequence ids and Last-Event-ID replay.

The installed starlette TestClient runs an ASGI app to completion inside `handle_request`,
so an infinite SSE endpoint cannot be read incrementally through `client.stream`. The SSE
tests therefore drive the REAL endpoint through a direct ASGI harness that collects a
bounded number of events and then cancels the app task (auth, guard, tenant scoping, the
Last-Event-ID query parsing and the SSE formatting are all exercised for real)."""
from __future__ import annotations

import asyncio

import pytest

from nhi_sentinel.core.events import latest_sequence

from .conftest import ANALYST, login, start_run


def _collect_sse(app, session_cookie: str, run_id: str, cursor: int, want: int,
                 timeout_s: float = 20.0) -> tuple[list[int], int]:
    """Invoke GET /v1/runs/{id}/events as raw ASGI, collect `want` event ids, then cancel.

    Returns (ids, response_status)."""
    path = f"/v1/runs/{run_id}/events"

    async def _run() -> tuple[list[int], int]:
        scope = {
            "type": "http", "http_version": "1.1", "method": "GET",
            "path": path, "raw_path": path.encode(), "root_path": "", "scheme": "http",
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"cookie", f"nhi_session={session_cookie}".encode()),
                (b"last-event-id", str(cursor).encode()),
                (b"accept", b"text/event-stream"),
            ],
            "client": ("testclient", 51000), "server": ("testserver", 80),
        }
        status: dict[str, int] = {}
        ids: list[int] = []
        buffer = ""
        got_enough = asyncio.Event()

        async def receive():
            await asyncio.sleep(timeout_s)
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal buffer
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            elif message["type"] == "http.response.body":
                buffer += message.get("body", b"").decode("utf-8", "replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.rstrip("\r")
                    if line.startswith("id:"):
                        ids.append(int(line.split(":", 1)[1].strip()))
                        if len(ids) >= want:
                            got_enough.set()
                            return

        task: asyncio.Task = asyncio.ensure_future(app(scope, receive, send))
        try:
            await asyncio.wait_for(got_enough.wait(), timeout=timeout_s)
        except (asyncio.TimeoutError, TimeoutError):
            pass
        finally:
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc is not None:
                    raise exc
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        return ids, status.get("code", 0)

    return asyncio.run(_run())


def test_AT25_UX16__sse_sequences_are_monotonic_and_replay_from_last_event_id(client, app):
    analyst = login(client, ANALYST)
    tenant_a = analyst["tenant_id"]
    run_id = start_run(client, analyst)

    # Create the full event history, then drive to quiescence: a run parked at the G02
    # human gate emits no further events, so the stream content is stable while we read.
    from nhi_sentinel.worker.engine import run_until_quiescent
    run_until_quiescent()

    latest = latest_sequence(tenant_a, run_id)
    assert latest >= 3, f"expected a real event history, got sequence {latest}"

    cookie = client.cookies.get("nhi_session")
    assert cookie, "expected session cookie"

    ids, status = _collect_sse(app, cookie, run_id, cursor=0, want=latest)
    assert status == 200
    assert len(ids) == latest, f"expected {latest} replayed events, got {len(ids)}"
    assert ids[0] == 1, f"replay from 0 must start at sequence 1, got {ids[0]}"
    assert ids == sorted(ids), f"sequence ordering broken: {ids}"
    assert len(set(ids)) == len(ids), "duplicate sequence ids in stream"

    # Resume from Last-Event-ID = latest-2: exactly the two newer events are replayed.
    cursor = latest - 2
    tail, status2 = _collect_sse(app, cookie, run_id, cursor=cursor, want=2)
    assert status2 == 200
    assert tail == [latest - 1, latest], \
        f"replay after {cursor} must deliver exactly [{latest - 1}, {latest}], got {tail}"


def test_AT25_UX16__sse_stream_content_is_sse_formatted(client, app):
    analyst = login(client, ANALYST)
    tenant_a = analyst["tenant_id"]
    run_id = start_run(client, analyst)
    from nhi_sentinel.worker.engine import run_until_quiescent
    run_until_quiescent()
    latest = latest_sequence(tenant_a, run_id)

    cookie = client.cookies.get("nhi_session")
    chunks: list[str] = []

    async def _grab():
        path = f"/v1/runs/{run_id}/events"

        async def receive():
            await asyncio.sleep(20.0)
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body":
                chunks.append(message.get("body", b"").decode("utf-8", "replace"))

        task = asyncio.ensure_future(app({
            "type": "http", "http_version": "1.1", "method": "GET", "path": path,
            "raw_path": path.encode(), "root_path": "", "scheme": "http",
            "query_string": b"",
            "headers": [(b"host", b"testserver"),
                        (b"cookie", f"nhi_session={cookie}".encode())],
            "client": ("testclient", 51001), "server": ("testserver", 80),
        }, receive, send))
        try:
            await asyncio.sleep(1.5)
        finally:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    asyncio.run(_grab())
    stream = "".join(chunks)
    assert stream, "no SSE payload received"
    assert stream.count("id: ") >= 1
    assert "event: run." in stream or "event: task." in stream or "event: check." in stream
    assert f'"run_id": "{run_id}"' in stream, "SSE events must carry the run id envelope"
    data_lines = [l for l in stream.splitlines() if l.startswith("data: ")]
    assert data_lines, "each event must carry a data line"


def test_AT25_UX16__sse_requires_authentication(client, app):
    from nhi_sentinel.worker.engine import run_until_quiescent

    analyst = login(client, ANALYST)
    run_id = start_run(client, analyst)
    run_until_quiescent()

    client.cookies.clear()
    resp = client.get(f"/v1/runs/{run_id}/events", headers={"Last-Event-ID": "0"})
    assert resp.status_code == 401, "event stream is tenant/session bound (no anonymous reads)"
