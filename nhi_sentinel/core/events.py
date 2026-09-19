"""Event log / outbox and run topology (DC18, EX06, API10, UX16).

Events are committed in the same transaction as the state change they describe.
SSE replays by sequence from Last-Event-ID; cursor expiry triggers a resync signal.
"""
from __future__ import annotations

import asyncio
import json

from sqlalchemy import func, select

from .db import EventOutbox, new_id, session_scope, utcnow


def emit(session, tenant_id: str, run_id: str | None, event_type: str, payload: dict) -> EventOutbox:
    """Append event using the caller's open transaction (call before commit)."""
    seq = 1
    if run_id:
        last = session.execute(
            select(func.max(EventOutbox.sequence)).where(
                EventOutbox.tenant_id == tenant_id, EventOutbox.run_id == run_id)
        ).scalar()
        seq = (last or 0) + 1
    ev = EventOutbox(id=new_id("evt"), tenant_id=tenant_id, run_id=run_id, sequence=seq,
                     type=event_type, payload_json=payload, created_at=utcnow())
    session.add(ev)
    return ev


def replay(tenant_id: str, run_id: str, after_sequence: int = 0, limit: int = 500) -> list[EventOutbox]:
    with session_scope() as s:
        rows = s.execute(
            select(EventOutbox).where(
                EventOutbox.tenant_id == tenant_id, EventOutbox.run_id == run_id,
                EventOutbox.sequence > after_sequence)
            .order_by(EventOutbox.sequence).limit(limit)
        ).scalars().all()
        s.expunge_all()
        return list(rows)


def latest_sequence(tenant_id: str, run_id: str) -> int:
    with session_scope() as s:
        return s.execute(
            select(func.max(EventOutbox.sequence)).where(
                EventOutbox.tenant_id == tenant_id, EventOutbox.run_id == run_id)
        ).scalar() or 0


def sse_format(ev: EventOutbox) -> str:
    data = json.dumps({
        "schema_version": "1.0", "event_id": ev.id, "tenant_id": ev.tenant_id,
        "run_id": ev.run_id, "sequence": ev.sequence, "type": ev.type,
        "timestamp": ev.created_at.isoformat() + "Z", "payload": ev.payload_json,
    }, ensure_ascii=False, default=str)
    return f"id: {ev.sequence}\nevent: {ev.type}\ndata: {data}\n\n"


RESYNC_SENTINEL = "event: resync\ndata: {\"reason\": \"cursor_expired\"}\n\n"


class RunWaiter:
    """Lightweight in-process notify so SSE streams push immediately instead of pure polling."""

    def __init__(self):
        self._events: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    async def notify(self, run_id: str) -> None:
        async with self._lock:
            ev = self._events.get(run_id)
        if ev:
            ev.set()

    async def register(self, run_id: str) -> asyncio.Event:
        async with self._lock:
            ev = self._events.get(run_id)
            if ev is None:
                ev = asyncio.Event()
                self._events[run_id] = ev
            return ev

    async def unregister(self, run_id: str) -> None:
        async with self._lock:
            self._events.pop(run_id, None)


waiter = RunWaiter()
