"""Append-only audit log with hash chain (SC15, AT17). Verification walks the chain in
insertion order."""
from __future__ import annotations

import threading

from sqlalchemy import select, text

from ..contracts import Role
from .db import AuditEntry, utcnow, new_id, session_scope
from .security import canonical_json, sha256_hex

_append_lock = threading.Lock()


def append_audit(tenant_id: str, actor_id: str, action: str, object_type: str,
                 object_id: str, detail: dict | None = None, session=None) -> AuditEntry:
    """Append an entry, optionally joining the caller's open transaction (OP05: the audit
    write commits atomically with the mutation it describes; a nested session_scope here
    would contend on the BEGIN IMMEDIATE write lock).

    Own-transaction appends serialize on _append_lock so two concurrent writers cannot
    chain from the same head (multi-worker deployments need the head read inside the
    write transaction / a unique (tenant, prev_hash) constraint instead)."""
    own = session is None
    if own:
        with _append_lock, session_scope() as s:
            return _append(s, tenant_id, actor_id, action, object_type, object_id, detail)
    return _append(session, tenant_id, actor_id, action, object_type, object_id, detail)


def _append(s, tenant_id, actor_id, action, object_type, object_id, detail) -> AuditEntry:
    prev_hash = _latest_head(tenant_id)
    entry = AuditEntry(
        id=new_id("aud"), tenant_id=tenant_id, actor_id=actor_id, action=action,
        object_type=object_type, object_id=object_id, detail_json=detail or {},
        prev_hash=prev_hash,
        created_at=utcnow(),
    )
    entry.entry_hash = sha256_hex(canonical_json({
        "prev": prev_hash, "actor": actor_id, "action": action,
        "object": f"{object_type}:{object_id}", "detail": detail or {},
        "at": entry.created_at.isoformat(),
    }))
    s.add(entry)
    return entry


def _latest_head(tenant_id: str) -> str:
    """Read the chain head through a fresh autocommit connection.

    A head read on the CALLER's session uses that transaction's snapshot: a long-running
    request transaction would miss entries committed after it began and fork the chain.
    The fresh read is race-free because our BEGIN IMMEDIATE write lock (held from the
    transaction's first statement until commit) blocks any concurrent committer."""
    from .db import get_engine
    raw = get_engine().raw_connection()
    try:
        cur = raw.cursor()
        cur.execute(
            "SELECT entry_hash FROM audit_log WHERE tenant_id = ? "
            "ORDER BY rowid DESC LIMIT 1",
            (tenant_id,))
        row = cur.fetchone()
        cur.close()
    finally:
        raw.close()
    return row[0] if row and row[0] else "genesis"


def walk_chain(entries, limit: int | None = None) -> dict:
    """Recompute the hash chain over an ordered (insertion-order) entry list. Pure: callers
    run it inside their OWN transaction (API33 signed export must not nest session_scope).
    limit confines the walk to the first N entries so a signed export stays verifiable while
    newer entries keep appending; tampering within the window still breaks it."""
    prev = "genesis"
    broken_at = None
    checked = 0
    for e in entries:
        if limit is not None and checked >= limit:
            break
        expected = sha256_hex(canonical_json({
            "prev": prev, "actor": e.actor_id, "action": e.action,
            "object": f"{e.object_type}:{e.object_id}", "detail": e.detail_json,
            "at": e.created_at.isoformat(),
        }))
        if e.prev_hash != prev or not _consteq(expected, e.entry_hash):
            broken_at = e.id
            break
        prev = e.entry_hash
        checked += 1
    return {"valid": broken_at is None, "broken_at": broken_at, "head": prev}


def verify_chain(tenant_id: str) -> dict:
    """Recompute the hash chain; any mutation/removal/reorder breaks verification (AT17).
    Walk order is INSERTION order (rowid): wall-clock timestamps assigned in different
    threads are not a reliable total order for chaining."""
    with session_scope() as s:
        entries = s.execute(
            select(AuditEntry).where(AuditEntry.tenant_id == tenant_id)
            .order_by(text("rowid"))  # SQLite insertion order (Postgres: identity column)
        ).scalars().all()
    walked = walk_chain(entries)
    return {"entries": len(entries), "valid": walked["valid"], "broken_at": walked["broken_at"],
            "head": "genesis" if not entries else entries[-1].entry_hash}


def _consteq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)


ROLE_AUDIT_READ = {Role.AUDITOR, Role.TENANT_ADMIN}
