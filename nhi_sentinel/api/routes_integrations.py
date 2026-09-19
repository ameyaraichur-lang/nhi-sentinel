"""Control API part 4: integration surfaces - inbound webhooks (API26) and outbound ticket
drafts (API39/OP18).

Webhooks are an unauthenticated machine surface: authenticity comes from an HMAC-SHA256
signature over the RAW body plus a timestamp anti-replay window, never from a session.
The tenant is NEVER taken from the payload: rows are stored under the reserved tenant
'webhooks' until certified per-integration secrets and tenant mappings arrive with real
integrations.

Tickets are drafts only: no external calls are made from this slice - real delivery to an
external tracker is a certified integration (OP18)."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..config import get_settings
from ..core.audit import append_audit
from ..core.db import Finding, Ticket, WebhookEvent, new_id, session_scope
from ..core.repo import TenantViolation, scoped_get
from .deps import guard, tenant_of, user_id

router = APIRouter(prefix="/v1")

TIMESTAMP_SKEW_S = 300  # RFC3339 X-Timestamp may drift at most 5 minutes (anti-replay)
TICKET_DESTINATIONS = ["demo-tracker"]  # allowlist; real trackers are certified integrations


class TicketCreate(BaseModel):
    finding_id: str
    destination: str
    subject: str = Field(min_length=3, max_length=300)
    body: str = Field(default="", max_length=20000)


def _parse_rfc3339(value: str) -> datetime | None:
    """Parse an RFC3339 timestamp to aware UTC; None when malformed."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # naive treated as UTC (DC08)
    return dt.astimezone(timezone.utc)


# --- inbound webhooks (API26) ------------------------------------------------------------

@router.post("/webhooks/{integration}")
async def api_inbound_webhook(integration: str, request: Request):
    """API26: HMAC-verified inbound integration event with dedup by (integration, event_id).

    - X-Signature: HMAC-SHA256 hex of the RAW request body under the configured signing
      secret (per-integration secrets arrive with certified integrations).
    - X-Timestamp: RFC3339; skew beyond 5 minutes is rejected (401 TIMESTAMP_SKEW).
    - Duplicate (integration, event_id) replays answer 200 accepted:false reason duplicate.
    The tenant is never trusted from the payload (reserved tenant 'webhooks')."""
    integration = integration[:60]
    raw = await request.body()
    ts = _parse_rfc3339(request.headers.get("X-Timestamp", ""))
    if ts is None or abs((datetime.now(timezone.utc) - ts).total_seconds()) > TIMESTAMP_SKEW_S:
        raise HTTPException(401, detail={"code": "TIMESTAMP_SKEW",
                                         "message": "X-Timestamp missing, malformed, or older "
                                                    "than 5 minutes (anti-replay).",
                                         "retryable": False})
    supplied = request.headers.get("X-Signature", "")
    expected = hmac.new(get_settings().signing_secret.encode("utf-8"), raw,
                        hashlib.sha256).hexdigest()
    if not supplied or not hmac.compare_digest(expected, supplied.strip().lower()):
        raise HTTPException(401, detail={"code": "INVALID_SIGNATURE",
                                         "message": "X-Signature does not authenticate this "
                                                    "payload.",
                                         "retryable": False})
    try:
        body = json.loads(raw or b"{}")
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except ValueError:
        raise HTTPException(422, detail={"code": "VALIDATION",
                                         "message": "webhook body must be a JSON object.",
                                         "retryable": False})
    event_id = str(body.get("event_id") or "")
    if not event_id:
        raise HTTPException(422, detail={"code": "VALIDATION",
                                         "message": "event_id is required.",
                                         "retryable": False})
    with session_scope() as s:
        existing = s.execute(select(WebhookEvent).where(
            WebhookEvent.integration == integration,
            WebhookEvent.event_id == event_id[:200])).scalars().first()
        if existing is not None:
            return {"accepted": False, "reason": "duplicate", "event_id": event_id,
                    "integration": integration,
                    "received_at": existing.received_at.isoformat() + "Z"}
        row = WebhookEvent(id=new_id("whk"), tenant_id="webhooks", integration=integration,
                           event_id=event_id[:200], accepted=True)
        s.add(row)
        s.flush()
        return {"accepted": True, "event_id": event_id, "integration": integration,
                "webhook_event_id": row.id,
                "received_at": row.received_at.isoformat() + "Z",
                "note": "tenant reserved 'webhooks'; payload tenant is never trusted (API26)"}


# --- ticket drafts (API39/OP18) -----------------------------------------------------------

def _ticket_out(t: Ticket) -> dict:
    return {"ticket_id": t.id, "finding_id": t.finding_id, "destination": t.destination,
            "subject": t.subject, "body": t.body, "status": t.status,
            "idempotency_key": t.idempotency_key,
            "created_at": t.created_at.isoformat() + "Z"}


@router.post("/tickets", status_code=201)
def api_create_ticket(body: TicketCreate, request: Request,
                      principal=Depends(guard("finding:update"))):
    """API39: draft a remediation ticket for one tenant-visible finding. Destination is
    allowlisted; Idempotency-Key replays return the SAME draft (no duplicate). No external
    delivery happens here - real delivery is a certified integration (OP18)."""
    tid, uid = tenant_of(principal), user_id(principal)
    if body.destination not in TICKET_DESTINATIONS:
        raise HTTPException(422, detail={"code": "DESTINATION_NOT_ALLOWED",
                                         "message": f"destination must be one of "
                                                    f"{TICKET_DESTINATIONS}; certified "
                                                    f"integrations deliver real tickets.",
                                         "retryable": False})
    idem = (request.headers.get("Idempotency-Key") or "").strip()[:120] or new_id("idem")
    with session_scope() as s:
        existing = s.execute(select(Ticket).where(
            Ticket.tenant_id == tid, Ticket.idempotency_key == idem)).scalars().first()
        if existing is not None:
            # replay: same draft, 200 (not a creation)
            return JSONResponse(status_code=200, content={**_ticket_out(existing), "replayed": True})
        try:
            finding = scoped_get(s, Finding, tid, body.finding_id)
        except TenantViolation:
            raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "not found",
                                             "retryable": False})
        ticket = Ticket(id=new_id("tkt"), tenant_id=tid, finding_id=finding.id,
                        destination=body.destination, subject=body.subject[:300],
                        body=body.body[:20000], status="drafted", idempotency_key=idem)
        s.add(ticket)
        s.flush()
        append_audit(tid, uid, "ticket.drafted", "ticket", ticket.id,
                     {"finding": finding.id, "destination": ticket.destination,
                      "idempotency_key": idem}, session=s)
        return _ticket_out(ticket)


@router.get("/tickets")
def api_list_tickets(principal=Depends(guard("read:findings")), limit: int = 50, offset: int = 0):
    tid = tenant_of(principal)
    with session_scope() as s:
        rows = s.execute(select(Ticket).where(Ticket.tenant_id == tid)
                         .order_by(Ticket.created_at.desc())
                         .limit(max(1, min(limit, 100))).offset(max(0, offset))).scalars().all()
        return [_ticket_out(t) for t in rows]
