"""Leftover backend work packages: PS15 retest closure (1), API26 inbound webhooks (2),
API39/OP18 ticket drafts (3), SC22/AT25 rate limiting (4), SC23/AT33 support elevation (5),
API33 signed audit export (6), AT11 retry bounds (7), AT19 unsupported claims (8).

Engine-driven tests drive runs in-process (run_demo.headless pattern) instead of via the API
where the API would add gates this work package does not exercise."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from nhi_sentinel.core.db import (
    AuditEntry, CheckResult, Connector, Engagement, EventOutbox, Finding, Run, ScopeVersion,
    Snapshot, SupportGrant, Task, Ticket, Tenant, WebhookEvent, new_id, session_scope, utcnow,
)

from .conftest import ANALYST, AUDITOR, DEMO_PASSWORD, INTRUDER, QA_DATA_DIR, login

SUPPORT_EMAIL = "support@nhi.internal"
RUN_PARKED_STATES = {"waiting_approval", "partial", "succeeded", "failed", "cancelled"}
BANNED_CLAIM_FRAGMENTS = ["maturity level", "certified", "certification", "guaranteed",
                          "anti-hallucination", "$"]


# --- shared helpers ------------------------------------------------------------------

def _tenant_a_id() -> str:
    with session_scope() as s:
        t = s.execute(select(Tenant).where(Tenant.name.like("%Northwind%"))).scalars().first()
        assert t is not None, "tenant A (Northwind synthetic demo) missing"
        return t.id


def _enable_connectors(tenant_id: str) -> None:
    """Earlier modules offboard tenant A (AT42 disables its connectors). A retest run has no
    AT24 preflight gate, but N00 requires the connectors enabled again."""
    with session_scope() as s:
        for c in s.execute(select(Connector).where(
                Connector.tenant_id == tenant_id)).scalars():
            c.enabled = True
            c.preflight_state = "passed"


def _drive_run(run_id: str, states: set[str], timeout_s: float = 240.0) -> str:
    """Drive the engine (background loop + in-process ticks) until the run reaches one of
    `states`. run_until_quiescent alone can exit early while a retry backoff sleeps."""
    from nhi_sentinel.worker.engine import run_until_quiescent

    deadline = time.time() + timeout_s
    state = ""
    while time.time() < deadline:
        run_until_quiescent()
        with session_scope() as s:
            run = s.get(Run, run_id)
            state = run.state if run else ""
        if state in states:
            return state
        time.sleep(0.5)
    return state


# --- 1. PS15/API16 retest closure ------------------------------------------------------

def test_PS15__retest_with_persisting_condition_leaves_finding_open(client, full_run_id):
    """Honest fixture case: the static corpus still fails the check, so the finding must stay
    open even after a fresh complete retest run (PS15 forbids closing on persisting evidence)."""
    analyst = login(client, ANALYST)
    tenant_a = analyst["tenant_id"]
    _enable_connectors(tenant_a)

    listing = client.get("/v1/findings?status=open&limit=1")
    assert listing.status_code == 200 and listing.json()["total"] >= 1, listing.text
    finding_id = listing.json()["items"][0]["finding_id"]

    created = client.post(f"/v1/findings/{finding_id}/retests", headers=analyst["headers"])
    assert created.status_code == 200, created.text
    retest_run_id = created.json()["retest_run_id"]

    state = _drive_run(retest_run_id, RUN_PARKED_STATES)
    assert state == "waiting_approval", f"retest run did not reach the release gate: {state}"

    detail = client.get(f"/v1/findings/{finding_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["workflow_status"] == "open", \
        "condition persists on fresh evidence: PS15 forbids closing this finding"

    with session_scope() as s:
        events = s.execute(select(EventOutbox).where(
            EventOutbox.run_id == retest_run_id,
            EventOutbox.type == "retest.evaluated")).scalars().all()
    assert events, "retest.evaluated event missing from the retest run"
    payload = events[-1].payload_json
    assert payload["still_open"] >= 1, payload
    assert payload["resolved"] == 0, "static fixture is deterministic: nothing may resolve"


def test_PS15__closure_resolves_clean_target_and_keeps_failing_target_open(client):
    """Unit case through nodes.evaluate_retest_closure with fabricated rows (SimpleNamespace
    run stand-ins): a target the retest no longer fails resolves; a still-failing one stays."""
    from nhi_sentinel.worker.nodes import evaluate_retest_closure

    tenant_id = _tenant_a_id()
    parent_id, retest_id = "run_qa_parent_ps15u", "run_qa_retest_ps15u"
    with session_scope() as s:
        s.add(Snapshot(id="snp_qa_ps15u_aws", tenant_id=tenant_id, run_id=retest_id,
                       source="aws_iam", connector_id="cn_qa_ps15u", scope_hash="qa-scope",
                       state="complete", seen_count=2, expected_count=2, completeness=1.0))
        # KEY-001 applies_to github: its relevant source must be complete for resolution
        s.add(Snapshot(id="snp_qa_ps15u_gh", tenant_id=tenant_id, run_id=retest_id,
                       source="github", connector_id="cn_qa_ps15u", scope_hash="qa-scope",
                       state="complete", seen_count=1, expected_count=1, completeness=1.0))
        # parent run: both targets failed once (immutable CheckResults identify the findings)
        s.add(CheckResult(id="res_qa_ps15u_p1", tenant_id=tenant_id, run_id=parent_id,
                          check_id="CLD-002", check_version="1.0.0", target_id="ide_qa_ps15u_a",
                          target_key="aws://qa-ps15u/still-failing", status="fail"))
        s.add(CheckResult(id="res_qa_ps15u_p2", tenant_id=tenant_id, run_id=parent_id,
                          check_id="KEY-001", check_version="1.0.0", target_id="ide_qa_ps15u_b",
                          target_key="aws://qa-ps15u/fixed", status="fail"))
        s.add(Finding(id="fnd_qa_ps15u_open", tenant_id=tenant_id, run_id=parent_id,
                      check_id="CLD-002", check_version="1.0.0", target_id="ide_qa_ps15u_a",
                      target_key="aws://qa-ps15u/still-failing", dedup_key="qa-ps15u|open",
                      title="still failing", severity="high", workflow_status="open"))
        s.add(Finding(id="fnd_qa_ps15u_fixed", tenant_id=tenant_id, run_id=parent_id,
                      check_id="KEY-001", check_version="1.0.0", target_id="ide_qa_ps15u_b",
                      target_key="aws://qa-ps15u/fixed", dedup_key="qa-ps15u|fixed",
                      title="fixed", severity="medium", workflow_status="in_progress"))
        # retest: still fails the first target; produces NO result at all for the second
        s.add(CheckResult(id="res_qa_ps15u_r1", tenant_id=tenant_id, run_id=retest_id,
                          check_id="CLD-002", check_version="1.0.0", target_id="ide_qa_ps15u_a",
                          target_key="aws://qa-ps15u/still-failing", status="fail"))

    with session_scope() as s:
        out = evaluate_retest_closure(s, tenant_id, SimpleNamespace(id=retest_id),
                                      SimpleNamespace(id=parent_id))
    assert out == {"resolved": 1, "still_open": 1}

    with session_scope() as s:
        kept = s.get(Finding, "fnd_qa_ps15u_open")
        fixed = s.get(Finding, "fnd_qa_ps15u_fixed")
    assert kept.workflow_status == "open" and kept.revision == 1, \
        "still-failing finding must remain open and untouched"
    assert fixed.workflow_status == "resolved" and fixed.revision == 2
    assert "resolved by retest run" in (fixed.facts or {}).get("resolution_reason", "")


# --- 2. API26 inbound webhooks ---------------------------------------------------------

def _signed_headers(body: bytes, ts: datetime | None = None,
                    sig: str | None = None) -> dict:
    from nhi_sentinel.config import get_settings
    stamp = (ts or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    if sig is None:
        sig = hmac.new(get_settings().signing_secret.encode("utf-8"), body,
                       hashlib.sha256).hexdigest()
    return {"X-Timestamp": stamp, "X-Signature": sig}


def test_API26__webhook_signature_timestamp_dedup_and_reserved_tenant(client):
    body = json.dumps({"event_id": "evt-at26-001",
                       "occurred_at": "2026-09-19T00:00:00Z",
                       "payload": {"alert": "synthetic-canary"}}).encode()
    url = "/v1/webhooks/demo-integration"

    ok = client.post(url, content=body, headers=_signed_headers(body))
    assert ok.status_code == 200, ok.text
    assert ok.json()["accepted"] is True

    replay = client.post(url, content=body, headers=_signed_headers(body))
    assert replay.status_code == 200, replay.text
    assert replay.json()["accepted"] is False and replay.json()["reason"] == "duplicate"

    bad_sig = client.post(url, content=body, headers=_signed_headers(body, sig="ab" * 32))
    assert bad_sig.status_code == 401, bad_sig.text
    assert bad_sig.json()["error"]["code"] == "INVALID_SIGNATURE"

    stale = datetime.now(timezone.utc) - timedelta(minutes=10)
    stale_ts = client.post(url, content=body, headers=_signed_headers(body, ts=stale))
    assert stale_ts.status_code == 401, stale_ts.text
    assert stale_ts.json()["error"]["code"] == "TIMESTAMP_SKEW"

    unsigned = client.post(url, content=body)
    assert unsigned.status_code == 401
    assert unsigned.json()["error"]["code"] in ("INVALID_SIGNATURE", "TIMESTAMP_SKEW")

    with session_scope() as s:
        row = s.execute(select(WebhookEvent).where(
            WebhookEvent.integration == "demo-integration",
            WebhookEvent.event_id == "evt-at26-001")).scalars().first()
    assert row is not None and row.accepted is True
    assert row.tenant_id == "webhooks", "tenant is reserved, never taken from the payload"


# --- 3. API39/OP18 ticket drafts ---------------------------------------------------------

def test_API39__ticket_draft_allowlist_idempotency_and_tenant_visibility(client, full_run_id):
    analyst = login(client, ANALYST)
    finding_id = client.get("/v1/findings?limit=1").json()["items"][0]["finding_id"]
    payload = {"finding_id": finding_id, "destination": "demo-tracker",
               "subject": "QA synthetic remediation ticket",
               "body": "Drafted by test_API39 (synthetic content only)."}
    headers = {**analyst["headers"], "Idempotency-Key": "qa-api39-idem-001"}

    first = client.post("/v1/tickets", headers=headers, json=payload)
    assert first.status_code == 201, first.text
    ticket = first.json()
    assert ticket["status"] == "drafted"
    assert ticket["idempotency_key"] == "qa-api39-idem-001"

    replay = client.post("/v1/tickets", headers=headers, json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["ticket_id"] == ticket["ticket_id"], \
        "idempotency replay must return the SAME draft"
    with session_scope() as s:
        stored = s.execute(select(Ticket).where(
            Ticket.idempotency_key == "qa-api39-idem-001")).scalars().all()
    assert len(stored) == 1, "replay must not create a duplicate ticket"

    blocked = client.post("/v1/tickets", headers=analyst["headers"],
                          json={**payload, "destination": "unapproved-crm"})
    assert blocked.status_code == 422, blocked.text
    assert blocked.json()["error"]["code"] == "DESTINATION_NOT_ALLOWED"

    intruder = login(client, INTRUDER, role="analyst")
    foreign = client.post("/v1/tickets",
                          headers={**intruder["headers"], "Idempotency-Key": "qa-api39-foreign"},
                          json=payload)
    assert foreign.status_code == 404, "cross-tenant finding must stay invisible (AT01)"
    assert foreign.json()["error"]["code"] == "NOT_FOUND"

    analyst = login(client, ANALYST)  # single cookie jar: back to tenant A for the listing
    listed = client.get("/v1/tickets")
    assert listed.status_code == 200, listed.text
    assert any(t["ticket_id"] == ticket["ticket_id"] for t in listed.json())


# --- 5. SC23/AT33 support elevation ------------------------------------------------------

def test_SC23__support_elevation_grant_lifecycle_and_normal_denials(client):
    raw = client.post("/v1/auth/login",
                      json={"email": SUPPORT_EMAIL, "password": DEMO_PASSWORD}).json()
    assert raw["capabilities"] == ["support:elevate"], \
        "support role ships with elevation capability ONLY (no read caps)"
    support = login(client, SUPPORT_EMAIL, role="support")
    tenant_a = _tenant_a_id()

    # case 1: no grant -> 403 SUPPORT_GRANT_REQUIRED
    denied = client.get("/v1/support/tenant-overview", params={"tenant_id": tenant_a})
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["code"] == "SUPPORT_GRANT_REQUIRED"

    # case 4: normal endpoints stay denied for the support role (no read capabilities)
    assert client.get("/v1/findings").status_code == 403
    assert client.get("/v1/overview").status_code == 403

    out_of_band = client.post("/v1/support-grants", headers=support["headers"],
                              json={"tenant_id": tenant_a, "minutes": 1,
                                    "reason": "below the 5-minute bound must fail"})
    assert out_of_band.status_code == 400, "minutes bounds are enforced server-side"

    # case 2: active grant -> same overview shape as /v1/overview + audited access
    grant = client.post("/v1/support-grants", headers=support["headers"],
                        json={"tenant_id": tenant_a, "minutes": 5,
                              "reason": "QA synthetic support elevation (SC23)"})
    assert grant.status_code == 201, grant.text
    assert grant.json()["status"] == "active"

    allowed = client.get("/v1/support/tenant-overview", params={"tenant_id": tenant_a})
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert {"tenant", "runs", "findings_by_severity", "connectors", "identity_count",
            "reports_awaiting_release", "proposals_pending"} <= set(body)

    # case 3: expired grant (expires_at forced into the past) -> 403 again
    with session_scope() as s:
        row = s.get(SupportGrant, grant.json()["grant_id"])
        row.expires_at = utcnow() - timedelta(seconds=1)
    expired = client.get("/v1/support/tenant-overview", params={"tenant_id": tenant_a})
    assert expired.status_code == 403, expired.text
    assert expired.json()["error"]["code"] == "SUPPORT_GRANT_REQUIRED"

    with session_scope() as s:
        accesses = s.execute(select(AuditEntry).where(
            AuditEntry.tenant_id == tenant_a,
            AuditEntry.action == "support.access")).scalars().all()
    assert len(accesses) >= 3, "every support.access call must be audited in the target tenant"
    assert any((a.detail_json or {}).get("granted") is True for a in accesses)
    assert any((a.detail_json or {}).get("granted") is False for a in accesses)


# --- 6. API33 signed audit export ----------------------------------------------------------

def test_API33__signed_audit_export_verifies_and_detects_tampering(client):
    auditor = login(client, AUDITOR, role="auditor")
    exported = client.get("/v1/audit-events/export")
    assert exported.status_code == 200, exported.text
    doc = exported.json()
    assert set(doc) >= {"tenant_id", "entries", "head", "count", "signature"}
    assert doc["count"] >= 1 and len(doc["entries"]) == doc["count"]
    assert doc["entries"][0]["action"] and doc["entries"][0]["entry_hash"]

    verified = client.get("/v1/audit-events/export/verify",
                          params={"count": doc["count"], "signature": doc["signature"]})
    assert verified.status_code == 200, verified.text
    v = verified.json()
    assert v["valid"] is True and v["signature_valid"] is True, v
    assert v["recomputed_head"] == doc["head"]

    # tamper one exported entry's action directly in the DB, then restore (leave no damage)
    victim_id = doc["entries"][0]["id"]
    with session_scope() as s:
        victim = s.get(AuditEntry, victim_id)
        original = victim.action
        victim.action = original + "-tampered"
    try:
        broken = client.get("/v1/audit-events/export/verify",
                            params={"count": doc["count"],
                                    "signature": doc["signature"]}).json()
        assert broken["valid"] is False, "tampering must break chain verification (AT17)"
        assert broken["signature_valid"] is False, "tampering must break the export signature"
        assert broken["recomputed_head"] != doc["head"]
    finally:
        with session_scope() as s:
            s.get(AuditEntry, victim_id).action = original
    restored = client.get("/v1/audit-events/export/verify",
                          params={"count": doc["count"],
                                  "signature": doc["signature"]}).json()
    assert restored["valid"] is True and restored["signature_valid"] is True


# --- 7. AT11 retry bounds -------------------------------------------------------------------

def test_AT11__failing_collection_task_retries_are_bounded(client):
    """N02 patched with a raiser: attempts must stop at the configured bound (3), the task
    ends failed, and the run can never report success."""
    from nhi_sentinel.config import get_settings
    from nhi_sentinel.worker import engine, nodes

    tenant_a = _tenant_a_id()
    _enable_connectors(tenant_a)
    original = nodes.HANDLERS["N02"]

    def _raiser(ctx):  # noqa: ANN001
        raise RuntimeError("AT11 synthetic collection outage")

    nodes.HANDLERS["N02"] = _raiser
    try:
        with session_scope() as s:
            eng = s.execute(select(Engagement).where(
                Engagement.tenant_id == tenant_a)).scalars().first()
            sv = s.execute(select(ScopeVersion).where(
                ScopeVersion.engagement_id == eng.id, ScopeVersion.version == 1)).scalars().first()
            run = Run(id=new_id("run"), tenant_id=tenant_a, engagement_id=eng.id,
                      scope_version_id=sv.id, epoch=99, mode="passive", state="queued",
                      versions_json={"engine": "1.0.0"}, budget_json={}, created_by="qa-at11")
            s.add(run)
            s.flush()
            run_id = run.id
        engine.create_run_tasks(tenant_a, run_id)
        state = _drive_run(run_id, RUN_PARKED_STATES)

        with session_scope() as s:
            n02_tasks = s.execute(select(Task).where(
                Task.run_id == run_id, Task.node == "N02")).scalars().all()
            run_row = s.get(Run, run_id)
            n02 = [(t.attempt, t.state, t.error or "") for t in n02_tasks]
            parked_state = run_row.state
        assert n02_tasks, "expected N02 collection partition tasks"
        bound = get_settings().bounds.max_task_attempts
        for attempt, tstate, error in n02:
            assert attempt == bound, \
                f"attempt {attempt} exceeds/below the retry bound {bound} (tasks={n02}, state={parked_state})"
            assert tstate == "failed"
            assert "AT11" in error
        assert parked_state == "waiting_approval", \
            f"run parks at the release gate with failed collection first, got {parked_state}"

        # refuse the gate (ok=False): with a failed N02 the run must finalize as failed
        engine.complete_external_gate(tenant_a, run_id, "G02", ok=False,
                                      note="qa: gate refused after failed collection (AT11)")
        final = _drive_run(run_id, {"failed", "cancelled", "partial", "succeeded"})
        with session_scope() as s:
            assert s.get(Run, run_id).state == "failed", f"final state {final}"
    finally:
        nodes.HANDLERS["N02"] = original


# --- 8. AT19 unsupported claims --------------------------------------------------------------

def test_AT19__report_claims_carry_no_maturity_labels_or_dollar_figures(client, full_run_id):
    analyst = login(client, ANALYST)
    mine = [r for r in client.get("/v1/reports").json() if r["run_id"] == full_run_id]
    if not mine:  # only drafts exist for other runs -> assemble one for this run (do NOT release)
        created = client.post("/v1/reports", headers=analyst["headers"],
                              json={"run_id": full_run_id})
        assert created.status_code == 202, created.text
        mine = [r for r in client.get("/v1/reports").json() if r["run_id"] == full_run_id]
    assert mine, "expected a report for the shared full run"

    detail = client.get(f"/v1/reports/{mine[0]['report_id']}")
    assert detail.status_code == 200, detail.text
    report = detail.json()
    claims = report.get("claims") or []
    assert claims, "report must carry explicit claims (AT19 surface)"

    for claim in claims:
        text_low = (claim.get("text") or "").lower()
        for frag in BANNED_CLAIM_FRAGMENTS:
            assert frag not in text_low, \
                (f"claim {claim.get('claim_id')} contains unsupported label {frag!r}: "
                 f"{claim.get('text')!r}")

    score = (report.get("content") or {}).get("posture_score") or {}
    assert score.get("aggregate_status") == "unavailable", \
        "detection is unexercised in pilot: the aggregate must stay unavailable (PS11/AT19)"
    assert score.get("observed_scope_score") is None, \
        "no invented dollar figure or numeric score may appear when detection is unmeasured"


# --- 4. SC22/AT25 rate limiting ---------------------------------------------------------------

def test_SC22__sliding_window_returns_429_with_retry_after_and_health_exempt(tmp_path):
    """Subprocess isolation: the limiter binds at app construction, so we launch a real
    server with NHI_RATE_LIMIT_PER_MIN=3 instead of mutating suite-global settings."""
    import httpx
    import subprocess
    import time as _time
    import urllib.request

    data_dir = tmp_path / "rl-data"
    port = 8577
    env = {**os.environ, "NHI_RATE_LIMIT_PER_MIN": "3",
           "NHI_DATA_DIR": str(data_dir), "NHI_WEB_DIR": str(Path(__file__).resolve().parent.parent / "web")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "nhi_sentinel.api.app:create_app",
         "--factory", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = _time.time() + 20
        up = False
        while _time.time() < deadline:
            try:
                urllib.request.urlopen(base + "/health", timeout=1)
                up = True
                break
            except Exception:
                _time.sleep(0.3)
        assert up, "rate-limit probe server did not start"

        with httpx.Client(base_url=base) as client:
            codes = [client.get("/v1/me").status_code for _ in range(3)]
            assert all(c in (200, 401) for c in codes)
            fourth = client.get("/v1/me")
            assert fourth.status_code == 429, fourth.text
            body = fourth.json()
            assert set(body) == {"error"}, f"expected EX07 envelope, got {body}"
            assert body["error"]["code"] == "RATE_LIMITED"
            assert fourth.headers.get("X-Correlation-ID")
            retry_after = fourth.headers.get("Retry-After")
            assert retry_after is not None and int(retry_after) >= 1, "429 must carry Retry-After"
            for _ in range(5):
                health = client.get("/health")
                assert health.status_code == 200, health.text
    finally:
        proc.terminate()
        proc.wait(timeout=10)
