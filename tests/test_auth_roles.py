"""Authentication, session lifecycle, CSRF and role capability tests (EX07/SC03/SC04/SC20)."""
from __future__ import annotations

from .conftest import ANALYST, OPERATOR, DEMO_PASSWORD, VIEWER, login, start_run


def _run_payload(client) -> dict:
    engagement_id = client.get("/v1/engagements").json()[0]["engagement_id"]
    sources = [c["type"] for c in client.get("/v1/connectors").json()] or ["aws_iam"]
    return {"engagement_id": engagement_id, "scope_version": 1,
            "connector_ids": sources, "check_ids": ["CLD-002"]}


def test_EX07__unauthenticated_me_returns_401_error_envelope(client):
    client.cookies.clear()
    resp = client.get("/v1/me")
    assert resp.status_code == 401
    assert resp.headers.get("X-Correlation-ID"), "correlation id header missing (EX07)"
    body = resp.json()
    assert set(body) == {"error"}, f"expected EX07 envelope, got {body}"
    err = body["error"]
    assert err["code"] in ("UNAUTHENTICATED", "SESSION_INVALID")
    assert err["correlation_id"]
    assert "message" in err and "retryable" in err
    assert "Traceback" not in resp.text and "stack" not in err


def test_SC03__login_with_wrong_password_is_401(client):
    resp = client.post("/v1/auth/login",
                       json={"email": ANALYST, "password": "definitely-not-the-password"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert client.cookies.get("nhi_session") is None, "failed login must not set a session"


def test_SC04__viewer_cannot_create_run_but_analyst_can(client):
    # connectors must pass preflight before any run creation (AT24 readiness gate)
    operator = login(client, OPERATOR, role="operator")
    for c in client.get("/v1/connectors").json():
        pre = client.post(f"/v1/connectors/{c['connector_id']}/preflight",
                          headers=operator["headers"])
        assert pre.status_code == 200 and pre.json()["ok"] is True

    viewer = login(client, VIEWER, role="viewer")
    denied = client.post("/v1/runs", headers=viewer["headers"], json=_run_payload(client))
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["code"] == "FORBIDDEN"

    analyst = login(client, ANALYST, role="analyst")
    allowed = client.post("/v1/runs", headers=analyst["headers"], json=_run_payload(client))
    assert allowed.status_code == 202, allowed.text
    assert allowed.json()["run_id"].startswith("run_")


def test_AT24__run_without_preflight_is_blocked(client):
    """AT24/OF02: a run cannot start past a failed/missing readiness check."""
    from sqlalchemy import select
    from nhi_sentinel.core.db import Connector, session_scope
    with session_scope() as s:
        for c in s.execute(select(Connector)).scalars():
            c.preflight_state = "not_run"
    analyst = login(client, ANALYST, role="analyst")
    denied = client.post("/v1/runs", headers=analyst["headers"], json=_run_payload(client))
    assert denied.status_code == 422, denied.text
    body = denied.json()["error"]
    assert body["code"] == "PREFLIGHT_REQUIRED"
    assert body["details"]["connectors"], "must name the un-preflighted connectors"
    # recovery: preflight then create (re-login analyst: single cookie jar)
    operator = login(client, OPERATOR, role="operator")
    for c in client.get("/v1/connectors").json():
        pre = client.post(f"/v1/connectors/{c['connector_id']}/preflight",
                          headers=operator["headers"])
        assert pre.status_code == 200 and pre.json()["ok"] is True
    analyst = login(client, ANALYST, role="analyst")
    allowed = client.post("/v1/runs", headers=analyst["headers"], json=_run_payload(client))
    assert allowed.status_code == 202, allowed.text


def test_SC20__mutation_without_csrf_header_is_rejected(client):
    analyst = login(client, ANALYST)
    resp = client.post("/v1/runs", json=_run_payload(client))  # no X-CSRF-Token header
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "CSRF_INVALID"
    # the session itself is still valid for reads
    assert client.get("/v1/me").status_code == 200


def test_SC03__logout_revokes_session_server_side(client):
    viewer = login(client, VIEWER)
    token = client.cookies.get("nhi_session")
    assert token, "expected session cookie after login"

    logout = client.post("/v1/auth/logout", headers=viewer["headers"])
    assert logout.status_code == 204
    # cookie cleared by the response -> unauthenticated
    resp = client.get("/v1/me")
    assert resp.status_code == 401
    # replaying the very same cookie must still fail: server-side revocation, not just jar loss
    client.cookies.set("nhi_session", token)
    replay = client.get("/v1/me")
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "SESSION_INVALID"
    client.cookies.clear()


def test_SC03__garbage_session_cookie_is_401(client):
    client.cookies.clear()
    client.cookies.set("nhi_session", "forged-token-value")
    resp = client.get("/v1/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "SESSION_INVALID"
    client.cookies.clear()


def test_SC03__start_run_helper_end_to_end(client):
    """Sanity for the shared helpers: a fresh login can start a run against scope v1."""
    analyst = login(client, ANALYST)
    run_id = start_run(client, analyst)
    assert run_id.startswith("run_")
