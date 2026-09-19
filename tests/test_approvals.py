"""AT05/SC05 two-person approval flow on the seeded dormant active-proof proposal (DC16/DC17,
D06: approvals never become capability in pilot)."""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from nhi_sentinel.core.db import ToolInvocation, session_scope

from .conftest import APPROVER1, APPROVER2, DEMO_PASSWORD, login

BAD_DIGEST = "0" * 64


def _approve(client, session, proposal: dict, digest: str, password: str = DEMO_PASSWORD):
    return client.post("/v1/approvals", headers=session["headers"], json={
        "proposal_id": proposal["proposal_id"],
        "proposal_digest": digest,
        "decision": "approve",
        "reason": "QA approval-flow decision",
        "reauth_password": password,
    })


def _seeded_proposal(client) -> dict:
    rows = client.get("/v1/proposals").json()
    seeded = [p for p in rows
              if p["kind"] == "active_proof" and p["template"] == "aws.iam_role_trust_probe"]
    assert seeded, "seeded dormant active-proof proposal missing"
    return seeded[0]


@pytest.fixture(scope="module")
def proposal(client):
    """The seeded pending proposal; fetched fresh so tests observe lifecycle transitions."""
    login(client, APPROVER1)
    return _seeded_proposal(client)


def test_AT05__approval_with_wrong_digest_is_409_stale(client, proposal):
    assert proposal["status"] == "pending"
    approver1 = login(client, APPROVER1, role="approver")
    resp = _approve(client, approver1, proposal, digest=BAD_DIGEST)
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"]["code"] == "STALE_APPROVAL"
    # no approval recorded
    after = _seeded_proposal(client)
    assert after["status"] == "pending" and after["approvals"] == []


def test_AT05__approval_with_wrong_reauth_password_is_401(client, proposal):
    approver1 = login(client, APPROVER1, role="approver")
    resp = _approve(client, approver1, proposal, digest=proposal["action_digest"],
                    password="not-my-password")
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "REAUTH_FAILED"
    after = _seeded_proposal(client)
    assert after["status"] == "pending" and after["approvals"] == []


def test_SC05__same_actor_cannot_approve_twice(client, proposal):
    approver1 = login(client, APPROVER1, role="approver")
    first = _approve(client, approver1, proposal, digest=proposal["action_digest"])
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "pending", "one approval must not reach quorum"

    second = _approve(client, approver1, proposal, digest=proposal["action_digest"])
    assert second.status_code == 422, second.text
    assert second.json()["error"]["code"] == "DUPLICATE_ACTOR"


def test_AT05__second_distinct_approver_reaches_approved(client, proposal):
    approver2 = login(client, APPROVER2, role="approver")
    resp = _approve(client, approver2, proposal, digest=proposal["action_digest"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"

    after = _seeded_proposal(client)
    assert after["status"] == "approved"
    actors = {a["actor_id"] for a in after["approvals"] if a["decision"] == "approve"}
    assert len(actors) == 2, "two distinct humans required (DC17)"


def test_D06__fully_approved_active_proof_cannot_execute(client):
    proposal = _seeded_proposal(client)
    assert proposal["status"] == "approved", "previous two-person approval must hold"
    approver1 = login(client, APPROVER1, role="approver")
    resp = client.post(f"/v1/proposals/{proposal['proposal_id']}/execute",
                       headers=approver1["headers"])
    assert resp.status_code == 422, resp.text
    assert resp.json()["error"]["code"] == "ACTIVE_PROOF_DISABLED"
    # D06: approvals never become capability - no execution record exists
    with session_scope() as s:
        n = s.execute(select(func.count()).select_from(ToolInvocation)).scalar() or 0
    assert n == 0, "an approved active proof must never dispatch a tool invocation"
