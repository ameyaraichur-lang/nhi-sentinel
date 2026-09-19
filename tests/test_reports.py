"""AT13/SC05 report lifecycle: deterministic draft with clean grounding, reviewer-only
release bound to the revision digest, immutable released content (UX23)."""
from __future__ import annotations

import pytest

from .conftest import ANALYST, DEMO_PASSWORD, REVIEWER, login

BAD_DIGEST = "f" * 64


def _reports(client) -> list[dict]:
    return client.get("/v1/reports").json()


def _report_detail(client, report_id: str) -> dict:
    resp = client.get(f"/v1/reports/{report_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _release(client, session, report_id: str, digest: str,
             password: str = DEMO_PASSWORD, review_record: str = "QA independent review record"):
    return client.post(f"/v1/reports/{report_id}/release", headers=session["headers"], json={
        "revision_digest": digest,
        "review_record": review_record,
        "reauth_password": password,
    })


@pytest.fixture(scope="module")
def engine_report(client, full_run_id):
    """The draft report the engine assembled during the shared full run (author: engine)."""
    login(client, ANALYST)
    mine = [r for r in _reports(client)
            if r["run_id"] == full_run_id and r["created_by"] == "system:run-engine"]
    assert mine, "engine-assembled report draft missing for the full run"
    return mine[0]["report_id"]


def test_AT13__full_run_produces_draft_with_clean_grounding(client, full_run_id, engine_report):
    draft = _report_detail(client, engine_report)
    assert draft["status"] == "draft"
    assert draft["run_id"] == full_run_id
    grounding = draft["grounding"] or {}
    assert grounding.get("unsupported") == [], \
        f"grounding must be clean for a deterministic draft: {grounding.get('unsupported')}"
    assert grounding.get("claims_total", 0) >= 1
    claims = draft.get("claims") or []
    assert claims, "report must carry explicit claims"
    assert all(c.get("ai_generated") is False for c in claims), "pilot narrative is deterministic"


def test_AT13__reviewer_cannot_release_with_mismatched_digest(client, engine_report):
    reviewer = login(client, REVIEWER, role="reviewer")
    resp = _release(client, reviewer, engine_report, digest=BAD_DIGEST)
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"]["code"] == "STALE_REVISION"
    assert _report_detail(client, engine_report)["status"] == "draft"


def test_SC05__analyst_author_via_api_cannot_release(client, full_run_id, engine_report):
    analyst = login(client, ANALYST)
    # analyst authors a report through the API (report:create capability)
    created = client.post("/v1/reports", headers=analyst["headers"],
                          json={"run_id": full_run_id})
    assert created.status_code == 202, created.text
    authored_id = created.json()["report_id"]
    assert _report_detail(client, authored_id)["created_by"] == analyst["user_id"]

    # the author still cannot release: role lacks report:release (SC05)
    digest = _report_detail(client, authored_id)["revision_digest"]
    resp = _release(client, analyst, authored_id, digest=digest)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "FORBIDDEN"
    assert _report_detail(client, authored_id)["status"] == "draft"

    # and the analyst cannot release the engine draft either (role, not authorship)
    engine_digest = _report_detail(client, engine_report)["revision_digest"]
    resp2 = _release(client, analyst, engine_report, digest=engine_digest)
    assert resp2.status_code == 403


def test_AT13__release_with_correct_digest_and_password_binds_signature(client, engine_report):
    reviewer = login(client, REVIEWER)
    digest = _report_detail(client, engine_report)["revision_digest"]
    assert digest, "draft must publish its revision digest"

    wrong_pw = _release(client, reviewer, engine_report, digest=digest, password="wrong-pass")
    assert wrong_pw.status_code == 401
    assert wrong_pw.json()["error"]["code"] == "REAUTH_FAILED"

    resp = _release(client, reviewer, engine_report, digest=digest)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "released"

    released = _report_detail(client, engine_report)
    assert released["status"] == "released"
    assert released["signature"], "release must bind a signature to the exact revision"
    assert released["reviewer_id"] == reviewer["user_id"]
    assert released["released_at"]


def test_UX23__claim_feedback_never_mutates_released_report(client, engine_report):
    analyst = login(client, ANALYST)
    before = _report_detail(client, engine_report)
    assert before["status"] == "released"
    claim_id = before["claims"][0]["claim_id"]

    resp = client.post(f"/v1/reports/{engine_report}/claim-feedback",
                       headers=analyst["headers"],
                       params={"claim_id": claim_id, "reference": "QA-ref-001",
                               "comment": "Flagged during QA verification"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "review_task_created"
    assert resp.json()["report_status"] == "released"

    after = _report_detail(client, engine_report)
    assert after["content"] == before["content"], "released report content is immutable"
    assert after["claims"] == before["claims"]
    assert after["status"] == "released"
    assert after["signature"] == before["signature"]


def test_AT13__grounding_validator_flags_bogus_evidence_reference():
    from nhi_sentinel.reports.builder import validate_grounding

    content = {
        "executive_summary": {"finding_counts": {}},
        "findings": [],
        "sections": {"claims": [
            {"claim_id": "claim-001", "section": "executive_summary",
             "text": "Claim citing evidence that does not exist.",
             "evidence_refs": ["art_does_not_exist"], "finding_ids": [], "ai_generated": False},
        ]},
    }
    grounding = validate_grounding(content, evidence_universe=set(), finding_universe=set())
    assert grounding["claims_total"] == 1
    assert grounding["unsupported"], "bogus evidence ref must be flagged as unsupported"
    assert grounding["unsupported"][0]["claim_id"] == "claim-001"
    assert "art_does_not_exist" in grounding["unsupported"][0]["bad_evidence"]
    assert grounding["claims_supported"] == 0
