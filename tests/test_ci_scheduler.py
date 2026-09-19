"""AT29 CI gate + S00 scheduler; AT25-adjacent machine-token auth."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from nhi_sentinel.core.db import (
    Engagement, Subscription, session_scope, utcnow,
)
from nhi_sentinel.scheduler import (
    create_subscription, record_signatures, resolve_machine_token, run_due_subscriptions,
)

from .conftest import login

DEMO_CI_TOKEN = "demo-ci-token-synthetic"


def _post_eval(client, **kw):
    body = {"protected": kw.pop("protected", True)}
    if "since" in kw:
        body["since"] = kw["since"]
    return client.post("/v1/ci/evaluations", json=body, headers={"X-API-Key": DEMO_CI_TOKEN})


def test_AT29__machine_token_required_and_validated(client, full_run_id):
    no_key = client.post("/v1/ci/evaluations", json={})
    assert no_key.status_code == 401
    bad = client.post("/v1/ci/evaluations", json={}, headers={"X-API-Key": "nope"})
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "INVALID_TOKEN"


def test_AT29__verdict_fails_on_new_blocking_findings(client, full_run_id):
    resp = _post_eval(client)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "fail", f"fixture corpus has blocking findings: {body}"
    assert body["blocking_findings"], "fail must list blocking findings"
    assert all(b["severity"] in ("critical", "high") for b in body["blocking_findings"])


def test_AT29__verdict_passes_when_since_excludes_findings(client, full_run_id):
    future = (utcnow() + timedelta(days=1)).isoformat() + "Z"
    # protected (default): partial coverage keeps the verdict unknown (fail-closed default)
    strict = _post_eval(client, since=future)
    assert strict.json()["verdict"] == "unknown", strict.text
    # repo-owner config tolerates unknown -> pass with no blocking findings
    resp = _post_eval(client, since=future, protected=False)
    body = resp.json()
    assert body["verdict"] == "pass", body
    assert body["blocking_findings"] == []


def test_AT29__partial_coverage_yields_unknown_fail_closed(client, full_run_id):
    """Fixture entra source is partial -> protected deployments must see unknown."""
    resp = _post_eval(client, since=(utcnow() + timedelta(days=1)).isoformat() + "Z")
    body = resp.json()
    # blocking findings removed via since; partial entra forces unknown (fail-closed)
    assert body["verdict"] == "unknown", body
    assert "entra" in body.get("partial_sources", [])


def test_S00__due_subscription_starts_run_and_records_signature(client, full_run_id):
    analyst = login(client, "admin@demo.nhi", role="tenant_admin")
    eng = client.get("/v1/engagements").json()[0]["engagement_id"]
    created = client.post("/v1/subscriptions", headers=analyst["headers"],
                          json={"engagement_id": eng, "cadence_hours": 24})
    assert created.status_code == 201, created.text
    sub_id = created.json()["subscription_id"]

    # force due + drive the scheduler pass directly
    with session_scope() as s:
        sub = s.get(Subscription, sub_id)
        sub.last_run_at = utcnow() - timedelta(hours=25)
    started = run_due_subscriptions()
    assert started >= 1, "due subscription must start a run (S00)"
    with session_scope() as s:
        sub = s.get(Subscription, sub_id)
        assert sub.last_run_id
    # signature recording: first pass records, second is quiet (OP18 no-change semantics)
    assert record_signatures() >= 1
    assert record_signatures() == 0  # identical signature set -> quiet no-change scan

    # disable via API
    patched = client.patch(f"/v1/subscriptions/{sub_id}", headers=analyst["headers"],
                           json={"enabled": False})
    assert patched.status_code == 200
    assert run_due_subscriptions() == 0


def test_machine_token_resolution():
    token = resolve_machine_token(DEMO_CI_TOKEN)
    assert token.label == "demo-ci-pipeline"
