"""AT01 tenant isolation: cross-tenant object access is 404 NOT_FOUND with no metadata leak."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from nhi_sentinel.core.db import Finding, session_scope
from nhi_sentinel.core.repo import TenantViolation, scoped_get

from .conftest import (
    ANALYST,
    INTRUDER,
    TENANT_A_NAME_FRAGMENT,
    db_first_artifact,
    login,
)


@pytest.fixture(scope="module")
def tenant_a_sample(client, full_run_id):
    """A grab-bag of tenant A object ids collected via the analyst's scoped API."""
    login(client, ANALYST)
    findings = client.get("/v1/findings").json()["items"]
    assert findings, "expected promoted findings from the full run"
    identities = client.get("/v1/identities").json()["items"]
    assert identities, "expected identities from the full run"
    reports = client.get("/v1/reports").json()
    report = next((r for r in reports if r["run_id"] == full_run_id), None)
    assert report, "expected a drafted report for the full run"
    with session_scope() as s:
        row = s.execute(select(Finding).order_by(Finding.id)).scalars().first()
        tenant_a = row.tenant_id
    return {
        "tenant_id": tenant_a,
        "run_id": full_run_id,
        "finding_id": findings[0]["finding_id"],
        "identity_id": identities[0]["identity_id"],
        "artifact_id": db_first_artifact(tenant_a, full_run_id),
        "report_id": report["report_id"],
    }


def test_AT01__cross_tenant_objects_return_404_not_found(client, tenant_a_sample):
    login(client, ANALYST)  # prove the objects exist for tenant A first
    assert client.get(f"/v1/runs/{tenant_a_sample['run_id']}").status_code == 200

    intruder = login(client, INTRUDER, role="analyst")
    assert intruder["tenant_id"] != tenant_a_sample["tenant_id"], "intruder must sit in tenant B"

    tenant_a_objects = [
        f"/v1/runs/{tenant_a_sample['run_id']}",
        f"/v1/findings/{tenant_a_sample['finding_id']}",
        f"/v1/identities/{tenant_a_sample['identity_id']}",
        f"/v1/evidence/{tenant_a_sample['artifact_id']}",
        f"/v1/reports/{tenant_a_sample['report_id']}",
    ]
    for path in tenant_a_objects:
        resp = client.get(path)  # as intruder
        assert resp.status_code == 404, f"{path}: expected 404, got {resp.status_code}"
        assert resp.status_code != 403, f"{path}: must be 404, never an existence hint (403)"
        body = resp.json()
        assert set(body) == {"error"}, f"{path}: expected EX07 envelope, got {body}"
        assert body["error"]["code"] == "NOT_FOUND", f"{path}: {body}"
        assert TENANT_A_NAME_FRAGMENT not in resp.text, \
            f"{path}: tenant A name leaked in error body"
        assert tenant_a_sample["tenant_id"] not in resp.text, \
            f"{path}: tenant A id leaked in error body"


def test_AT01__intruder_list_endpoints_show_no_tenant_a_rows(client, tenant_a_sample):
    login(client, ANALYST)
    login(client, INTRUDER)

    runs = client.get("/v1/runs").json()
    assert all(r["run_id"] != tenant_a_sample["run_id"] for r in runs)

    findings = client.get("/v1/findings").json()
    assert findings["total"] == 0 and findings["items"] == []

    identities = client.get("/v1/identities").json()
    assert identities["total"] == 0 and identities["items"] == []

    reports = client.get("/v1/reports").json()
    assert all(r["run_id"] != tenant_a_sample["run_id"] for r in reports)

    overview = client.get("/v1/overview").json()
    assert TENANT_A_NAME_FRAGMENT not in str(overview)


def test_AT01__tenant_scoped_writes_cannot_touch_tenant_a(client, tenant_a_sample):
    intruder = login(client, INTRUDER)
    resp = client.patch(f"/v1/findings/{tenant_a_sample['finding_id']}",
                        headers=intruder["headers"],
                        json={"assignee_id": intruder["user_id"], "reason": "isolation probe"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "NOT_FOUND"

    # repository layer enforces the same bound for direct in-process access
    with session_scope() as s:
        with pytest.raises(TenantViolation):
            scoped_get(s, Finding, intruder["tenant_id"], tenant_a_sample["finding_id"])
