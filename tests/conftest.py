"""QA work-package shared fixtures (session-scoped app/client; AT01-AT27 support).

Isolation model: a fresh NHI_DATA_DIR temp dir is set BEFORE any nhi_sentinel import,
then settings + DB engine are reset so the whole suite runs against a throwaway SQLite
file. The app's background engine loop ticks concurrently with TestClient calls; that is
safe (idempotent ticks + serialized dispatch), and assertions refetch state.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

# Must run before any nhi_sentinel import anywhere in the suite (config reads NHI_ env).
QA_DATA_DIR = Path(tempfile.mkdtemp(prefix="nhi-sentinel-qa-"))
os.environ["NHI_DATA_DIR"] = str(QA_DATA_DIR)
# SC22/AT25: keep the in-process rate limiter out of the way for the whole suite
# (test_leftovers.py exercises it with its own module-scoped mini-app fixture).
os.environ["NHI_RATE_LIMIT_PER_MIN"] = "100000"

# (transactional shim removed: the app now passes sessions explicitly; nested
# session_scope calls no longer exist in app code, so tests exercise real behavior)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_JSON = Path(__file__).resolve().parent / "golden" / "expected_outcomes.json"

DEMO_PASSWORD = "demo-synthetic-only"
ADMIN = "admin@demo.nhi"
ANALYST = "analyst@demo.nhi"
OPERATOR = "operator@demo.nhi"
APPROVER1 = "approver1@demo.nhi"
APPROVER2 = "approver2@demo.nhi"
REVIEWER = "reviewer@demo.nhi"
VIEWER = "viewer@demo.nhi"
AUDITOR = "auditor@demo.nhi"
INTRUDER = "intruder@contoso.nhi"  # tenant B analyst (AT01 counterpart)
TENANT_A_NAME_FRAGMENT = "Northwind"


# --- session-scoped app/client -------------------------------------------------

@pytest.fixture(scope="session")
def app():
    """The real FastAPI app on a fresh throwaway DB (also used for direct ASGI calls)."""
    from nhi_sentinel.config import reset_settings
    from nhi_sentinel.core.db import reset_db

    reset_settings()
    reset_db()
    from nhi_sentinel.api.app import create_app
    from nhi_sentinel.seed import ensure_seed

    info = ensure_seed()
    assert info.get("tenant_id"), "seed did not produce tenant A"
    return create_app()


@pytest.fixture(scope="session")
def client(app):
    """TestClient running the real app lifespan (seed + engine loop) on a fresh DB."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def full_run_id(client):
    """One shared full passive pass (seeded approved scope v1) for read-only consumers."""
    return run_full_pass(client)


# --- auth helper -----------------------------------------------------------------

def login(client: TestClient, email: str, role: str | None = None) -> dict:
    """Login and return {"user_id","email","role","tenant_id","csrf_token","headers"}.

    The client cookie jar now carries this user's HttpOnly session cookie; mutations
    must send result["headers"] (X-CSRF-Token)."""
    resp = client.post("/v1/auth/login", json={"email": email, "password": DEMO_PASSWORD})
    assert resp.status_code == 200, f"login failed for {email}: {resp.status_code} {resp.text}"
    data = resp.json()
    assert data.get("csrf_token"), f"no csrf token returned for {email}"
    if role is not None:
        assert data.get("role") == role, f"{email}: expected role {role}, got {data.get('role')}"
    return {
        "user_id": data["user_id"],
        "email": data["email"],
        "role": data["role"],
        "tenant_id": data["tenant_id"],
        "csrf_token": data["csrf_token"],
        "headers": {"X-CSRF-Token": data["csrf_token"]},
    }


# --- run helpers -----------------------------------------------------------------

def start_run(client: TestClient, session: dict) -> str:
    """POST /v1/runs against the seeded approved scope v1 (scope drives the run).

    The AT24 readiness gate requires connectors to pass read-only preflight first, so the
    operator session runs preflight for each connector before the run is created. The API
    also enforces OP17 (request lists must be subsets of the approved scope)."""
    from nhi_sentinel.seed import PILOT_CHECK_IDS

    engagements = client.get("/v1/engagements").json()
    assert engagements, "no engagement visible"
    engagement_id = engagements[0]["engagement_id"]
    connectors = client.get("/v1/connectors").json()
    # preflight under the operator session FIRST (single cookie jar), then re-login the
    # analyst so cookie and CSRF header belong to the same session again
    operator = login(client, OPERATOR, role="operator")
    for c in connectors:
        pre = client.post(f"/v1/connectors/{c['connector_id']}/preflight",
                          headers=operator["headers"])
        assert pre.status_code == 200, f"preflight failed for {c['connector_id']}: {pre.text}"
        assert pre.json()["ok"] is True
    session = login(client, ANALYST)
    resp = client.post("/v1/runs", headers=session["headers"], json={
        "engagement_id": engagement_id,
        "scope_version": 1,
        "connector_ids": [c["type"] for c in connectors],  # approved source names
        "check_ids": list(PILOT_CHECK_IDS),                # approved pilot checks
    })
    assert resp.status_code == 202, f"run create failed: {resp.status_code} {resp.text}"
    return resp.json()["run_id"]


def run_full_pass(client: TestClient, session: dict | None = None) -> str:
    """Create a passive run and drive the engine to quiescence in-process (synchronous)."""
    from nhi_sentinel.worker.engine import run_until_quiescent

    session = session or login(client, ANALYST)
    run_id = start_run(client, session)
    run_until_quiescent()
    return run_id


def get_run(client: TestClient, session: dict, run_id: str) -> dict:
    resp = client.get(f"/v1/runs/{run_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- direct DB helpers (read-only + custody tamper tests) --------------------------

def db_results(tenant_id: str, run_id: str) -> list[dict]:
    """CheckResult rows for a run as plain dicts (golden runner input)."""
    from sqlalchemy import select

    from nhi_sentinel.core.db import CheckResult, session_scope

    with session_scope() as s:
        rows = s.execute(select(CheckResult).where(
            CheckResult.tenant_id == tenant_id, CheckResult.run_id == run_id)).scalars().all()
        return [{"check_id": r.check_id, "target_key": r.target_key, "status": r.status,
                 "run_id": r.run_id} for r in rows]


def db_first_artifact(tenant_id: str, run_id: str) -> str:
    from sqlalchemy import select

    from nhi_sentinel.core.db import EvidenceArtifact, session_scope

    with session_scope() as s:
        art = s.execute(select(EvidenceArtifact).where(
            EvidenceArtifact.tenant_id == tenant_id,
            EvidenceArtifact.run_id == run_id).order_by(EvidenceArtifact.id)).scalars().first()
        assert art is not None, "no evidence artifact collected"
        return art.id


def load_golden() -> dict:
    """Parse tests/golden/expected_outcomes.json (tolerates the file's docstring prefix)."""
    text = GOLDEN_JSON.read_text(encoding="utf-8")
    return json.loads(text[text.index("{"):])
