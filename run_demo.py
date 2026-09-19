#!/usr/bin/env python
"""One-command demo.

  python run_demo.py reseed            # reset DB + seed synthetic data
  python run_demo.py headless          # seed + drive one full run to the release gate (no server)
  python run_demo.py serve             # seed + start portal+API on http://127.0.0.1:8650/portal
"""
from __future__ import annotations

import sys


def headless() -> None:
    from nhi_sentinel.config import reset_settings
    reset_settings()
    from nhi_sentinel.seed import ensure_seed, PILOT_CHECK_IDS
    info = ensure_seed()
    print(f"seed: {info}")
    from sqlalchemy import select
    from nhi_sentinel.core.db import Engagement, Run, session_scope, new_id, utcnow
    from nhi_sentinel.contracts import RunState
    from nhi_sentinel.core.security import digest_of
    from nhi_sentinel.core.db import ScopeVersion
    from nhi_sentinel.worker import engine

    with session_scope() as s:
        eng = s.execute(select(Engagement)).scalars().first()
        sv = s.execute(select(ScopeVersion).where(
            ScopeVersion.engagement_id == eng.id, ScopeVersion.version == 1)).scalars().first()
        run = Run(id=new_id("run"), tenant_id=eng.tenant_id, engagement_id=eng.id,
                  scope_version_id=sv.id, epoch=1, mode="passive", state=RunState.QUEUED.value,
                  versions_json={"engine": "1.0.0"}, budget_json={}, created_by="headless")
        s.add(run)
        s.flush()
        run_id, tenant_id = run.id, run.tenant_id
    engine.create_run_tasks(tenant_id, run_id)
    ticks = engine.run_until_quiescent()
    with session_scope() as s:
        run = s.get(Run, run_id)
        from nhi_sentinel.core.db import Finding, Snapshot, CheckResult
        from sqlalchemy import select as sel
        findings = s.execute(sel(Finding).where(Finding.run_id == run_id)).scalars().all()
        snaps = s.execute(sel(Snapshot).where(Snapshot.run_id == run_id)).scalars().all()
        results = s.execute(sel(CheckResult).where(CheckResult.run_id == run_id)).scalars().all()
        print(f"run {run_id}: state={run.state}, ticks={ticks}")
        print(f"  snapshots: {[(x.source, x.state, x.seen_count) for x in snaps]}")
        print(f"  check results: {len(results)}; findings: {len(findings)}")
        for f in findings:
            print(f"    [{f.severity:<13}] {f.check_id:<9} {f.target_key[:60]}")
        print("  report parked at release gate (G02) - release via portal or API")
    return run_id


def serve() -> None:
    import uvicorn
    from nhi_sentinel.seed import ensure_seed
    print("seed:", ensure_seed())
    print("portal: http://127.0.0.1:8650/portal   docs: http://127.0.0.1:8650/api-docs")
    uvicorn.run("nhi_sentinel.api.app:create_app", factory=True, host="127.0.0.1", port=8650)


def reseed() -> None:
    from nhi_sentinel.config import get_settings
    db = get_settings().data_dir / "sentinel.db"
    for suffix in ("", "-wal", "-shm"):
        p = db.with_name(db.name + suffix)
        if p.exists():
            p.unlink()
    from nhi_sentinel.core.db import reset_db
    reset_db()
    from nhi_sentinel.seed import ensure_seed
    print("seed:", ensure_seed())


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    {"reseed": reseed, "headless": headless, "serve": serve}[cmd]()
