"""Export service (API23, SC21 export safety, AT32): released reports only, formula-char
sanitization, audited, payload persisted with the job."""
from __future__ import annotations

import csv
import io
import json

from .reports.core_guard import assert_tenant
from .core.db import ExportJob, Finding, Report, new_id, utcnow
from .core.security import digest_of

_SANITIZE_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: str) -> str:
    """SC21/AT32: neutralize spreadsheet formula injection in untrusted text."""
    if isinstance(value, str) and value.startswith(_SANITIZE_PREFIXES):
        return "'" + value
    return value


def build_export(session, *, tenant_id: str, report_id: str, fmt: str, created_by: str) -> ExportJob:
    report = session.get(Report, report_id)
    assert_tenant(report, tenant_id)
    if report.status != "released":
        raise ValueError("only released reports can be exported (DC19)")
    findings = session.query(Finding).filter(
        Finding.tenant_id == tenant_id, Finding.run_id == report.run_id).all()
    if fmt == "json":
        content = json.dumps({
            "report_id": report.id, "revision_digest": report.revision_digest,
            "released_at": report.released_at.isoformat() + "Z" if report.released_at else None,
            "finding_count": len(findings),
            "findings": [{
                "finding_id": f.id, "check_id": f.check_id, "target_key": f.target_key,
                "severity": f.severity, "assurance": f.assurance,
                "workflow_status": f.workflow_status, "title": f.title,
            } for f in findings],
        }, indent=1, ensure_ascii=False)
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["finding_id", "check_id", "severity", "assurance", "status",
                         "target_key", "title"])
        for f in findings:
            writer.writerow([sanitize_cell(str(v)) for v in
                             (f.id, f.check_id, f.severity, f.assurance, f.workflow_status,
                              f.target_key, f.title)])
        content = buf.getvalue()
    else:
        raise ValueError(f"unsupported export format {fmt}")
    job = ExportJob(id=new_id("exp"), tenant_id=tenant_id, report_id=report.id, format=fmt,
                    status="complete", sha256=digest_of(content), finding_count=len(findings),
                    payload=content, created_by=created_by, created_at=utcnow())
    session.add(job)
    session.flush()
    return job
