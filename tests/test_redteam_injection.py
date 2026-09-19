"""AT03/VD13-lite pragmatic injection-surface checks: the XSS canary travels as data,
the served portal contains no document.write, and app.js (if present) only ever assigns
static string literals to innerHTML."""
from __future__ import annotations

import re

import pytest

from nhi_sentinel.config import get_settings

from .conftest import ANALYST, full_run_id, login  # noqa: F401  (full_run_id is a fixture)

CANARY_FRAGMENT = "alert(1)"


def test_VD13__xss_canary_travels_as_plain_data_not_executable_markup(client, full_run_id):
    analyst = login(client, ANALYST)
    resp = client.get("/v1/identities", params={"limit": 100})
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/json"), \
        "identity data must be served as JSON, never as executable text/html"
    items = resp.json()["items"]

    canaries = [i for i in items if CANARY_FRAGMENT in (i.get("display_name") or "")]
    assert canaries, "expected the entra XSS canary identity (sp-reporting-app) in the corpus"
    for item in canaries:
        name = item["display_name"]
        # the payload survives as opaque display text, escaped by JSON encoding on the wire
        assert "<script>" in name and CANARY_FRAGMENT in name
        assert isinstance(name, str)


def test_AT03__served_portal_html_contains_no_document_write(client):
    resp = client.get("/portal/index.html")
    assert resp.status_code == 200, "the app must serve its control-room portal"
    assert resp.headers["content-type"].startswith("text/html")
    assert "document.write" not in resp.text, "document.write is a DOM-XSS vector"
    for match in re.finditer(r"innerHTML\s*=", resp.text):
        tail = resp.text[match.start():match.start() + 60].strip()
        assert re.match(r"innerHTML\s*=\s*['\"]", tail), \
            f"non-literal innerHTML assignment in index.html: {tail!r}"


def test_VD13__portal_js_innerhtml_only_ever_gets_static_literals():
    app_js = get_settings().web_dir / "app.js"
    if not app_js.exists():
        pytest.skip("web/app.js not present yet (portal JS lands with the frontend package)")
    source = app_js.read_text(encoding="utf-8")
    offenders = []
    for match in re.finditer(r"innerHTML\s*=", source):  # assignments only, not prose/comments
        tail = source[match.start():match.start() + 80]
        if not re.match(r"innerHTML\s*=\s*['\"]", tail):
            offenders.append(source[max(0, match.start() - 40):match.end() + 40])
    assert not offenders, \
        f"innerHTML must only be assigned static string literals; offenders: {offenders}"
