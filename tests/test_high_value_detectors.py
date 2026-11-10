"""CORS (web) и open redirect (webprobe): детект реальных случаев без ложных
срабатываний, scope-гейт, гейт активной валидации, маршрутизация в
eligibility/advisor и поведение SafeHTTP(allow_redirects=False)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from apex import advisor, eligibility
from apex.engagement import EngagementManifest
from apex.http import SafeHTTP
from apex.models import Finding
from apex.modules import web, webprobe
from apex.modules.web import CORS_PROBE_ORIGIN, _cors_findings
from apex.scope import Scope


class Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = body


class Store:
    assets: dict = {}

    def __init__(self):
        self.added = []

    def add_finding(self, f):
        self.added.append(f)


def _scope(tmp_path: Path) -> Scope:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program": "hv-test", "authorized": True, "researcher": "ci",
        "rate_limit_rps": 50, "in_scope": ["example.com", "*.example.com"],
        "out_of_scope": [], "rules": "test",
    }))
    return Scope.load(str(p))


# ---- CORS -------------------------------------------------------------------
class CorsHTTP:
    """policy(origin) -> headers ответа."""
    def __init__(self, policy):
        self.policy = policy
        self.calls = []

    def get(self, url, headers=None, **_kw):
        origin = (headers or {}).get("Origin")
        self.calls.append(origin)
        return Resp(200, self.policy(origin) if origin else {})


def _titles(fs):
    return [f.title for f in fs]


def test_cors_reflect_with_credentials_is_high_and_eligible():
    http = CorsHTTP(lambda o: {"access-control-allow-origin": o,
                               "access-control-allow-credentials": "true"})
    fs = _cors_findings("https://example.com/", http)
    top = next(f for f in fs if "произвольного Origin с credentials" in f.title)
    assert top.severity in ("high", "critical")
    assert CORS_PROBE_ORIGIN in top.evidence
    assert eligibility.classify(top)[0] == eligibility.ELIGIBLE
    assert advisor._match(top) == "cors"
    # Origin: null тоже отражён с credentials
    assert any("null" in t for t in _titles(fs))


def test_cors_reflect_without_credentials_needs_impact():
    http = CorsHTTP(lambda o: {"access-control-allow-origin": o})
    fs = _cors_findings("https://example.com/", http)
    assert len(fs) == 1 and "без credentials" in fs[0].title
    assert fs[0].severity == "medium"
    assert eligibility.classify(fs[0])[0] == eligibility.NEEDS_IMPACT


@pytest.mark.parametrize("hdrs", [
    {},                                                       # CORS нет
    {"access-control-allow-origin": "*"},                     # публичный API
    {"access-control-allow-origin": "https://app.example.com",
     "access-control-allow-credentials": "true"},             # строгий allowlist
])
def test_cors_safe_configs_produce_no_findings(hdrs):
    assert _cors_findings("https://example.com/", CorsHTTP(lambda o: hdrs)) == []


def test_cors_null_origin_with_credentials():
    def policy(o):
        return ({"access-control-allow-origin": "null",
                 "access-control-allow-credentials": "true"} if o == "null" else {})
    fs = _cors_findings("https://example.com/", CorsHTTP(policy))
    assert _titles(fs) == ["CORS: разрешён Origin null с credentials"]
    assert eligibility.classify(fs[0])[0] == eligibility.ELIGIBLE


def test_cors_dead_target_no_findings():
    class Dead:
        def get(self, url, **_kw):
            return Resp(0)
    assert _cors_findings("https://example.com/", Dead()) == []


def test_web_run_includes_cors(tmp_path):
    class H(CorsHTTP):
        def get(self, url, headers=None, **_kw):
            if headers and "Origin" in headers:
                return super().get(url, headers=headers)
            return Resp(200 if urlparse(url).path in ("", "/") else 404,
                        {"strict-transport-security": "x", "content-security-policy": "x",
                         "x-frame-options": "x", "x-content-type-options": "x"})
    http = H(lambda o: {"access-control-allow-origin": o,
                        "access-control-allow-credentials": "true"})
    store = Store()
    web.run(_scope(tmp_path), store, http, True, ["http://example.com/"])
    assert any(f.title.startswith("CORS:") for f in store.added)


# ---- open redirect ----------------------------------------------------------
class RedirHTTP:
    """Имитирует сервер: handler(url) -> Resp. Проверяет, что редиректам не следуют."""
    def __init__(self, handler):
        self.handler = handler
        self.urls = []

    def get(self, url, allow_redirects=True, **_kw):
        assert allow_redirects is False, "webprobe не должен следовать редиректам"
        self.urls.append(url)
        return self.handler(url)


def _echo_redirect(param):
    def handler(url):
        v = parse_qs(urlparse(url).query).get(param, [""])[0]
        return Resp(302, {"location": v})
    return handler


def test_open_redirect_detected(tmp_path):
    http = RedirHTTP(_echo_redirect("next"))
    store = Store()
    fs = webprobe.run(_scope(tmp_path), store, http, True,
                      ["https://example.com/login?next=/home&x=1"])
    assert len(fs) == 1 and fs[0].title == "Open redirect: параметр next"
    assert fs[0].module == "webprobe" and store.added == fs
    assert len(http.urls) == 1                     # первый payload подтвердил — стоп
    assert "x=1" in http.urls[0]                   # прочие параметры сохранены
    assert eligibility.classify(fs[0])[0] == eligibility.NEEDS_IMPACT
    assert advisor._match(fs[0]) == "open_redirect"


def test_open_redirect_protocol_relative_bypass(tmp_path):
    def handler(url):
        v = parse_qs(urlparse(url).query).get("url", [""])[0]
        return Resp(302, {"location": v if v.startswith("//") else "/"})
    fs = webprobe.run(_scope(tmp_path), Store(), RedirHTTP(handler), True,
                      ["https://example.com/out?url=/a"])
    assert len(fs) == 1


@pytest.mark.parametrize("handler", [
    lambda url: Resp(302, {"location": "/home"}),                       # относительный
    lambda url: Resp(302, {"location": "https://example.com/home"}),    # свой хост
    lambda url: Resp(200, {}),                                          # нет редиректа
    # canary только в query своего URL — не уводит на чужой хост
    lambda url: Resp(302, {"location": "https://example.com/l?next=https://apex-redirect-canary.attacker.example/"}),
    lambda url: Resp(302, {"location": "https://apex-redirect-canary.attacker.example.example.com/"}),
])
def test_open_redirect_safe_servers_no_findings(tmp_path, handler):
    fs = webprobe.run(_scope(tmp_path), Store(), RedirHTTP(handler), True,
                      ["https://example.com/login?next=/home"])
    assert fs == []


def test_open_redirect_no_redirect_params_sends_nothing(tmp_path):
    http = RedirHTTP(_echo_redirect("q"))
    assert webprobe.run(_scope(tmp_path), Store(), http, True,
                        ["https://example.com/search?q=1", "https://example.com/"]) == []
    assert http.urls == []


def test_webprobe_gates(tmp_path):
    scope = _scope(tmp_path)
    http = RedirHTTP(_echo_redirect("next"))
    with pytest.raises(PermissionError):
        webprobe.run(scope, Store(), http, False, ["https://example.com/?next=/"])
    with pytest.raises(PermissionError):
        webprobe.run(scope, Store(), http, True, ["https://evil.org/?next=/"])
    with pytest.raises(ValueError):
        webprobe.run(scope, Store(), http, True, [])
    assert http.urls == []


def test_manifest_requires_active_policy_for_webprobe(tmp_path):
    scope = _scope(tmp_path)

    def manifest(active: bool) -> EngagementManifest:
        p = tmp_path / f"m{active}.json"
        p.write_text(json.dumps({
            "name": "m", "scope_file": "scope.json",
            "targets": ["https://example.com/?next=/"], "modules": ["webprobe"],
            "policy": {"active_web_validation": active},
        }))
        return EngagementManifest.load(p)

    with pytest.raises(PermissionError):
        manifest(False).validate_against_scope(scope)
    manifest(True).validate_against_scope(scope)


def test_advisor_has_playbooks():
    assert {"cors", "open_redirect"} <= set(advisor.PLAYBOOKS)
    f = Finding(title="Отсутствует заголовок: x-frame-options", severity="low",
                target="t", module="web")
    assert advisor._match(f) == "missing_header"   # старая маршрутизация цела


# ---- SafeHTTP(allow_redirects=False) на реальном loopback-сервере -----------
class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/r":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"final")

    def log_message(self, *a):
        pass


def test_safehttp_no_follow_returns_3xx():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        http = SafeHTTP(rate_limit_rps=100)
        r = http.get(base + "/r", allow_redirects=False)
        assert r.status == 302 and r.headers["location"] == "/final"
        followed = http.get(base + "/r")
        assert followed.status == 200 and followed.body == b"final"
    finally:
        srv.shutdown()


# ---- subdomain takeover (recon) --------------------------------------------
def test_takeover_fingerprint_detected():
    from apex.modules import recon
    f = recon._takeover_finding("https://old.example.com",
                                b"<h1>There isn't a GitHub Pages site here.</h1>")
    assert f is not None and "GitHub Pages" in f.title and f.severity in ("high", "critical")
    assert eligibility.classify(f)[0] == eligibility.ELIGIBLE
    assert advisor._match(f) == "subdomain_takeover"
    assert "subdomain_takeover" in advisor.PLAYBOOKS


def test_takeover_no_false_positive_on_normal_page():
    from apex.modules import recon
    assert recon._takeover_finding("https://example.com", b"<html>Welcome</html>") is None
