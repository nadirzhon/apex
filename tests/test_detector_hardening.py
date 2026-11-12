"""Надёжность новых детекторов на граничных случаях:

- subdomain takeover: висячий сервис отвечает 404/5xx — тело ошибки должно
  доходить до детектора (ложный пропуск), а общие маркеры не должны срабатывать
  на живой 200-странице (ложное срабатывание);
- open redirect: битый Location от цели не роняет прогон, обходные формы и
  несколько параметров обрабатываются.

Всё офлайн: заглушки и loopback-сервер."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from apex import eligibility
from apex.http import SafeHTTP
from apex.modules import recon, webprobe
from apex.modules.recon import TAKEOVER_FINGERPRINTS, _takeover_finding
from apex.modules.webprobe import _CANARY_HOST, _location_host
from apex.scope import Scope


class Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = body


class Store:
    def __init__(self):
        self.findings = []
        self.assets = []

    def add_finding(self, f):
        self.findings.append(f)

    def add_asset(self, a):
        self.assets.append(a)


def _scope(tmp_path: Path, in_scope=None, out_of_scope=None) -> Scope:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program": "hardening-test", "authorized": True, "researcher": "ci",
        "rate_limit_rps": 50, "in_scope": in_scope or ["example.com", "*.example.com"],
        "out_of_scope": out_of_scope or [], "rules": "test",
    }))
    return Scope.load(str(p))


# ---- SafeHTTP: тело ответа-ошибки ------------------------------------------
class _ErrH(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/big":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"x" * 5000)
            return
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>There isn't a GitHub Pages site here.</h1>")

    def do_HEAD(self):
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture()
def err_server():
    srv = HTTPServer(("127.0.0.1", 0), _ErrH)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_safehttp_keeps_error_body(err_server):
    r = SafeHTTP(rate_limit_rps=100).get(err_server + "/")
    assert r.status == 404 and r.error == "HTTP 404"
    assert b"GitHub Pages" in r.body
    assert r.headers["content-type"] == "text/html"


def test_safehttp_error_body_respects_max_bytes(err_server):
    r = SafeHTTP(rate_limit_rps=100).get(err_server + "/big", max_bytes=100)
    assert r.status == 500 and len(r.body) == 100


def test_safehttp_head_error_has_no_body(err_server):
    r = SafeHTTP(rate_limit_rps=100).get(err_server + "/", method="HEAD")
    assert r.status == 404 and r.body == b""


def test_safehttp_scoped_client_keeps_error_body(err_server):
    r = SafeHTTP(rate_limit_rps=100, in_scope=lambda u: True).get(err_server + "/")
    assert r.status == 404 and b"GitHub Pages" in r.body


def test_takeover_detected_through_real_client_on_404(err_server):
    """Регрессия: раньше тело 404 отбрасывалось и детектор был слеп."""
    r = SafeHTTP(rate_limit_rps=100).get(err_server + "/")
    f = _takeover_finding("https://old.example.com", r.body, r.status)
    assert f is not None and "GitHub Pages" in f.title
    assert "404" in f.evidence


# ---- takeover: сигнатуры и статус ------------------------------------------
@pytest.mark.parametrize("service", sorted(TAKEOVER_FINGERPRINTS))
def test_every_fingerprint_fires_on_error_response(service):
    marker, _ = TAKEOVER_FINGERPRINTS[service]
    f = _takeover_finding("https://old.example.com", b"<html>" + marker + b"</html>", 404)
    assert f is not None and service in f.title
    assert f.severity in ("high", "critical") and f.module == "recon"
    assert eligibility.classify(f)[0] == eligibility.ELIGIBLE


GENERIC = sorted(s for s, (_, error_only) in TAKEOVER_FINGERPRINTS.items() if error_only)
UNIQUE = sorted(s for s, (_, error_only) in TAKEOVER_FINGERPRINTS.items() if not error_only)


def test_fingerprint_table_shape():
    # короткие общие фразы обязаны быть помечены error_only
    assert {"AWS S3", "Bitbucket", "Surge.sh", "Tilda"} <= set(GENERIC)
    assert "GitHub Pages" in UNIQUE and "Heroku" in UNIQUE
    for service, (marker, _) in TAKEOVER_FINGERPRINTS.items():
        assert isinstance(marker, bytes) and len(marker) >= 10, service


@pytest.mark.parametrize("service", GENERIC)
@pytest.mark.parametrize("status", [0, 200, 204, 301, 302])
def test_generic_marker_on_live_page_is_not_a_finding(service, status):
    marker, _ = TAKEOVER_FINGERPRINTS[service]
    body = b"<article>How to fix the error: " + marker + b"</article>"
    assert _takeover_finding("https://docs.example.com", body, status) is None


@pytest.mark.parametrize("service", GENERIC)
@pytest.mark.parametrize("status", [400, 404, 410, 500, 503])
def test_generic_marker_on_error_response_is_a_finding(service, status):
    marker, _ = TAKEOVER_FINGERPRINTS[service]
    assert _takeover_finding("https://old.example.com", marker, status) is not None


@pytest.mark.parametrize("service", UNIQUE)
def test_unique_marker_fires_regardless_of_status(service):
    marker, _ = TAKEOVER_FINGERPRINTS[service]
    assert _takeover_finding("https://old.example.com", marker, 200) is not None


def test_generic_marker_without_status_fails_closed():
    assert _takeover_finding("https://example.com", b"NoSuchBucket") is None


@pytest.mark.parametrize("body", [b"", b"<html>Welcome</html>", b"nosuchbucket", b"Not Found"])
def test_takeover_no_finding_on_unrelated_error_page(body):
    assert _takeover_finding("https://example.com", body, 404) is None


# ---- takeover: сквозной прогон recon.run -----------------------------------
class ReconHTTP:
    def __init__(self, pages):
        self.pages = pages
        self.urls = []

    def get(self, url, **_kw):
        self.urls.append(url)
        return self.pages.get(url, Resp(0))


def test_recon_run_reports_takeover_on_dangling_host(tmp_path, monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    scope = _scope(tmp_path, in_scope=["old.example.com", "docs.example.com"])
    http = ReconHTTP({
        "https://old.example.com": Resp(404, {"server": "GitHub.com"},
                                        b"<title>Site not found</title>There isn't a GitHub Pages site here."),
        # живая документация, упоминающая NoSuchBucket, — не takeover
        "https://docs.example.com": Resp(200, {}, b"<title>Docs</title>NoSuchBucket means ..."),
    })
    store = Store()
    fs = recon.run(scope, store, http, True)
    assert [f.target for f in fs] == ["https://old.example.com"]
    assert store.findings == fs
    urls = {a.value: a for a in store.assets if a.kind == "url"}
    assert urls["https://old.example.com"].meta["status"] == 404
    assert urls["https://docs.example.com"].meta["title"] == "Docs"


def test_recon_run_falls_back_to_http_and_skips_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    scope = _scope(tmp_path, in_scope=["old.example.com", "blog.example.com"],
                   out_of_scope=["blog.example.com"])
    http = ReconHTTP({
        "http://old.example.com": Resp(404, {}, b"<Error><Code>NoSuchBucket</Code></Error>"),
        "https://blog.example.com": Resp(404, {}, b"There isn't a GitHub Pages site here."),
    })
    fs = recon.run(scope, Store(), http, True)
    assert len(fs) == 1 and "AWS S3" in fs[0].title and fs[0].target == "http://old.example.com"
    assert not any("blog.example.com" in u for u in http.urls)   # out-of-scope не запрашивался


def test_recon_run_skips_unresolvable_host_and_requires_authorization(tmp_path, monkeypatch):
    def no_dns(host):
        raise OSError("nxdomain")
    monkeypatch.setattr(recon.socket, "gethostbyname", no_dns)
    scope = _scope(tmp_path, in_scope=["old.example.com"])
    http = ReconHTTP({})
    assert recon.run(scope, Store(), http, True) == []
    with pytest.raises(PermissionError):
        recon.run(scope, Store(), http, False)
    assert http.urls == []


# ---- open redirect: разбор Location ----------------------------------------
@pytest.mark.parametrize("location", [
    f"https://{_CANARY_HOST}/",
    f"//{_CANARY_HOST}/",
    f"https:/{_CANARY_HOST}/",
    f"http:/{_CANARY_HOST}/",
    f"  https://{_CANARY_HOST}/path?x=1  ",
    f"HTTPS://{_CANARY_HOST.upper()}/",
    f"https://example.com@{_CANARY_HOST}/",          # userinfo-трюк: реальный хост — canary
    f"https://{_CANARY_HOST}:8443/",
])
def test_location_host_resolves_to_canary(location):
    assert _location_host(location) == _CANARY_HOST


@pytest.mark.parametrize("location", [
    "", "/home", "home", "?next=1", "#frag",
    f"/redirect?to=https://{_CANARY_HOST}/",
    f"https://example.com/?u=https://{_CANARY_HOST}/",
    f"https://{_CANARY_HOST}.example.com/",            # canary как поддомен своего хоста
    f"https://{_CANARY_HOST}@example.com/",            # canary в userinfo, хост свой
    f"https://not-{_CANARY_HOST}/",
    "http://[::1",                                     # битый IPv6-литерал
    "https://[bad/",
])
def test_location_host_is_not_canary(location):
    assert _location_host(location) != _CANARY_HOST


class RedirHTTP:
    def __init__(self, handler):
        self.handler = handler
        self.urls = []

    def get(self, url, allow_redirects=True, **_kw):
        assert allow_redirects is False
        self.urls.append(url)
        return self.handler(url)


def _param(url, name):
    return parse_qs(urlparse(url).query).get(name, [""])[0]


@pytest.mark.parametrize("location", ["http://[::1", "https://[bad/"])
def test_malformed_location_does_not_crash_probe(tmp_path, location):
    """Регрессия: ValueError из urlparse ронял весь прогон webprobe."""
    http = RedirHTTP(lambda url: Resp(302, {"location": location}))
    fs = webprobe.run(_scope(tmp_path), Store(), http, True,
                      ["https://example.com/login?next=/home"])
    assert fs == [] and len(http.urls) == 3            # все payload'ы опробованы, находок нет


def test_redirect_without_location_header_is_not_a_finding(tmp_path):
    http = RedirHTTP(lambda url: Resp(302, {}))
    assert webprobe.run(_scope(tmp_path), Store(), http, True,
                        ["https://example.com/login?next=/home"]) == []


def test_missing_slash_bypass_detected_by_third_payload(tmp_path):
    def handler(url):
        v = _param(url, "next")
        # фильтр режет «//», но пропускает «https:/host»
        return Resp(302, {"location": v if "//" not in v else "/"})
    http = RedirHTTP(handler)
    fs = webprobe.run(_scope(tmp_path), Store(), http, True,
                      ["https://example.com/login?next=/home"])
    assert len(fs) == 1 and len(http.urls) == 3
    assert "302" in fs[0].evidence


def test_only_vulnerable_parameter_is_reported(tmp_path):
    http = RedirHTTP(lambda url: Resp(302, {"location": _param(url, "url") or "/"}))
    fs = webprobe.run(_scope(tmp_path), Store(), http, True,
                      ["https://example.com/out?next=/a&url=/b&q=keep"])
    assert [f.title for f in fs] == ["Open redirect: параметр url"]
    # next: 3 безрезультатных payload'а; url: подтверждён первым
    assert len(http.urls) == 4
    assert all("q=keep" in u for u in http.urls)
    # при пробе одного параметра второй сохраняет исходное значение
    assert _param(http.urls[0], "url") == "/b" and _param(http.urls[3], "next") == "/a"


def test_param_name_case_insensitive_and_duplicates_probed_once(tmp_path):
    http = RedirHTTP(lambda url: Resp(200, {}))
    webprobe.run(_scope(tmp_path), Store(), http, True,
                 ["https://example.com/l?Next=/a&Next=/b"])
    assert len(http.urls) == 3                         # один ключ → один набор payload'ов


@pytest.mark.parametrize("status", [200, 201, 300, 304, 400, 404, 500, 0])
def test_non_redirect_status_with_canary_location_is_ignored(tmp_path, status):
    http = RedirHTTP(lambda url: Resp(status, {"location": f"https://{_CANARY_HOST}/"}))
    assert webprobe.run(_scope(tmp_path), Store(), http, True,
                        ["https://example.com/login?next=/home"]) == []


def test_probe_requests_stay_on_target_host(tmp_path):
    """Пробы уходят только на исходный in-scope хост; canary — лишь значение параметра."""
    http = RedirHTTP(lambda url: Resp(200, {}))
    webprobe.run(_scope(tmp_path), Store(), http, True,
                 ["https://example.com/login?next=/home"])
    assert {urlparse(u).hostname for u in http.urls} == {"example.com"}
