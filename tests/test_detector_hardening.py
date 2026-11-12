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

from apex import advisor, eligibility
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
    f = _takeover_finding("https://old.example.com", r.body, r.status, ["org.github.io"])
    assert f is not None and "GitHub Pages" in f.title
    assert "404" in f.evidence and "org.github.io" in f.evidence


# ---- takeover: маркер + CNAME ----------------------------------------------
# Пример CNAME-цели на домене каждого сервиса (как её вернул бы резолвер).
SERVICE_CNAME = {
    "GitHub Pages": "org.github.io",
    "AWS S3": "bucket.s3-website-us-east-1.amazonaws.com",
    "Heroku": "app-1234.herokudns.com",
    "Fastly": "prod.global.fastly.net",
    "Shopify": "shops.myshopify.com",
    "Surge.sh": "na-west1.surge.sh",
    "Bitbucket": "team.bitbucket.io",
    "Pantheon": "live-site.pantheonsite.io",
    "Tilda": "project123.tilda.ws",
    "Help Scout": "acme.helpscoutdocs.com",
    "Ghost": "acme.ghost.io",
}
GENERIC = sorted(s for s, fp in TAKEOVER_FINGERPRINTS.items() if fp.error_only)
UNIQUE = sorted(s for s, fp in TAKEOVER_FINGERPRINTS.items() if not fp.error_only)


def _body(service):
    return b"<html>" + TAKEOVER_FINGERPRINTS[service].marker + b"</html>"


def test_fingerprint_table_shape():
    assert set(SERVICE_CNAME) == set(TAKEOVER_FINGERPRINTS)
    # короткие общие фразы обязаны быть помечены error_only
    assert {"AWS S3", "Bitbucket", "Surge.sh", "Tilda"} <= set(GENERIC)
    assert "GitHub Pages" in UNIQUE and "Heroku" in UNIQUE
    for service, fp in TAKEOVER_FINGERPRINTS.items():
        assert isinstance(fp.marker, bytes) and len(fp.marker) >= 10, service
        assert fp.cname_suffixes and all("." in s and s == s.lower() for s in fp.cname_suffixes), service


@pytest.mark.parametrize("service", sorted(TAKEOVER_FINGERPRINTS))
def test_marker_plus_matching_cname_is_confirmed_finding(service):
    f = _takeover_finding("https://old.example.com", _body(service), 404, [SERVICE_CNAME[service]])
    assert f is not None and f.title == f"Возможный subdomain takeover ({service})"
    assert f.severity in ("high", "critical") and f.module == "recon"
    assert SERVICE_CNAME[service] in f.evidence
    assert eligibility.classify(f)[0] == eligibility.ELIGIBLE
    assert advisor._match(f) == "subdomain_takeover"


@pytest.mark.parametrize("service", sorted(TAKEOVER_FINGERPRINTS))
def test_cname_match_is_case_and_trailing_dot_insensitive(service):
    cname = SERVICE_CNAME[service].upper() + "."
    f = _takeover_finding("https://old.example.com", _body(service), 404, [cname])
    assert f is not None and f.title.startswith("Возможный subdomain takeover")


@pytest.mark.parametrize("cnames", [
    None,                                   # резолвера нет
    [],                                     # CNAME-записи нет (A-запись)
    ["lb.example.com"],                     # CNAME на свой же балансировщик
    ["cdn.cloudfront.net"],                 # CNAME на другой сервис
])
@pytest.mark.parametrize("service", GENERIC)
def test_generic_marker_without_cname_match_is_not_a_finding(service, cnames):
    """Своя 404-страница со словами «Repository not found» — не takeover."""
    assert _takeover_finding("https://git.example.com", _body(service), 404, cnames) is None


@pytest.mark.parametrize("cnames,why", [
    (None, "резолвер недоступен"),
    ([], "CNAME-записи нет"),
    (["lb.example.com"], "lb.example.com"),
])
@pytest.mark.parametrize("service", UNIQUE)
def test_unique_marker_without_cname_match_is_low_confidence(service, cnames, why):
    f = _takeover_finding("https://old.example.com", _body(service), 404, cnames)
    assert f is not None and "CNAME не подтверждён" in f.title and service in f.title
    assert f.severity == "low" and f.cvss_score == 0.0
    assert why in f.evidence
    # не уходит как готовая к подаче находка, но плейбук остаётся доступен
    assert eligibility.classify(f)[0] == eligibility.NEEDS_IMPACT
    assert advisor._match(f) == "subdomain_takeover"


@pytest.mark.parametrize("name", [
    "github.io.example.com",                # суффикс сервиса внутри своего домена
    "notgithub.io",                         # не граница метки
    "evilgithub.io.attacker.example",
])
def test_cname_suffix_must_match_on_label_boundary(name):
    fp = TAKEOVER_FINGERPRINTS["GitHub Pages"]
    assert not fp.matches_cname(name)
    f = _takeover_finding("https://old.example.com", _body("GitHub Pages"), 404, [name])
    assert f is not None and f.severity == "low"       # только низкая уверенность


@pytest.mark.parametrize("name,expected", [
    ("bucket.s3.amazonaws.com", True),
    ("bucket.s3.eu-west-1.amazonaws.com", True),
    ("bucket.s3-website-us-east-1.amazonaws.com", True),
    ("s3-1-w.amazonaws.com", True),
    ("my-lb-123.eu-west-1.elb.amazonaws.com", False),  # AWS, но не S3
    ("ec2-1-2-3-4.compute-1.amazonaws.com", False),
    ("amazonaws.com", False),
])
def test_s3_cname_requires_s3_label(name, expected):
    assert TAKEOVER_FINGERPRINTS["AWS S3"].matches_cname(name) is expected


def test_cname_of_one_service_does_not_confirm_marker_of_another():
    # маркер S3 (общий), а CNAME ведёт на GitHub Pages — подтверждения нет
    assert _takeover_finding("https://old.example.com", _body("AWS S3"), 404, ["org.github.io"]) is None


@pytest.mark.parametrize("service", GENERIC)
@pytest.mark.parametrize("status", [0, 200, 204, 301, 302])
def test_generic_marker_on_live_page_is_not_a_finding_even_with_cname(service, status):
    body = b"<article>How to fix the error: " + TAKEOVER_FINGERPRINTS[service].marker + b"</article>"
    assert _takeover_finding("https://docs.example.com", body, status, [SERVICE_CNAME[service]]) is None


@pytest.mark.parametrize("service", GENERIC)
@pytest.mark.parametrize("status", [400, 404, 410, 500, 503])
def test_generic_marker_on_error_response_with_cname_is_a_finding(service, status):
    assert _takeover_finding("https://old.example.com", _body(service), status,
                             [SERVICE_CNAME[service]]) is not None


@pytest.mark.parametrize("service", UNIQUE)
def test_unique_marker_with_cname_fires_regardless_of_status(service):
    f = _takeover_finding("https://old.example.com", _body(service), 200, [SERVICE_CNAME[service]])
    assert f is not None and f.severity in ("high", "critical")


@pytest.mark.parametrize("body", [b"", b"<html>Welcome</html>", b"nosuchbucket", b"Not Found"])
def test_takeover_no_finding_on_unrelated_error_page(body):
    assert _takeover_finding("https://example.com", body, 404, ["org.github.io"]) is None


# ---- резолвер CNAME ---------------------------------------------------------
def test_system_resolver_returns_chain_without_host_itself(monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname_ex",
                        lambda h: ("Org.GitHub.io.", ["old.example.com", "alias.fastly.net"], ["192.0.2.1"]))
    assert recon.system_cname_resolver("old.example.com") == ["org.github.io", "alias.fastly.net"]


def test_system_resolver_no_cname_and_dns_error(monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname_ex", lambda h: (h, [], ["192.0.2.1"]))
    assert recon.system_cname_resolver("example.com") == []

    def boom(h):
        raise OSError("nxdomain")
    monkeypatch.setattr(recon.socket, "gethostbyname_ex", boom)
    assert recon.system_cname_resolver("example.com") == []


def test_resolve_cnames_degrades_gracefully():
    def broken(host):
        raise RuntimeError("resolver down")
    assert recon._resolve_cnames("example.com", None) is None
    assert recon._resolve_cnames("example.com", broken) is None
    assert recon._resolve_cnames("example.com", lambda h: ["A.GitHub.IO.", ""]) == ["a.github.io"]
    assert recon._resolve_cnames("example.com", lambda h: iter(())) == []


# ---- takeover: сквозной прогон recon.run -----------------------------------
@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """Страховка: ни один тест этого файла не делает настоящий DNS-запрос."""
    def blocked(host, *a, **kw):
        raise AssertionError(f"реальный DNS-запрос в тесте: {host}")
    monkeypatch.setattr(recon.socket, "gethostbyname", blocked)
    monkeypatch.setattr(recon.socket, "gethostbyname_ex", blocked)


class ReconHTTP:
    def __init__(self, pages):
        self.pages = pages
        self.urls = []

    def get(self, url, **_kw):
        self.urls.append(url)
        return self.pages.get(url, Resp(0))


class Resolver:
    def __init__(self, table):
        self.table = table
        self.asked = []

    def __call__(self, host):
        self.asked.append(host)
        return self.table.get(host, [])


GH_404 = b"<title>Site not found</title>There isn't a GitHub Pages site here."


def test_recon_run_reports_confirmed_takeover(tmp_path, monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    scope = _scope(tmp_path, in_scope=["old.example.com", "docs.example.com", "git.example.com"])
    http = ReconHTTP({
        "https://old.example.com": Resp(404, {"server": "GitHub.com"}, GH_404),
        # живая документация, упоминающая NoSuchBucket, — не takeover
        "https://docs.example.com": Resp(200, {}, b"<title>Docs</title>NoSuchBucket means ..."),
        # своя 404-страница git-сервера — маркер есть, CNAME на сервис нет
        "https://git.example.com": Resp(404, {}, b"<title>Git</title>Repository not found"),
    })
    resolver = Resolver({"old.example.com": ["org.github.io"], "git.example.com": ["lb.example.com"]})
    store = Store()
    fs = recon.run(scope, store, http, True, cname_resolver=resolver)
    assert [f.target for f in fs] == ["https://old.example.com"]
    assert fs[0].severity in ("high", "critical") and "org.github.io" in fs[0].evidence
    assert store.findings == fs
    # DNS спрашиваем только там, где маркер уже найден
    assert resolver.asked == ["old.example.com", "git.example.com"]
    urls = {a.value: a for a in store.assets if a.kind == "url"}
    assert urls["https://old.example.com"].meta["status"] == 404
    assert urls["https://docs.example.com"].meta["title"] == "Docs"


def test_recon_run_falls_back_to_http_and_skips_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    scope = _scope(tmp_path, in_scope=["old.example.com", "blog.example.com"],
                   out_of_scope=["blog.example.com"])
    http = ReconHTTP({
        "http://old.example.com": Resp(404, {}, b"<Error><Code>NoSuchBucket</Code></Error>"),
        "https://blog.example.com": Resp(404, {}, GH_404),
    })
    resolver = Resolver({"old.example.com": ["old.example.com.s3.amazonaws.com"]})
    fs = recon.run(scope, Store(), http, True, cname_resolver=resolver)
    assert len(fs) == 1 and "AWS S3" in fs[0].title and fs[0].target == "http://old.example.com"
    assert not any("blog.example.com" in u for u in http.urls)   # out-of-scope не запрашивался
    assert "blog.example.com" not in resolver.asked              # и не резолвился


@pytest.mark.parametrize("resolver", [None, lambda h: (_ for _ in ()).throw(RuntimeError("down"))])
def test_recon_run_without_working_resolver_degrades(tmp_path, monkeypatch, resolver):
    """Нет резолвера или он падает: прогон не падает, критичной находки нет."""
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    scope = _scope(tmp_path, in_scope=["old.example.com", "git.example.com"])
    http = ReconHTTP({
        "https://old.example.com": Resp(404, {}, GH_404),
        "https://git.example.com": Resp(404, {}, b"Repository not found"),
    })
    store = Store()
    fs = recon.run(scope, store, http, True, cname_resolver=resolver)
    assert len(fs) == 1 and fs[0].target == "https://old.example.com"
    assert fs[0].severity == "low" and "CNAME не подтверждён" in fs[0].title
    assert eligibility.classify(fs[0])[0] == eligibility.NEEDS_IMPACT
    assert len([a for a in store.assets if a.kind == "url"]) == 2


def test_recon_run_default_resolver_uses_system_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    monkeypatch.setattr(recon.socket, "gethostbyname_ex",
                        lambda h: ("org.github.io", [h], ["127.0.0.1"]))
    scope = _scope(tmp_path, in_scope=["old.example.com"])
    http = ReconHTTP({"https://old.example.com": Resp(404, {}, GH_404)})
    fs = recon.run(scope, Store(), http, True)
    assert len(fs) == 1 and fs[0].severity in ("high", "critical")


def test_recon_run_skips_unresolvable_host_and_requires_authorization(tmp_path, monkeypatch):
    def no_dns(host):
        raise OSError("nxdomain")
    monkeypatch.setattr(recon.socket, "gethostbyname", no_dns)
    scope = _scope(tmp_path, in_scope=["old.example.com"])
    http = ReconHTTP({})
    resolver = Resolver({})
    assert recon.run(scope, Store(), http, True, cname_resolver=resolver) == []
    with pytest.raises(PermissionError):
        recon.run(scope, Store(), http, False, cname_resolver=resolver)
    assert http.urls == [] and resolver.asked == []


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
