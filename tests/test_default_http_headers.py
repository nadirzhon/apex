"""Идентифицирующие заголовки на каждом запросе (например
``X-HackerOne-Research: <username>``): клиент, хопы редиректа, манифест,
автопилот и все модули. Офлайн: loopback-сервер и подменённый opener."""
from __future__ import annotations

import io
import json
import threading
import urllib.response
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from apex import autopilot
from apex import http as http_mod
from apex.engagement import EngagementManifest
from apex.http import UA, SafeHTTP, _merge_headers
from apex.modules import recon, secrets, web, webprobe
from apex.scope import Scope

HDR = "X-HackerOne-Research"
WHO = "researcher-ci"
DEFAULT = {HDR: WHO}


# ---- loopback-сервер, запоминающий заголовки каждого запроса ----------------
class _Srv(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.seen: list[tuple[str, dict[str, str]]] = []   # (путь, заголовки в нижнем регистре)


class _H(BaseHTTPRequestHandler):
    def _go(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.server.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        port = self.server.server_port
        if self.path.startswith("/chain/"):
            n = int(self.path.rsplit("/", 1)[1])
            if n > 0:
                return self._go(f"/chain/{n - 1}")
        elif self.path == "/cross":
            return self._go(f"http://localhost:{port}/chain/1")
        elif self.path == "/missing":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"final")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture()
def srv():
    server = _Srv(("127.0.0.1", 0), _H)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def _client(**kw) -> SafeHTTP:
    return SafeHTTP(rate_limit_rps=1000, **kw)


# ---- (а) каждый запрос несёт default-заголовок ------------------------------
def test_every_request_carries_default_header(srv):
    client = _client(default_headers=DEFAULT)
    client.get(_base(srv) + "/a")
    client.get(_base(srv) + "/b", method="HEAD")
    client.get(_base(srv) + "/missing")                      # ответ-ошибка
    client.get(_base(srv) + "/chain/1", allow_redirects=False)
    assert [p for p, _ in srv.seen] == ["/a", "/b", "/missing", "/chain/1"]
    assert all(h.get(HDR.lower()) == WHO for _, h in srv.seen)
    assert all(h["user-agent"] == UA for _, h in srv.seen)   # User-Agent не потерян


def test_multiple_default_headers_all_sent(srv):
    client = _client(default_headers={HDR: WHO, "X-Bug-Bounty": "program-123"})
    client.get(_base(srv) + "/a")
    _, h = srv.seen[0]
    assert h[HDR.lower()] == WHO and h["x-bug-bounty"] == "program-123"


# ---- (б) заголовок на хопах редиректа ---------------------------------------
@pytest.mark.parametrize("scoped", [False, True])
def test_default_header_on_every_redirect_hop(srv, scoped):
    client = _client(default_headers=DEFAULT, in_scope=(lambda u: True) if scoped else None)
    r = client.get(_base(srv) + "/chain/3")
    assert r.status == 200
    assert [p for p, _ in srv.seen] == ["/chain/3", "/chain/2", "/chain/1", "/chain/0"]
    assert all(h.get(HDR.lower()) == WHO for _, h in srv.seen)
    assert all(h["user-agent"] == UA for _, h in srv.seen)


def test_default_header_follows_redirect_to_another_host(srv):
    client = _client(default_headers=DEFAULT)
    r = client.get(_base(srv) + "/cross")
    assert r.status == 200
    hosts = [h["host"].split(":")[0] for _, h in srv.seen]
    assert hosts == ["127.0.0.1", "localhost", "localhost"]
    assert all(h.get(HDR.lower()) == WHO for _, h in srv.seen)


def test_out_of_scope_hop_still_blocked_with_default_headers(srv):
    client = _client(default_headers=DEFAULT, in_scope=lambda u: "localhost" not in u)
    r = client.get(_base(srv) + "/cross")
    assert r.status == 302 and len(srv.seen) == 1            # scope-гейт не ослаблен


# ---- (в) приоритет слоёв ----------------------------------------------------
def test_per_call_header_overrides_default(srv):
    client = _client(default_headers=DEFAULT)
    client.get(_base(srv) + "/a", headers={HDR: "override"})
    client.get(_base(srv) + "/b")
    assert srv.seen[0][1][HDR.lower()] == "override"
    assert srv.seen[1][1][HDR.lower()] == WHO                # переопределение только на один вызов


def test_per_call_override_is_case_insensitive_and_sent_once(srv):
    client = _client(default_headers=DEFAULT)
    client.get(_base(srv) + "/a", headers={HDR.lower(): "override"})
    assert srv.seen[0][1][HDR.lower()] == "override"         # ровно одно значение, не два


def test_per_call_headers_are_added_next_to_default(srv):
    client = _client(default_headers=DEFAULT)
    client.get(_base(srv) + "/a", headers={"Origin": "https://probe.example", "Cookie": "s=1"})
    _, h = srv.seen[0]
    assert h[HDR.lower()] == WHO and h["origin"] == "https://probe.example" and h["cookie"] == "s=1"


def test_default_header_can_replace_user_agent_and_call_can_replace_it_back(srv):
    client = _client(default_headers={"user-agent": "ProgramUA/1"})
    client.get(_base(srv) + "/a")
    client.get(_base(srv) + "/b", headers={"User-Agent": "CallUA/2"})
    assert srv.seen[0][1]["user-agent"] == "ProgramUA/1"
    assert srv.seen[1][1]["user-agent"] == "CallUA/2"


def test_merge_headers_order_and_case():
    assert _merge_headers({"User-Agent": "a"}, {}, {}) == {"User-Agent": "a"}
    assert _merge_headers({"User-Agent": "a"}, {"X-A": "1"}, {"x-a": "2", "X-B": "3"}) == {
        "User-Agent": "a", "x-a": "2", "X-B": "3"}


# ---- (г) без default_headers поведение прежнее ------------------------------
@pytest.mark.parametrize("kw", [{}, {"default_headers": None}, {"default_headers": {}}])
def test_without_default_headers_only_user_agent_is_added(srv, kw):
    client = _client(**kw)
    assert client.default_headers == {}
    client.get(_base(srv) + "/chain/1")
    client.get(_base(srv) + "/a", headers={"Origin": "null"})
    assert len(srv.seen) == 3
    for _, h in srv.seen[:2]:
        # только то, что urllib ставит сам, плюс наш User-Agent
        assert set(h) == {"host", "user-agent", "accept-encoding", "connection"}
        assert h["user-agent"] == UA
    assert srv.seen[2][1]["origin"] == "null" and HDR.lower() not in srv.seen[2][1]


def test_default_headers_are_copied_at_construction(srv):
    source = dict(DEFAULT)
    client = _client(default_headers=source)
    source[HDR] = "mutated"
    source["X-Late"] = "1"
    client.get(_base(srv) + "/a")
    _, h = srv.seen[0]
    assert h[HDR.lower()] == WHO and "x-late" not in h


def test_per_call_headers_do_not_leak_into_defaults(srv):
    client = _client(default_headers=DEFAULT)
    client.get(_base(srv) + "/a", headers={"Cookie": "s=1"})
    client.get(_base(srv) + "/b")
    assert "cookie" not in srv.seen[1][1] and client.default_headers == DEFAULT


# ---- (д) манифест → клиент --------------------------------------------------
def _write(tmp_path: Path, manifest_extra=None, in_scope=None) -> Path:
    (tmp_path / "scope.json").write_text(json.dumps({
        "program": "hdr-test", "authorized": True, "researcher": "ci", "rate_limit_rps": 1000,
        "in_scope": in_scope or ["example.com", "*.example.com"], "out_of_scope": [], "rules": "test",
    }))
    data = {"name": "hdr", "scope_file": "scope.json", "targets": ["http://example.com/login?next=/home"],
            "out_dir": "out", "state_file": "out/state.json"}
    data.update(manifest_extra or {})
    p = tmp_path / "engagement.json"
    p.write_text(json.dumps(data))
    return p


def test_manifest_reads_http_headers(tmp_path):
    m = EngagementManifest.load(_write(tmp_path, {"http_headers": {HDR: f"  {WHO} "}}))
    assert m.http_headers == DEFAULT                          # пробелы по краям срезаны
    assert m.summary()["http_headers"] == [HDR]               # в сводке только имена


@pytest.mark.parametrize("extra", [{}, {"http_headers": {}}, {"http_headers": None}])
def test_manifest_http_headers_default_empty(tmp_path, extra):
    m = EngagementManifest.load(_write(tmp_path, extra))
    assert m.http_headers == {} and m.summary()["http_headers"] == []


@pytest.mark.parametrize("bad", [
    ["X-A: 1"],                              # не объект
    "X-A: 1",
    {HDR: 5},                                # значение не строка
    {HDR: ""},                               # пустое значение
    {HDR: "   "},
    {"": "x"},                               # пустое имя
    {"X Bad": "x"},                          # пробел в имени
    {"X-Bad:": "x"},
    {HDR: "a\r\nX-Injected: 1"},             # попытка вставить второй заголовок
    {HDR: "a\nb"},
    {"X-A\r\nX-B": "1"},
    {"Cookie": "session=secret"},            # учётные данные — не в манифест
    {"authorization": "Bearer t"},
    {"Host": "evil.example"},
    {"Content-Length": "0"},
    {HDR: "a", HDR.lower(): "b"},            # дубликат без учёта регистра
])
def test_manifest_rejects_invalid_http_headers(tmp_path, bad):
    with pytest.raises(ValueError, match="http_headers"):
        EngagementManifest.load(_write(tmp_path, {"http_headers": bad}))


def test_manifest_refuses_http_headers_with_webvuln(tmp_path):
    """Внешний сканер webvuln шлёт запросы сам и заголовок не поставит."""
    extra = {"modules": ["web", "webvuln"], "policy": {"active_web_validation": True}}
    path = _write(tmp_path, extra)
    scope = Scope.load(str(tmp_path / "scope.json"))
    EngagementManifest.load(path).validate_against_scope(scope)          # без заголовков — можно
    path = _write(tmp_path, {**extra, "http_headers": DEFAULT})
    with pytest.raises(PermissionError, match="http_headers"):
        EngagementManifest.load(path).validate_against_scope(scope)


# ---- все модули и автопилот: заголовок на каждом исходящем запросе ----------
class FakeOpener:
    """Вместо сети: запоминает готовые urllib.Request и отдаёт заготовленный ответ."""
    def __init__(self, log, tag):
        self.log = log
        self.tag = tag
        self.handlers = []

    def open(self, req, timeout=None):
        self.log.append((self.tag, req.full_url, {k.lower(): v for k, v in req.header_items()}))
        body = b'<html><title>t</title><script src="/app.js"></script></html>'
        return urllib.response.addinfourl(io.BytesIO(body), Message(), req.full_url, 200)


@pytest.fixture()
def offline(monkeypatch):
    """Реальный SafeHTTP.get, но без сети, DNS и TLS-рукопожатий."""
    log: list[tuple[str, str, dict[str, str]]] = []
    real_init = SafeHTTP.__init__

    def init(self, *a, **kw):
        real_init(self, *a, **kw)
        self._opener = FakeOpener(log, "follow")
    monkeypatch.setattr(SafeHTTP, "__init__", init)
    monkeypatch.setattr(http_mod, "_NO_REDIRECT_OPENER", FakeOpener(log, "no-follow"))
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")

    def no_dns(host, *a, **kw):
        raise AssertionError(f"реальный DNS-запрос в тесте: {host}")
    monkeypatch.setattr(recon.socket, "gethostbyname_ex", no_dns)
    monkeypatch.setattr(web, "_tls_finding", lambda host, port=443: None)
    return log


class Store:
    def __init__(self):
        self.assets = {}

    def add_finding(self, f):
        pass

    def add_asset(self, a):
        self.assets[a.value] = a


@pytest.mark.parametrize("module,expected_min", [("recon", 1), ("web", 8), ("secrets", 2), ("webprobe", 3)])
def test_each_module_sends_default_header_on_all_requests(tmp_path, offline, module, expected_min):
    _write(tmp_path)
    scope = Scope.load(str(tmp_path / "scope.json"))
    client = _client(default_headers=DEFAULT, in_scope=scope.in_scope_target)
    target = ["http://example.com/login?next=/home"]
    if module == "recon":
        recon.run(scope, Store(), client, True, cname_resolver=None)
    elif module == "web":
        web.run(scope, Store(), client, True, target)
    elif module == "secrets":
        secrets.run(scope, Store(), client, True, target)
    else:
        webprobe.run(scope, Store(), client, True, target)
    assert len(offline) >= expected_min
    assert all(h.get(HDR.lower()) == WHO for _, _, h in offline)
    assert all(h["user-agent"] == UA for _, _, h in offline)


def test_web_cors_probe_keeps_default_header_next_to_origin(tmp_path, offline):
    _write(tmp_path)
    scope = Scope.load(str(tmp_path / "scope.json"))
    web.run(scope, Store(), _client(default_headers=DEFAULT), True, ["http://example.com/"])
    with_origin = [h for _, _, h in offline if "origin" in h]
    assert len(with_origin) == 2 and all(h[HDR.lower()] == WHO for h in with_origin)


def test_autopilot_passes_manifest_headers_to_every_module_request(tmp_path, offline):
    path = _write(tmp_path, {
        "modules": ["recon", "web", "secrets", "webprobe"],
        "policy": {"active_web_validation": True},
        "http_headers": DEFAULT,
    })
    autopilot.run(str(path), True)
    assert len(offline) > 10
    assert all(h.get(HDR.lower()) == WHO for _, _, h in offline), [u for _, u, h in offline if HDR.lower() not in h]
    urls = [u for _, u, _ in offline]
    assert "https://example.com" in urls                              # recon
    assert any(u.endswith(web.SOFT404_PROBE) for u in urls)           # web
    assert any(u.endswith("/app.js") for u in urls)                   # secrets
    assert any(tag == "no-follow" and "attacker.example" in u for tag, u, _ in offline)   # webprobe


def test_autopilot_without_http_headers_sends_none(tmp_path, offline):
    autopilot.run(str(_write(tmp_path, {"modules": ["web", "secrets"]})), True)
    assert offline and all(HDR.lower() not in h for _, _, h in offline)
    assert all(h["user-agent"] == UA for _, _, h in offline)
