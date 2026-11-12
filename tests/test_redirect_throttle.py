"""Лимит запросов на хопах редиректа: каждый хоп — настоящий запрос к цели и
обязан пройти через тот же throttle SafeHTTP, что и первый запрос.

Офлайн: loopback-сервер; время подменяется фейковыми часами там, где важна
точная арифметика лимита."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from apex import http as http_mod
from apex.http import SafeHTTP


class _Srv(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.hits: list[tuple[float, str, str]] = []      # (время, Host, путь)


class _H(BaseHTTPRequestHandler):
    def _go(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.server.hits.append((time.monotonic(), self.headers.get("Host", ""), self.path))
        port = self.server.server_port
        if self.path.startswith("/chain/"):
            n = int(self.path.rsplit("/", 1)[1])
            if n > 0:
                return self._go(f"/chain/{n - 1}")
        elif self.path == "/cross":
            # тот же сервер под другим именем хоста: 127.0.0.1 → localhost
            return self._go(f"http://localhost:{port}/chain/0")
        elif self.path == "/cross-chain":
            return self._go(f"http://localhost:{port}/chain/2")
        elif self.path == "/loop":
            return self._go("/loop")
        elif self.path == "/out":
            return self._go("/forbidden")
        body = b"final"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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


def _count_throttle(client: SafeHTTP) -> list[int]:
    """Обернуть настоящий throttle счётчиком. Хук редиректа держит ссылку на
    bound-метод, поэтому подменяем функцию на уровне экземпляра через opener."""
    calls: list[int] = []
    real = SafeHTTP._throttle

    def counted(self=client):
        calls.append(1)
        real(self)
    client._throttle = counted                       # первый запрос (get → self._throttle)
    for h in client._opener.handlers:                # хопы редиректа
        if isinstance(h, http_mod._ScopedRedirect):
            h._before_hop = counted
    return calls


class FakeClock:
    """Подмена модуля time в apex.http: sleep не ждёт, а двигает часы."""
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture()
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(http_mod, "time", c)
    return c


# ---- N редиректов = N соблюдений лимита ------------------------------------
@pytest.mark.parametrize("hops", [0, 1, 3, 5])
def test_every_redirect_hop_goes_through_throttle(srv, hops):
    client = SafeHTTP(rate_limit_rps=1000)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + f"/chain/{hops}")
    assert r.status == 200 and r.body == b"final"
    assert len(srv.hits) == hops + 1                 # столько запросов реально ушло
    assert len(calls) == hops + 1                    # и столько же раз соблюдён лимит


@pytest.mark.parametrize("hops", [1, 3])
def test_each_hop_waits_a_full_interval(srv, clock, hops):
    """Арифметика лимита без реального ожидания: 1 rps → 1 с перед каждым хопом."""
    client = SafeHTTP(rate_limit_rps=1)
    r = client.get(_base(srv) + f"/chain/{hops}")
    assert r.status == 200
    # первый запрос идёт сразу, каждый хоп ждёт полный интервал
    assert clock.sleeps == [pytest.approx(1.0)] * hops


def test_hops_are_spaced_in_real_time(srv):
    """Тот же факт глазами сервера: между хопами проходит не меньше интервала."""
    client = SafeHTTP(rate_limit_rps=20)             # интервал 50 мс
    r = client.get(_base(srv) + "/chain/3")
    assert r.status == 200 and len(srv.hits) == 4
    stamps = [t for t, _, _ in srv.hits]
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    assert all(g >= 0.04 for g in gaps), gaps        # без throttle было бы ~1 мс


def test_request_after_redirect_chain_still_waits(srv, clock):
    client = SafeHTTP(rate_limit_rps=1)
    client.get(_base(srv) + "/chain/2")
    client.get(_base(srv) + "/chain/0")
    assert clock.sleeps == [pytest.approx(1.0)] * 3  # 2 хопа + следующий запрос


# ---- редирект на другой хост ------------------------------------------------
def test_cross_host_hop_is_throttled(srv, clock):
    client = SafeHTTP(rate_limit_rps=1)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/cross")
    assert r.status == 200
    hosts = [h.split(":")[0] for _, h, _ in srv.hits]
    assert hosts == ["127.0.0.1", "localhost"]       # хоп действительно ушёл на другой хост
    assert len(calls) == 2
    assert clock.sleeps == [pytest.approx(1.0)]      # новый хост не получает запрос «вне очереди»


def test_chain_on_new_host_keeps_limit_for_that_host(srv, clock):
    client = SafeHTTP(rate_limit_rps=2)              # интервал 0.5 с
    r = client.get(_base(srv) + "/cross-chain")
    assert r.status == 200
    hosts = [h.split(":")[0] for _, h, _ in srv.hits]
    assert hosts == ["127.0.0.1", "localhost", "localhost", "localhost"]
    assert clock.sleeps == [pytest.approx(0.5)] * 3  # каждый хоп на новом хосте — в лимите


# ---- scope и throttle вместе ------------------------------------------------
def test_in_scope_chain_is_checked_and_throttled_per_hop(srv):
    checked: list[str] = []

    def in_scope(url):
        checked.append(url)
        return True
    client = SafeHTTP(rate_limit_rps=1000, in_scope=in_scope)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/chain/3")
    assert r.status == 200
    assert len(checked) == 3                         # scope проверен на каждом хопе
    assert len(calls) == 4 and len(srv.hits) == 4


def test_out_of_scope_hop_is_not_followed_and_not_throttled(srv, clock):
    client = SafeHTTP(rate_limit_rps=1, in_scope=lambda u: "/forbidden" not in u)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/out")
    assert r.status == 302 and r.body != b"final"
    assert [p for _, _, p in srv.hits] == ["/out"]   # за запрещённым Location не пошли
    assert len(calls) == 1 and clock.sleeps == []    # и слот лимита на него не тратили


def test_cross_host_hop_blocked_by_scope(srv):
    client = SafeHTTP(rate_limit_rps=1000, in_scope=lambda u: "localhost" not in u)
    r = client.get(_base(srv) + "/cross")
    assert r.status == 302
    assert [h.split(":")[0] for _, h, _ in srv.hits] == ["127.0.0.1"]


def test_no_redirect_mode_makes_exactly_one_throttled_request(srv):
    client = SafeHTTP(rate_limit_rps=1000)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/chain/3", allow_redirects=False)
    assert r.status == 302 and r.headers["location"] == "/chain/2"
    assert len(calls) == 1 and len(srv.hits) == 1


def test_head_redirect_hops_are_throttled(srv):
    client = SafeHTTP(rate_limit_rps=1000)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/chain/2", method="HEAD")
    assert r.status == 200 and r.body == b""
    assert len(calls) == 3 and len(srv.hits) == 3


def test_redirect_loop_is_bounded_and_fully_throttled(srv):
    client = SafeHTTP(rate_limit_rps=1000)
    calls = _count_throttle(client)
    r = client.get(_base(srv) + "/loop")
    assert r.status in (302, 0)                      # urllib обрывает петлю, клиент не падает
    assert 1 < len(srv.hits) <= 11
    # ни одного запроса мимо лимита; urllib замечает петлю уже после хука хопа,
    # поэтому один слот может быть потрачен на хоп, который так и не ушёл (строже)
    assert len(srv.hits) <= len(calls) <= len(srv.hits) + 1


def test_rate_limit_floor_is_preserved():
    assert SafeHTTP(rate_limit_rps=0).min_interval == pytest.approx(10.0)
    assert SafeHTTP(rate_limit_rps=4).min_interval == pytest.approx(0.25)
