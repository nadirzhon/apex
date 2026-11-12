"""Устойчивость SafeHTTP.get к сбоям уровня соединения и чтения: капризный хост
даёт Response(status=0, error=...), а не исключение, роняющее весь прогон.

Офлайн: «сырой» TCP-сервер на loopback, который ломает соединение разными
способами, и подменённый opener для перечисления типов исключений."""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import struct
import threading
import urllib.error

import pytest

from apex import http as http_mod
from apex.http import Response, SafeHTTP
from apex.modules import recon, web
from apex.scope import Scope


# ---- сырой сервер: поведение выбирается по пути запроса ---------------------
class RawServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.paths: list[str] = []
        self._held: list[socket.socket] = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            path = data.split(b" ")[1].decode() if data.count(b" ") >= 2 else ""
            self.paths.append(path)
            if path == "/close":                       # закрыть без ответа → RemoteDisconnected
                pass
            elif path == "/reset":                     # RST вместо FIN → ConnectionResetError
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif path == "/hang":                      # принять и молчать → таймаут
                self._held.append(conn)
                return
            elif path == "/garbage":                   # не HTTP → BadStatusLine
                conn.sendall(b"this is not http\r\n\r\n")
            elif path == "/short":                     # обещано 100 байт, пришло 5, соединение закрыто
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
            elif path == "/short404":                  # то же в теле ответа-ошибки
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 100\r\n\r\nshort")
            elif path == "/hang-body":                 # заголовки есть, тело не приходит
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                self._held.append(conn)
                return
            elif path.startswith("/to/"):              # редирект на «плохой» путь
                target = "/" + path[len("/to/"):]
                conn.sendall(f"HTTP/1.1 302 Found\r\nLocation: {target}\r\n"
                             f"Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
            elif path == "/to-closed-port":
                conn.sendall(f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{_free_port()}/x\r\n"
                             f"Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
            else:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            if conn not in self._held:
                conn.close()

    def stop(self):
        self._stop = True
        self.sock.close()
        for c in self._held:
            c.close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def raw():
    server = RawServer()
    try:
        yield server
    finally:
        server.stop()


def _client(**kw) -> SafeHTTP:
    return SafeHTTP(rate_limit_rps=1000, **{"timeout": 0.3, **kw})


def _assert_failed(r: Response, url: str):
    assert isinstance(r, Response)
    assert r.status == 0
    assert r.error and r.body == b"" and r.headers == {} and r.url == url


# ---- реальные сбои соединения на loopback -----------------------------------
def test_connection_closed_without_response(raw):
    """Регрессия: RemoteDisconnected ронял весь engagement из recon.run."""
    url = raw.base + "/close"
    r = _client().get(url)
    _assert_failed(r, url)
    assert "closed connection" in r.error.lower()


@pytest.mark.parametrize("path", ["/close", "/reset", "/hang", "/garbage", "/hang-body"])
@pytest.mark.parametrize("mode", ["follow", "no-follow", "scoped", "head"])
def test_broken_host_returns_status_zero_in_every_mode(raw, path, mode):
    if mode == "head" and path == "/hang-body":
        pytest.skip("HEAD не читает тело — обрыв тела не наблюдается")
    url = raw.base + path
    client = _client(in_scope=(lambda u: True) if mode == "scoped" else None)
    r = client.get(url, allow_redirects=mode != "no-follow", method="HEAD" if mode == "head" else "GET")
    _assert_failed(r, url)


def test_connection_refused(raw):
    url = f"http://127.0.0.1:{_free_port()}/"
    _assert_failed(_client().get(url), url)


def test_truncated_body_returns_what_arrived(raw):
    """Соединение оборвано посреди тела: без исключения, отдаём полученную часть."""
    r = _client().get(raw.base + "/short")
    assert r.status == 200 and r.body == b"short"


def test_truncated_error_body_keeps_status(raw):
    r = _client().get(raw.base + "/short404")
    assert r.status == 404 and r.error == "HTTP 404"        # статус известен, тело просто не дочитано


# ---- сбой на хопе редиректа -------------------------------------------------
@pytest.mark.parametrize("bad", ["close", "reset", "hang", "garbage", "hang-body"])
@pytest.mark.parametrize("scoped", [False, True])
def test_failure_on_redirect_hop_does_not_raise(raw, bad, scoped):
    url = raw.base + f"/to/{bad}"
    r = _client(in_scope=(lambda u: True) if scoped else None).get(url)
    _assert_failed(r, url)
    assert raw.paths == [f"/to/{bad}", f"/{bad}"]            # хоп действительно был сделан


def test_redirect_to_closed_port_does_not_raise(raw):
    url = raw.base + "/to-closed-port"
    _assert_failed(_client().get(url), url)


# ---- успешный путь не задет -------------------------------------------------
def test_success_and_redirect_still_work(raw):
    client = _client()
    ok = client.get(raw.base + "/fine")
    assert ok.status == 200 and ok.body == b"ok" and not ok.error
    followed = client.get(raw.base + "/to/fine")
    assert followed.status == 200 and followed.body == b"ok"
    assert followed.url == raw.base + "/fine"
    raw302 = client.get(raw.base + "/to/fine", allow_redirects=False)
    assert raw302.status == 302 and raw302.headers["location"] == "/fine"


def test_client_recovers_after_a_broken_host(raw):
    client = _client()
    assert client.get(raw.base + "/close").status == 0
    assert client.get(raw.base + "/fine").status == 200
    assert client.get(raw.base + "/reset").status == 0
    assert client.get(raw.base + "/fine").status == 200


def test_out_of_scope_hop_still_blocked(raw):
    r = _client(in_scope=lambda u: "/fine" not in u).get(raw.base + "/to/fine")
    assert r.status == 302 and raw.paths == ["/to/fine"]


# ---- перечень типов исключений (подменённый opener, без сети) ---------------
class Raising:
    handlers: list = []

    def __init__(self, exc):
        self.exc = exc

    def open(self, req, timeout=None):
        raise self.exc


class BadBody:
    """Ответ пришёл, но чтение тела падает."""
    status = 200
    url = "http://example.com/"
    headers: dict = {}

    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=None):
        raise self.exc


NETWORK_ERRORS = [
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    http.client.BadStatusLine("garbage"),
    http.client.IncompleteRead(b"par", 97),
    http.client.LineTooLong("header line"),
    http.client.CannotSendRequest(),
    http.client.ResponseNotReady(),
    http.client.HTTPException("generic"),
    ConnectionResetError(54, "Connection reset by peer"),
    ConnectionAbortedError(53, "Software caused connection abort"),
    ConnectionRefusedError(61, "Connection refused"),
    BrokenPipeError(32, "Broken pipe"),
    ConnectionError("generic connection error"),
    TimeoutError(),
    TimeoutError("timed out"),
    socket.timeout("timed out"),  # noqa: UP041 — алиас проверяем явно
    socket.gaierror(8, "nodename nor servname provided"),
    ssl.SSLError("handshake failure"),
    ssl.SSLCertVerificationError("certificate verify failed"),
    OSError(65, "No route to host"),
    urllib.error.URLError("unreachable"),
    ValueError("unknown url type"),
]


@pytest.mark.parametrize("exc", NETWORK_ERRORS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("phase", ["connect", "read"])
def test_network_error_types_become_status_zero(exc, phase):
    client = _client()
    if phase == "connect":
        client._opener = Raising(exc)
    else:
        class Ok:
            handlers: list = []

            def open(self, req, timeout=None):
                return BadBody(exc)
        client._opener = Ok()
    r = client.get("http://example.com/")
    _assert_failed(r, "http://example.com/")


@pytest.mark.parametrize("exc", NETWORK_ERRORS[:6], ids=lambda e: type(e).__name__)
def test_network_error_types_in_no_follow_mode(monkeypatch, exc):
    monkeypatch.setattr(http_mod, "_NO_REDIRECT_OPENER", Raising(exc))
    _assert_failed(_client().get("http://example.com/", allow_redirects=False), "http://example.com/")


def test_empty_exception_message_still_gives_error_text():
    client = _client()
    client._opener = Raising(TimeoutError())
    assert client.get("http://example.com/").error == "TimeoutError"


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), RuntimeError("bug"), AssertionError("bug")],
                         ids=lambda e: type(e).__name__)
def test_non_network_errors_are_not_swallowed(exc):
    """Ловим только сеть: прерывание оператором и ошибки программы не маскируются."""
    client = _client()
    client._opener = Raising(exc)
    with pytest.raises(type(exc)):
        client.get("http://example.com/")


# ---- модули переживают капризный хост --------------------------------------
class Store:
    def __init__(self):
        self.assets = {}
        self.findings = []

    def add_finding(self, f):
        self.findings.append(f)

    def add_asset(self, a):
        self.assets[a.value] = a


def _scope(tmp_path) -> Scope:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program": "resilience", "authorized": True, "researcher": "ci", "rate_limit_rps": 1000,
        "in_scope": ["dead.example.com", "example.com"], "out_of_scope": [], "rules": "test",
    }))
    return Scope.load(str(p))


def test_recon_run_survives_remote_disconnect(tmp_path, monkeypatch):
    """Точный сценарий из реального прогона: recon.run → http.get → RemoteDisconnected."""
    monkeypatch.setattr(recon.socket, "gethostbyname", lambda h: "127.0.0.1")
    client = _client()
    client._opener = Raising(http.client.RemoteDisconnected("Remote end closed connection without response"))
    store = Store()
    assert recon.run(_scope(tmp_path), store, client, True, cname_resolver=None) == []
    assert [a.kind for a in store.assets.values()] == ["host", "host"]   # хосты учтены, URL-ассетов нет


def test_web_run_survives_connection_reset(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "_tls_finding", lambda host, port=443: None)
    client = _client()
    client._opener = Raising(ConnectionResetError(54, "Connection reset by peer"))
    assert web.run(_scope(tmp_path), Store(), client, True, ["http://example.com/"]) == []
