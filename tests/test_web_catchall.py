"""Regression tests: exposed-file check must not fire on soft-404 / SPA catch-all.

Контекст: на 1win.com сайты — SPA, отдающие index.html (200) на ЛЮБОЙ путь.
Старый код помечал /actuator/health, /.well-known/security.txt и т.п. как
«экспонированные» по одному лишь статусу 200 → ложные находки. Проверяем, что
базовая линия soft-404 и усиленные маркеры это гасят, но реальный файл ловится."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from apex.modules import web
from apex.modules.web import _is_real_exposure
from apex.scope import Scope


class FakeResp:
    def __init__(self, status: int, body: bytes = b"", ctype: str = "text/html"):
        self.status = status
        self.body = body
        self.headers = {"content-type": ctype}


class FakeHTTP:
    """Отдаёт заданные ответы по path, а на всё прочее — default (soft-404/SPA)."""
    def __init__(self, routes: dict[str, FakeResp], default: FakeResp):
        self.routes = routes
        self.default = default

    def get(self, url: str, **_kw) -> FakeResp:
        path = urlparse(url).path or "/"
        return self.routes.get(path, self.default)


class FakeStore:
    assets: dict = {}

    def __init__(self):
        self.added = []

    def add_finding(self, f):
        self.added.append(f)


def _scope(tmp_path: Path) -> Scope:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program": "catchall-test",
        "authorized": True,
        "researcher": "ci",
        "rate_limit_rps": 5,
        "in_scope": ["example.com", "*.example.com"],
        "out_of_scope": [],
        "rules": "test",
    }))
    return Scope.load(str(p))


# ---- unit: _is_real_exposure ------------------------------------------------

SPA = FakeResp(200, b"<html><body>status Contact = foo</body></html>", "text/html")


def test_catchall_weak_marker_in_baseline_rejected():
    # маркер есть и в пробе, и в общей оболочке → не доказательство
    assert _is_real_exposure(SPA, SPA, b"=") is False


def test_catchall_marker_absent_rejected():
    # '"status"' (JSON) нет в HTML-оболочке
    assert _is_real_exposure(SPA, SPA, b'"status"') is False


def test_real_file_on_non_catchall_accepted():
    baseline404 = FakeResp(404, b"not found")
    git = FakeResp(200, b"ref: refs/heads/main", "text/plain")
    assert _is_real_exposure(git, baseline404, b"ref:") is True


def test_real_file_on_catchall_distinct_body_accepted():
    # сайт catch-all, но реальный файл несёт маркер, которого нет в оболочке
    env = FakeResp(200, b"SECRET_KEY=abc123", "text/plain")
    assert _is_real_exposure(env, SPA, b"SECRET_KEY") is True


def test_empty_marker_catchall_same_html_rejected():
    assert _is_real_exposure(SPA, SPA, b"") is False


def test_non_200_rejected():
    assert _is_real_exposure(FakeResp(404), FakeResp(404), b"ref:") is False


# ---- integration: web.run ---------------------------------------------------

def _exposed_titles(findings):
    return [f.title for f in findings if f.title.startswith("Экспонирован")]


def test_run_spa_catchall_yields_no_exposed_findings(tmp_path):
    """SPA отдаёт 200 html на любой путь → ни одной exposed-находки."""
    home = FakeResp(200, b"<html>app status Contact</html>", "text/html")
    http = FakeHTTP(routes={"/": home}, default=SPA)
    out = web.run(_scope(tmp_path), FakeStore(), http, True, ["http://example.com"])
    assert _exposed_titles(out) == []


def test_run_real_git_exposure_detected(tmp_path):
    """Не-catch-all сайт с реально открытым /.git/HEAD → находка есть."""
    default404 = FakeResp(404, b"nope")
    routes = {
        "/": FakeResp(200, b"<html>home</html>"),
        "/.git/HEAD": FakeResp(200, b"ref: refs/heads/main", "text/plain"),
    }
    http = FakeHTTP(routes=routes, default=default404)
    out = web.run(_scope(tmp_path), FakeStore(), http, True, ["http://example.com"])
    assert "Экспонирован /.git/HEAD" in _exposed_titles(out)
