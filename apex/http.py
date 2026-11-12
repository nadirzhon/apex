"""Безопасный HTTP-клиент: только GET/HEAD, rate-limit, таймауты, без редиректов
на чужие хосты. Ноль зависимостей (urllib)."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

UA = "APEX/1.0 (authorized bug-bounty automation; +https://github.com/nadirzhon/apex)"


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """Следовать 3xx ТОЛЬКО если цель редиректа остаётся в scope. Иначе не ходим
    по чужому Location (fail-closed): возвращаем сам 3xx-ответ вызывающему.

    Это закрывает обход scope-гейта: in-scope URL не может увести пробу на
    out-of-scope хост простым редиректом."""

    def __init__(self, in_scope: Callable[[str], bool]):
        super().__init__()
        self._in_scope = in_scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self._in_scope(newurl):
            return None  # вне scope — не следуем; opener вернёт 3xx-ответ
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Не следовать 3xx — вернуть сам ответ-редирект (нужно для детекта
    open-redirect и чтобы не ходить за цель по чужому Location).

    Возврат ``fp`` из http_error_30x заставляет opener вернуть сам 3xx-ответ
    с нетронутыми статусом и заголовками (включая Location)."""

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class SafeHTTP:
    """Дросселированный клиент. Все запросы идут через один инстанс, который
    держит rate-limit по программе (не долбит цель)."""

    def __init__(self, rate_limit_rps: float = 2.0, timeout: float = 10.0,
                 in_scope: Callable[[str], bool] | None = None):
        self.min_interval = 1.0 / max(rate_limit_rps, 0.1)
        self.timeout = timeout
        self._last = 0.0
        # Если задан предикат scope — редиректы проверяются на КАЖДОМ хопе, и за
        # out-of-scope Location клиент не ходит (fail-closed, см. _ScopedRedirect).
        self._scoped_opener = (
            urllib.request.build_opener(_ScopedRedirect(in_scope)) if in_scope else None
        )

    def _throttle(self) -> None:
        dt = time.monotonic() - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.monotonic()

    def get(self, url: str, method: str = "GET", max_bytes: int = 512_000,
            headers: dict[str, str] | None = None,
            allow_redirects: bool = True) -> Response:
        self._throttle()
        h = {"User-Agent": UA}
        if headers:
            h.update(headers)                 # сессии актёров (Cookie/Authorization)
        req = urllib.request.Request(url, method=method, headers=h)
        ctx = ssl.create_default_context()
        # Выбор opener:
        #  - allow_redirects=False → не следуем 3xx (open-redirect, SSRF-гигиена);
        #  - иначе есть scope-предикат → следуем, но только по in-scope Location;
        #  - иначе → обычное поведение urlopen.
        if not allow_redirects:
            opener = _NO_REDIRECT_OPENER.open
        elif self._scoped_opener is not None:
            opener = self._scoped_opener.open
        else:
            opener = None
        try:
            r = (opener(req, timeout=self.timeout)
                 if opener else urllib.request.urlopen(req, timeout=self.timeout, context=ctx))
            with r:
                body = r.read(max_bytes) if method == "GET" else b""
                return Response(
                    url=getattr(r, "url", None) or (r.geturl() if hasattr(r, "geturl") else url),
                    status=getattr(r, "status", None) or r.getcode(),
                    headers={k.lower(): v for k, v in r.headers.items()},
                    body=body,
                )
        except urllib.error.HTTPError as e:
            # Тело ошибки (4xx/5xx) читаем с тем же лимитом max_bytes: это ответ
            # того же уже проверенного хоста, новых запросов нет. Без него
            # детекторы по сигнатуре страницы ошибки (subdomain takeover = 404
            # «no such app/bucket») были слепы.
            err_body = b""
            if method == "GET":
                try:
                    err_body = e.read(max_bytes)
                except (OSError, ValueError, AttributeError):
                    err_body = b""
            return Response(
                url=url, status=e.code,
                headers={k.lower(): v for k, v in (e.headers or {}).items()},
                body=err_body, error=f"HTTP {e.code}",
            )
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ValueError) as e:
            return Response(url=url, status=0, headers={}, body=b"", error=str(e))
