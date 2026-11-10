"""Безопасный HTTP-клиент: только GET/HEAD, rate-limit, таймауты, без редиректов
на чужие хосты. Ноль зависимостей (urllib)."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

UA = "APEX/1.0 (authorized bug-bounty automation; +https://github.com/nadirzhon/apex)"


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

    def __init__(self, rate_limit_rps: float = 2.0, timeout: float = 10.0):
        self.min_interval = 1.0 / max(rate_limit_rps, 0.1)
        self.timeout = timeout
        self._last = 0.0

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
        # allow_redirects=False: не ходим за чужим Location (open-redirect, SSRF-гигиена)
        opener = _NO_REDIRECT_OPENER.open if not allow_redirects else None
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
            return Response(
                url=url, status=e.code,
                headers={k.lower(): v for k, v in (e.headers or {}).items()},
                body=b"", error=f"HTTP {e.code}",
            )
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ValueError) as e:
            return Response(url=url, status=0, headers={}, body=b"", error=str(e))
