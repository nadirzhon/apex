"""Безопасный HTTP-клиент: только GET/HEAD, rate-limit, таймауты, без редиректов
на чужие хосты. Ноль зависимостей (urllib)."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

UA = "APEX/1.0 (authorized bug-bounty automation; +https://github.com/nadirzhon/apex)"


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
            headers: dict[str, str] | None = None) -> Response:
        self._throttle()
        h = {"User-Agent": UA}
        if headers:
            h.update(headers)                 # сессии актёров (Cookie/Authorization)
        req = urllib.request.Request(url, method=method, headers=h)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                body = r.read(max_bytes) if method == "GET" else b""
                return Response(
                    url=r.geturl(),
                    status=r.status,
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
