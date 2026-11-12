"""Безопасный HTTP-клиент: только GET/HEAD, rate-limit, таймауты, без редиректов
на чужие хосты. Ноль зависимостей (urllib)."""
from __future__ import annotations

import http.client
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

UA = "APEX/1.0 (authorized bug-bounty automation; +https://github.com/nadirzhon/apex)"


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """Следовать 3xx ТОЛЬКО если цель редиректа остаётся в scope, и каждый хоп
    проводить через тот же ограничитель скорости, что и обычные запросы.

    - Вне scope — не ходим по чужому Location (fail-closed): вызывающему
      возвращается сам 3xx-ответ. In-scope URL не может увести пробу на
      out-of-scope хост простым редиректом.
    - Хоп редиректа — это настоящий запрос к цели, поэтому перед ним вызывается
      ``before_hop`` (throttle клиента). Без этого цепочка из N редиректов давала
      N запросов подряд мимо rate_limit_rps."""

    def __init__(self, in_scope: Callable[[str], bool] | None = None,
                 before_hop: Callable[[], None] | None = None):
        super().__init__()
        self._in_scope = in_scope
        self._before_hop = before_hop

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self._in_scope is not None and not self._in_scope(newurl):
            return None  # вне scope — не следуем; opener вернёт 3xx-ответ
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and self._before_hop is not None:
            self._before_hop()  # ждём слот лимита только перед реально уходящим хопом
        return new


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Не следовать 3xx — вернуть сам ответ-редирект (нужно для детекта
    open-redirect и чтобы не ходить за цель по чужому Location).

    Возврат ``fp`` из http_error_30x заставляет opener вернуть сам 3xx-ответ
    с нетронутыми статусом и заголовками (включая Location)."""

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _merge_headers(*layers: dict[str, str]) -> dict[str, str]:
    """Слить слои заголовков; имена регистронезависимы, поздний слой побеждает."""
    merged: dict[str, tuple[str, str]] = {}
    for layer in layers:
        for name, value in layer.items():
            merged[name.lower()] = (name, value)
    return dict(merged.values())


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
    держит rate-limit по программе (не долбит цель).

    Лимит один на клиент и общий для всех хостов: между ЛЮБЫМИ двумя исходящими
    запросами — включая каждый хоп редиректа и хоп на другой хост — проходит не
    меньше ``1 / rate_limit_rps`` секунд. Это строже лимита «на хост»: ни один
    хост не получает запросы чаще, чем разрешено scope."""

    def __init__(self, rate_limit_rps: float = 2.0, timeout: float = 10.0,
                 in_scope: Callable[[str], bool] | None = None,
                 default_headers: dict[str, str] | None = None):
        self.min_interval = 1.0 / max(rate_limit_rps, 0.1)
        self.timeout = timeout
        # Заголовки, которые уходят на КАЖДОМ запросе клиента, включая хопы
        # редиректа (urllib переносит заголовки запроса на следующий хоп).
        # Нужны программам, которые обязывают помечать тестовый трафик, например
        # ``X-HackerOne-Research: <username>``. Копия — чтобы внешний dict нельзя
        # было поменять после создания клиента.
        self.default_headers: dict[str, str] = dict(default_headers or {})
        self._last = 0.0
        # Один opener на клиент: каждый хоп редиректа проходит через _throttle, а
        # если задан предикат scope — ещё и проверяется на scope; за out-of-scope
        # Location клиент не ходит (fail-closed, см. _ScopedRedirect).
        self._opener = urllib.request.build_opener(
            _ScopedRedirect(in_scope, self._throttle),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
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
        # Порядок: User-Agent → default_headers клиента → заголовки вызова.
        # Имена сравниваются без учёта регистра, более поздний слой побеждает.
        h = _merge_headers({"User-Agent": UA}, self.default_headers, headers or {})
        req = urllib.request.Request(url, method=method, headers=h)
        # allow_redirects=False → не следуем 3xx вовсе (open-redirect, SSRF-гигиена);
        # иначе следуем через opener клиента: throttle (и scope) на каждом хопе.
        opener = self._opener if allow_redirects else _NO_REDIRECT_OPENER
        try:
            r = opener.open(req, timeout=self.timeout)
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
                except (OSError, http.client.HTTPException, ValueError, AttributeError):
                    err_body = b""
            return Response(
                url=url, status=e.code,
                headers={k.lower(): v for k, v in (e.headers or {}).items()},
                body=err_body, error=f"HTTP {e.code}",
            )
        except (OSError, http.client.HTTPException, ValueError) as e:
            # Любой сбой уровня соединения/чтения — на первом запросе или на хопе
            # редиректа — это «хост не ответил» (status=0), а не падение прогона:
            #  - OSError: URLError, ConnectionError (reset/refused/aborted/broken
            #    pipe), TimeoutError/socket.timeout, ssl.SSLError, socket.gaierror;
            #  - http.client.HTTPException: RemoteDisconnected, BadStatusLine,
            #    IncompleteRead, LineTooLong и прочие нарушения протокола;
            #  - ValueError: некорректный URL.
            # Один недоступный или капризный хост не должен ронять весь engagement.
            return Response(url=url, status=0, headers={}, body=b"",
                            error=str(e) or type(e).__name__)
