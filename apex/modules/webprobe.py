"""Активные, но неразрушающие проверки высокооплачиваемых веб-классов, которые
не ловятся пассивно: сейчас — open redirect.

АКТИВНЫЙ модуль: подменяет значение redirect-параметра на свой безобидный
canary-URL и смотрит, НЕ УВОДИТ ли сервер (3xx Location) на чужой хост. Сам
редирект НЕ выполняется (allow_redirects=False), состояние не меняется, данные
не трогаются. Работает только внутри scope и с --i-am-authorized (fail-closed).

Консервативность против ложных срабатываний: параметры НЕ угадываются вслепую —
проверяются только уже присутствующие в URL параметры с «редиректным» именем.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..http import SafeHTTP
from ..models import Finding
from ..scope import Scope
from ..store import Store

# Имена параметров, которые обычно задают цель редиректа.
REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "redir", "return",
    "returnurl", "return_url", "returnto", "return_to", "dest", "destination",
    "continue", "goto", "go", "target", "to", "rurl", "forward", "callback",
    "checkout_url", "image_url", "out", "view", "login_redirect", "r", "u",
}

_CANARY_HOST = "apex-redirect-canary.attacker.example"
# Несколько форм обхода наивных фильтров — все ведут на наш безобидный canary-хост.
_CANARY_PAYLOADS = (
    f"https://{_CANARY_HOST}/",
    f"//{_CANARY_HOST}/",
    f"https:/{_CANARY_HOST}/",            # пропущенный слэш — частый обход
)

_3XX = {301, 302, 303, 307, 308}


def _location_host(location: str) -> str:
    """Хост цели редиректа. Нормализует протокол-относительные и «кривые» формы."""
    loc = location.strip()
    if loc.startswith("//"):
        loc = "https:" + loc
    elif loc.startswith("https:/") and not loc.startswith("https://"):
        loc = "https://" + loc[len("https:/"):]
    elif loc.startswith("http:/") and not loc.startswith("http://"):
        loc = "http://" + loc[len("http:/"):]
    return (urlparse(loc).hostname or "").lower()


def _check_url(url: str, http: SafeHTTP) -> list[Finding]:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redirect_keys = [k for k, _ in pairs if k.lower() in REDIRECT_PARAMS]
    if not redirect_keys:
        return []

    out: list[Finding] = []
    seen: set[str] = set()
    for key in redirect_keys:
        if key in seen:
            continue
        seen.add(key)
        for payload in _CANARY_PAYLOADS:
            mutated = [(k, payload if k == key else v) for k, v in pairs]
            probe = urlunparse(parsed._replace(query=urlencode(mutated)))
            r = http.get(probe, allow_redirects=False)
            if r.status in _3XX and _location_host(r.headers.get("location", "")) == _CANARY_HOST:
                out.append(Finding(
                    title=f"Open redirect: параметр {key}",
                    severity="medium", target=url, module="webprobe",
                    description="Сервер формирует 3xx-редирект на хост, полностью заданный "
                                "значением параметра — классический open redirect. Impact "
                                "доказывается в связке (фишинг/кража OAuth-токена/обход SSRF-фильтра).",
                    evidence=f"GET {probe} → {r.status} Location: "
                             f"{r.headers.get('location', '')[:200]}",
                    remediation="Редиректь только на относительные пути или allowlist хостов; "
                                "не доверяй значению параметра напрямую.",
                    cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                ))
                break  # параметр подтверждён — остальные payload'ы не нужны
    return out


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
        targets: list[str] | None = None, **_: object) -> list[Finding]:
    """Активно проверить цели на open redirect. targets обязателен — вслепую по
    угаданным URL активные проверки не шлём."""
    scope.assert_ready(authorized)
    if not targets:
        raise ValueError("webprobe требует явные --target (активная проверка).")

    findings: list[Finding] = []
    for url in targets:
        scope.guard(url)  # fail-closed: активные пробы — только по in-scope
        findings.extend(_check_url(url, http))

    for f in findings:
        store.add_finding(f)
    return findings
