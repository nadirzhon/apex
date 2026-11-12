"""Разведка: резолв и HTTP-fingerprint хостов ИЗ scope. Никакого брутфорса
чужого — работаем только с тем, что уже объявлено в scope программы."""
from __future__ import annotations

import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..http import SafeHTTP
from ..models import Asset, Finding
from ..scope import Scope
from ..store import Store

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

# Сигнатуры «неподтверждённого/висячего» сервиса: если хост из scope указывает
# (CNAME) на такой сервис, а сам сервис отдаёт «claim this / not found», поддомен
# можно захватить. Куратор-список по публичному can-i-take-over-xyz. Сам захват
# не выполняется — это обнаружение.
#
# Находка ПОДТВЕРЖДАЕТСЯ двумя независимыми признаками:
#   1) текстовый маркер сервиса в теле ответа;
#   2) CNAME-цепочка хоста ведёт на домен этого сервиса (``cname_suffixes``).
# Один только маркер — не доказательство: своя 404-страница хоста может содержать
# «Repository not found». Без совпадения CNAME:
#   - общий маркер (``error_only``) находку не даёт вовсе;
#   - уникальная фраза сервиса даёт находку НИЗКОЙ уверенности (severity low, не
#     ELIGIBLE) — на случай apex-домена с A-записью на сервис, где CNAME нет.
#
# ``error_only``: короткие/общие фразы («NoSuchBucket») встречаются и на живых
# страницах; для них дополнительно требуем статус ошибки (>= 400).
@dataclass(frozen=True)
class TakeoverFingerprint:
    marker: bytes
    cname_suffixes: tuple[str, ...]
    error_only: bool = False
    # если задано — одна из меток имени должна начинаться с этого префикса
    # (amazonaws.com общий для всего AWS; S3 — это метки s3 / s3-website-…)
    cname_label_prefix: str = ""

    def matches_cname(self, name: str) -> bool:
        n = name.strip().lower().rstrip(".")
        if not any(n == suf or n.endswith("." + suf) for suf in self.cname_suffixes):
            return False
        if self.cname_label_prefix:
            return any(label.startswith(self.cname_label_prefix) for label in n.split("."))
        return True


TAKEOVER_FINGERPRINTS: dict[str, TakeoverFingerprint] = {
    "GitHub Pages": TakeoverFingerprint(b"There isn't a GitHub Pages site here", ("github.io",)),
    "AWS S3": TakeoverFingerprint(b"NoSuchBucket", ("amazonaws.com",), error_only=True,
                                  cname_label_prefix="s3"),
    "Heroku": TakeoverFingerprint(b"herokucdn.com/error-pages/no-such-app.html",
                                  ("herokuapp.com", "herokudns.com", "herokussl.com")),
    "Fastly": TakeoverFingerprint(b"Fastly error: unknown domain", ("fastly.net", "fastlylb.net")),
    "Shopify": TakeoverFingerprint(b"Sorry, this shop is currently unavailable", ("myshopify.com",)),
    "Surge.sh": TakeoverFingerprint(b"project not found", ("surge.sh",), error_only=True),
    "Bitbucket": TakeoverFingerprint(b"Repository not found", ("bitbucket.io",), error_only=True),
    "Pantheon": TakeoverFingerprint(b"The gods are wise, but do not know of the site which you seek",
                                    ("pantheonsite.io",)),
    "Tilda": TakeoverFingerprint(b"Please renew your subscription", ("tilda.ws",), error_only=True),
    "Help Scout": TakeoverFingerprint(b"No settings were found for this company", ("helpscoutdocs.com",)),
    "Ghost": TakeoverFingerprint(b"The thing you were looking for is no longer here", ("ghost.io",)),
}

# Резолвер CNAME: хост → имена его CNAME-цепочки (без самого хоста). Вынесен за
# параметр, чтобы тесты подставляли заглушку и не делали DNS-запросов.
CnameResolver = Callable[[str], Iterable[str]]


def system_cname_resolver(host: str) -> list[str]:
    """CNAME-цепочка средствами stdlib: каноническое имя и алиасы из
    ``gethostbyname_ex``. Запрос идёт только по имени хоста, уже проверенного
    на scope (тот же резолв, что recon и так делает). Ошибка DNS → пустой список."""
    try:
        canonical, aliases, _ = socket.gethostbyname_ex(host)
    except OSError:
        return []
    own = host.strip().lower().rstrip(".")
    names = [n.strip().lower().rstrip(".") for n in (canonical, *aliases) if n]
    return [n for n in dict.fromkeys(names) if n != own]


def _resolve_cnames(host: str, resolver: CnameResolver | None) -> list[str] | None:
    """Имена CNAME-цепочки или None, если узнать нельзя (резолвер не задан или
    упал). Сбой резолвера никогда не роняет прогон — он лишь оставляет находку
    неподтверждённой."""
    if resolver is None:
        return None
    try:
        return [str(n).strip().lower().rstrip(".") for n in resolver(host) if n]
    except Exception:  # noqa: BLE001 — чужой резолвер может бросить что угодно
        return None


def _takeover_candidates(body: bytes, status: int) -> list[str]:
    """Сервисы, чей текстовый маркер есть в ответе (с учётом ``error_only``).
    Неизвестный статус (0) трактуется как «не ошибка»."""
    return [
        service for service, fp in TAKEOVER_FINGERPRINTS.items()
        if fp.marker in body and not (fp.error_only and status < 400)
    ]


def _takeover_finding(url: str, body: bytes, status: int = 0,
                      cnames: Iterable[str] | None = None) -> Finding | None:
    """Находка subdomain takeover по ответу хоста и его CNAME-цепочке.

    ``cnames`` — имена CNAME-цепочки хоста; ``None`` = неизвестно (резолвера нет).
    Маркер + CNAME на домен сервиса → подтверждённая находка (high/critical).
    Маркер без совпадения CNAME → для уникальной фразы находка низкой уверенности,
    для общего маркера — ничего."""
    candidates = _takeover_candidates(body, status)
    if not candidates:
        return None
    names = None if cnames is None else [str(n) for n in cnames]

    for service in candidates:
        fp = TAKEOVER_FINGERPRINTS[service]
        hit = next((n for n in names or [] if fp.matches_cname(n)), None)
        if hit:
            return Finding(
                title=f"Возможный subdomain takeover ({service})",
                severity="high", target=url, module="recon",
                description=f"Хост из scope указывает (CNAME) на сервис {service} и отдаёт "
                            f"его страницу неподтверждённого ресурса («claim this / not "
                            f"found»). Если на сервисе можно зарегистрировать этот ресурс — "
                            f"поддомен захватывается.",
                evidence=f"GET {url} → {status or '?'}, сигнатура {service}: "
                         f"{fp.marker.decode('utf-8', 'replace')!r}; CNAME → {hit}",
                remediation=f"Удалите висячую DNS-запись (CNAME) на {service} или заберите "
                            f"ресурс на своём аккаунте сервиса.",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            )

    for service in candidates:
        fp = TAKEOVER_FINGERPRINTS[service]
        if fp.error_only:
            continue  # общий маркер без CNAME — не находка
        if names is None:
            why = "CNAME не проверен (резолвер недоступен)"
        elif names:
            why = f"CNAME ({', '.join(names[:3])}) не ведёт на домен сервиса"
        else:
            why = "CNAME-записи нет (возможна A-запись на сервис)"
        return Finding(
            title=f"Сигнатура висячего сервиса {service} — CNAME не подтверждён",
            severity="low", target=url, module="recon",
            description=f"Ответ хоста содержит страницу неподтверждённого ресурса {service}, "
                        f"но связь хоста с сервисом по DNS не подтверждена. Это НЕ "
                        f"доказанный takeover — нужна ручная проверка DNS.",
            evidence=f"GET {url} → {status or '?'}, сигнатура {service}: "
                     f"{fp.marker.decode('utf-8', 'replace')!r}; {why}",
            remediation=f"Проверьте DNS-записи хоста (dig CNAME / A): если они ведут на "
                        f"{service}, удалите их или заберите ресурс на своём аккаунте.",
        )
    return None


def _hosts_from_scope(scope: Scope) -> list[str]:
    """Конкретные хосты из in_scope (wildcard разворачиваем в базовый домен)."""
    hosts = []
    for entry in scope.in_scope:
        if "." not in entry or " " in entry:
            continue
        if entry.startswith("*."):
            hosts.append(entry[2:])          # *.example.com → example.com
        elif "/" not in entry and not entry.count(".") == 0:
            hosts.append(entry)
    # отсечь мобильные пакеты (com.example.app тоже с точками) — грубая эвристика:
    return [h for h in dict.fromkeys(hosts) if not h.split(".")[-1].isalpha() or "." in h]


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
        cname_resolver: CnameResolver | None = system_cname_resolver) -> list[Finding]:
    """``cname_resolver`` подтверждает takeover по DNS; ``None`` отключает сверку
    (тогда возможны только находки низкой уверенности)."""
    scope.assert_ready(authorized)
    findings: list[Finding] = []

    for host in _hosts_from_scope(scope):
        if not scope.in_scope_target(host):
            continue
        # DNS
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            continue
        store.add_asset(Asset(kind="host", value=host, meta={"ip": ip}))

        # HTTP/HTTPS fingerprint
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            if not scope.in_scope_target(url):
                continue
            r = http.get(url)
            if r.status == 0:
                continue
            tf = None
            if _takeover_candidates(r.body, r.status):
                # DNS трогаем только когда маркер уже найден; хост проверен на scope
                tf = _takeover_finding(url, r.body, r.status,
                                       _resolve_cnames(host, cname_resolver))
            if tf:
                findings.append(tf)
                store.add_finding(tf)
            m = _TITLE.search(r.body)
            title = (m.group(1).decode("utf-8", "replace").strip()[:120] if m else "")
            store.add_asset(Asset(
                kind="url", value=url, source="recon",
                meta={
                    "status": r.status,
                    "server": r.headers.get("server", ""),
                    "powered_by": r.headers.get("x-powered-by", ""),
                    "title": title,
                },
            ))
            break  # хватит одной рабочей схемы на fingerprint

    return findings
