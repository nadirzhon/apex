"""Разведка: резолв и HTTP-fingerprint хостов ИЗ scope. Никакого брутфорса
чужого — работаем только с тем, что уже объявлено в scope программы."""
from __future__ import annotations

import re
import socket

from ..http import SafeHTTP
from ..models import Asset, Finding
from ..scope import Scope
from ..store import Store

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

# Сигнатуры «неподтверждённого/висячего» сервиса в теле ответа: если хост из scope
# указывает (CNAME) на такой сервис, а сам сервис отдаёт «claim this / not found»,
# поддомен можно захватить. Куратор-список по публичному can-i-take-over-xyz.
# Детект — ТОЛЬКО по характерной сигнатуре (минимум ложных срабатываний); сам
# захват не выполняется — это обнаружение.
TAKEOVER_FINGERPRINTS: dict[str, bytes] = {
    "GitHub Pages": b"There isn't a GitHub Pages site here",
    "AWS S3": b"NoSuchBucket",
    "Heroku": b"herokucdn.com/error-pages/no-such-app.html",
    "Fastly": b"Fastly error: unknown domain",
    "Shopify": b"Sorry, this shop is currently unavailable",
    "Surge.sh": b"project not found",
    "Bitbucket": b"Repository not found",
    "Pantheon": b"The gods are wise, but do not know of the site which you seek",
    "Tilda": b"Please renew your subscription",
    "Help Scout": b"No settings were found for this company",
    "Ghost": b"The thing you were looking for is no longer here",
}


def _takeover_finding(url: str, body: bytes) -> Finding | None:
    """Вернуть находку, если тело ответа соответствует сигнатуре висячего сервиса."""
    for service, marker in TAKEOVER_FINGERPRINTS.items():
        if marker in body:
            return Finding(
                title=f"Возможный subdomain takeover ({service})",
                severity="high", target=url, module="recon",
                description=f"Хост из scope отдаёт страницу неподтверждённого сервиса "
                            f"{service} («claim this / not found»). Если на сервисе можно "
                            f"зарегистрировать этот ресурс — поддомен захватывается.",
                evidence=f"GET {url} → сигнатура {service}: {marker.decode('utf-8', 'replace')!r}",
                remediation=f"Удалите висячую DNS-запись (CNAME) на {service} или заберите "
                            f"ресурс на своём аккаунте сервиса.",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
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


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool) -> list[Finding]:
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
            tf = _takeover_finding(url, r.body)
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
