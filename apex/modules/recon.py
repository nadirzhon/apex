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
