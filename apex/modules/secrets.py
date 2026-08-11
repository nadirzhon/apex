"""Поиск утёкших секретов в веб-контенте (страница + связанные .js).
Только чтение (GET), внутри scope. Ключи в отчёте маскируются."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..http import SafeHTTP
from ..models import Finding
from ..scope import Scope
from ..store import Store

# name → (regex, severity, cvss)
PATTERNS = {
    "AWS Access Key ID": (re.compile(r"AKIA[0-9A-Z]{16}"), "high",
                          "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "AWS Secret Key": (re.compile(r"(?i)aws_secret[^\n]{0,20}[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
                       "critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Google API Key": (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "medium",
                       "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Slack Token": (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "high",
                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "Private Key Block": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                          "critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "JWT": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            "low", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Stripe Live Key": (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "critical",
                        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Google OAuth Client Secret": (re.compile(r"GOCSPX-[0-9A-Za-z_-]{28}"), "high",
                                   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
}

_SCRIPT = re.compile(rb"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)


def _mask(s: str) -> str:
    return s[:6] + "…" + s[-4:] if len(s) > 12 else s[:2] + "…"


def _scan_text(text: str, source: str) -> list[Finding]:
    out = []
    for name, (rx, sev, vec) in PATTERNS.items():
        for m in rx.finditer(text):
            tok = m.group(0)
            out.append(Finding(
                title=f"Возможный утёкший секрет: {name}", severity=sev,
                target=source, module="secrets",
                description=f"В ответе обнаружен паттерн {name}.",
                evidence=f"{source}: {_mask(tok)} (замаскировано)",
                remediation="Проверьте и ротируйте секрет; уберите из клиентского кода.",
                cvss_vector=vec,
            ))
    return out


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
        targets: list[str] | None = None) -> list[Finding]:
    scope.assert_ready(authorized)
    findings: list[Finding] = []
    urls = targets or [a.value for a in store.assets.values() if a.kind == "url"]

    for url in urls:
        scope.guard(url)
        r = http.get(url)
        if not r.status:
            continue
        findings += _scan_text(r.text, url)

        # связанные скрипты (до 8, только in-scope)
        for m in _SCRIPT.findall(r.body)[:8]:
            src = m.decode("utf-8", "replace")
            js_url = urljoin(url, src)
            if not js_url.startswith("http") or not scope.in_scope_target(js_url):
                continue
            jr = http.get(js_url)
            if jr.status:
                findings += _scan_text(jr.text, js_url)

    # дедуп по (title, evidence)
    seen = set()
    uniq = []
    for f in findings:
        k = (f.title, f.evidence)
        if k not in seen:
            seen.add(k)
            store.add_finding(f)
            uniq.append(f)
    return uniq
