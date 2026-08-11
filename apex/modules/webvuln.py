"""Активное тестирование серьёзных веб-классов — SQLi, XSS, sensitive files.

Это НЕ гигиена (заголовки/схемы), а высокооплачиваемые уязвимости: инъекция
и reflected XSS проверяются реальными payload'ами с детекцией по ошибке БД /
отражению. Мост к web-vuln-scanner (github.com/nadirzhon/web-vuln-scanner).

АКТИВНЫЙ модуль: шлёт тестовые payload'ы, поэтому работает только внутри
scope и с --i-am-authorized (fail-closed на каждую цель). Требует requests+bs4
(берутся из окружения; если их нет — модуль сообщает и не падает).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from ..models import Finding
from ..scope import Scope
from ..store import Store

# метка сканера → (категория, CVSS-вектор). Только АКТИВНО подтверждённые
# серьёзные классы; sensitive-files оставлены web-модулю, чтобы не дублировать.
_MAP = {
    "SQL Injection": ("sqli", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # ~9.8 critical
    "Reflected XSS": ("xss", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),    # ~6.1 high
}


def _import_scanner():
    root = Path(os.environ.get("APEX_WEBVULN_PATH", Path.home() / "Desktop" / "web-vuln-scanner"))
    if root.exists() and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from scanner import VulnScanner
        return VulnScanner
    except ImportError as e:
        raise RuntimeError(
            f"web-vuln-scanner недоступен ({e}). Клонируй в ~/Desktop/web-vuln-scanner "
            "и поставь requests+beautifulsoup4, либо задай APEX_WEBVULN_PATH."
        )


def run(scope: Scope, store: Store, http, authorized: bool,
        targets: list[str] | None = None, *, crawl: bool = True) -> list[Finding]:
    """Активно протестировать цели на SQLi/XSS/exposed-files. targets обязателен
    (активные payload'ы не шлём по угаданным URL)."""
    scope.assert_ready(authorized)
    if not targets:
        raise ValueError("webvuln требует явные --target (активное тестирование).")

    VulnScanner = _import_scanner()
    findings: list[Finding] = []

    for url in targets:
        scope.guard(url)  # fail-closed: активные payload'ы — только по in-scope
        sc = VulnScanner(url)
        sc.run(crawl=crawl)
        for f in sc.findings:
            vuln = f.get("vulnerability", "")
            if vuln not in _MAP:
                continue  # заголовки/дубли гигиены пропускаем — здесь только серьёзное
            cat, vector = _MAP[vuln]
            findings.append(Finding(
                title=f"{vuln}: {f.get('detail', '')}",
                severity=f.get("severity", "high").lower(),
                target=url,
                module="webvuln",
                description=f"Активная проверка подтвердила {vuln} (payload-based).",
                evidence=f.get("detail", ""),
                remediation={
                    "sqli": "Параметризованные запросы/ORM; никакой конкатенации ввода в SQL.",
                    "xss": "Экранируй вывод по контексту; CSP; не вставляй ввод в HTML сырым.",
                    "exposed-file": "Убери файл из веб-корня; закрой доступ; ротация секретов.",
                }.get(cat, ""),
                cvss_vector=vector,
            ))

    for f in findings:
        store.add_finding(f)
    return findings
