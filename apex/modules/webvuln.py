"""Активное тестирование серьёзных веб-классов — SQLi, XSS, sensitive files.

Это НЕ гигиена (заголовки/схемы), а высокооплачиваемые уязвимости: инъекция
и reflected XSS проверяются реальными payload'ами с детекцией по ошибке БД /
отражению. Мост к web-vuln-scanner (github.com/nadirzhon/web-vuln-scanner).

АКТИВНЫЙ модуль: шлёт тестовые payload'ы, поэтому работает только внутри
scope и с --i-am-authorized (fail-closed на каждую цель). Требует requests+bs4+colorama
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


def _candidate_roots() -> list[Path]:
    """Места, где может лежать web-vuln-scanner (scanner.py), в порядке приоритета.
    APEX_WEBVULN_PATH — первым; затем типовые расположения рядом с apex."""
    roots: list[Path] = []
    env = os.environ.get("APEX_WEBVULN_PATH")
    if env:
        roots.append(Path(env))
    here = Path(__file__).resolve()
    # apex/apex/modules/webvuln.py → родитель репозитория apex
    repo_parent = here.parents[3] if len(here.parents) > 3 else Path.home()
    home = Path.home()
    # Только доверенные, НЕ управляемые атакующим пути. Намеренно БЕЗ Path.cwd():
    # импорт scanner.py из текущего каталога = запуск чужого кода, если apex
    # запущен в недоверенной директории (напр. распакованный engagement-архив).
    roots += [
        home / "finish_projects" / "web-vuln-scanner",
        repo_parent / "web-vuln-scanner",      # сосед репозитория apex (не CWD)
        home / "Desktop" / "web-vuln-scanner",
        home / "web-vuln-scanner",
        home / "projects" / "web-vuln-scanner",
    ]
    return roots


def _import_scanner() -> tuple[type | None, str | None]:
    """Найти и загрузить VulnScanner. Возвращает (класс, None) либо (None, причина).
    Никогда не бросает — вызывающий деградирует мягко (докстринг модуля)."""
    found: Path | None = None
    for root in _candidate_roots():
        try:
            if root and (root / "scanner.py").is_file():
                found = root
                break
        except OSError:
            continue
    if found is None:
        return None, (
            "web-vuln-scanner не найден. Склонируй github.com/nadirzhon/web-vuln-scanner "
            "рядом с apex (например ~/finish_projects/web-vuln-scanner) или задай APEX_WEBVULN_PATH."
        )
    if str(found) not in sys.path:
        sys.path.insert(0, str(found))
    try:
        from scanner import VulnScanner
        return VulnScanner, None
    except ImportError as e:
        return None, (
            f"web-vuln-scanner найден ({found}), но не загружается: {e}. "
            "Установи зависимости: pip install requests beautifulsoup4 colorama."
        )


def run(scope: Scope, store: Store, http, authorized: bool,
        targets: list[str] | None = None, *, crawl: bool = True) -> list[Finding]:
    """Активно протестировать цели на SQLi/XSS/exposed-files. targets обязателен
    (активные payload'ы не шлём по угаданным URL)."""
    scope.assert_ready(authorized)
    if not targets:
        raise ValueError("webvuln требует явные --target (активное тестирование).")

    VulnScanner, reason = _import_scanner()
    if VulnScanner is None:
        # Мягкая деградация (как обещает докстринг): без трейсбека, без находок.
        print(f"[webvuln] пропущено: {reason}")
        return []
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
