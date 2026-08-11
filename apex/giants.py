"""APEX Giants — прицел на крупнейшие цели.

Инструмент, специализированный под охоту на топовых гигантов: встроенный
каталог их bug-bounty программ (домены, AI/MCP-поверхность, что принимают,
выплаты) и оркестратор, который наводит ВЕСЬ арсенал на выбранного гиганта
одной командой — под тем же scope-гейтом fail-closed, что и всё в APEX.

Он не «взламывает гиганта сам» (такого не существует ни у кого). Он делает
рутинную часть работы охотника максимально: перечисляет поверхность гиганта,
прогоняет по ней каждый модуль, отсеивает известные паттерны и выдаёт
приоритизированный список КАНДИДАТОВ с доказательствами — то, что человек
дальше проверяет на impact и репортит. Это усилитель, наведённый на самые
крупные, самые платящие цели.

Только для авторизованного тестирования в рамках объявленной программы.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from .models import Finding
from .scope import Scope
from .store import Store
from .modules import web, secrets, llm, webvuln

# ── Каталог гигантов ────────────────────────────────────────────────────
# Курировано из публичных политик программ (2026). ai_endpoints/mcp_endpoints
# — поверхность для agentstrike / mcpscan; web_scope — для web/secrets.
# Тестировать строго на своём аккаунте и в рамках правил конкретной программы.
GIANTS = {
    "anthropic": {
        "name": "Anthropic — Model Safety & Security",
        "platform": "HackerOne (открытые сабмишены)",
        "url": "https://hackerone.com/anthropic",
        "web_scope": ["claude.ai", "api.anthropic.com", "*.anthropic.com"],
        "ai_endpoints": [],           # заполнить своим тест-эндпоинтом с ключом
        "mcp_endpoints": [],          # Claude Code MCP-интеграции (локальные)
        "prompt_injection": "core focus — принимают при доказанном impact",
        "reward": "до $15 000",
        "note": "Лучшее совпадение с mcpscan/agentstrike. MCP-scope: invisible tool use, permission bypass, sandbox escape.",
    },
    "openai": {
        "name": "OpenAI — Security track",
        "platform": "Bugcrowd (открытые сабмишены)",
        "url": "https://bugcrowd.com/openai",
        "web_scope": ["*.openai.com", "api.openai.com", "chatgpt.com"],
        "ai_endpoints": [],
        "mcp_endpoints": [],
        "prompt_injection": "agentic/MCP risks в scope; чистый jailbreak — нет",
        "reward": "до $100 000",
        "note": "Agentic risks including MCP, proprietary info exposure.",
    },
    "microsoft": {
        "name": "Microsoft Copilot (AI Bounty)",
        "platform": "MSRC (self-hosted)",
        "url": "https://msrc.microsoft.com/",
        "web_scope": ["copilot.microsoft.com", "*.microsoft.com"],
        "ai_endpoints": [],
        "mcp_endpoints": ["https://learn.microsoft.com/api/mcp"],
        "prompt_injection": "принимают и платят",
        "reward": "$250–$30 000",
        "note": "Copilot consumer + интеграции.",
    },
    "xai": {
        "name": "xAI / Grok",
        "platform": "HackerOne + vulnerabilities@x.ai",
        "url": "https://hackerone.com/x",
        "web_scope": ["x.ai", "*.x.ai", "grok.com"],
        "ai_endpoints": [],
        "mcp_endpoints": [],
        "prompt_injection": "в scope",
        "reward": "не раскрыто",
        "note": "Grok models + интеграции на платформе X.",
    },
    "google": {
        "name": "Google — Gemini / Bug Hunters",
        "platform": "Bug Hunters (self-hosted)",
        "url": "https://bughunters.google.com/",
        "web_scope": ["gemini.google.com", "*.google.com"],
        "ai_endpoints": [],
        "mcp_endpoints": [],
        "prompt_injection": "ИСКЛЮЧЁН из scope — не тратить время",
        "reward": "до $30 000",
        "note": "Prompt injection не принимают; сюда — только не-PI баги.",
    },
}


def list_programs() -> list[dict]:
    out = []
    for key, g in GIANTS.items():
        out.append({"key": key, **g})
    return out


def _mcpscan_surface(url: str) -> list[dict]:
    """Мягкий мост к mcpscan: аудит инструментов MCP-сервера.
    Возвращает список finding-dict mcpscan или [] с диагностикой при отсутствии."""
    root = Path(os.environ.get("APEX_MCPSCAN_PATH", Path.home() / "Desktop" / "mcpscan"))
    src = root / "src"
    if str(src) not in sys.path and src.exists():
        sys.path.insert(0, str(src))
    try:
        from mcpscan.connect import fetch_surface
        from mcpscan.checks import check_surface
    except ImportError as e:
        return [{
            "severity": "info", "category": "tooling",
            "target": url, "title": f"MCP-скан пропущен ({e})",
            "recommendation": "Установите mcpscan+fastmcp или задайте APEX_MCPSCAN_PATH.",
        }]
    surface = asyncio.run(fetch_surface(url))
    return check_surface(surface)


# severity mcpscan → CVSS-вектор APEX
_MCP_CVSS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "medium": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "",
}


def hunt(program_key: str, scope: Scope, store: Store, http, authorized: bool) -> list[Finding]:
    """Навести весь арсенал на одного гиганта: web → secrets → MCP → AI.
    Каждый модуль проходит через scope.guard (fail-closed)."""
    scope.assert_ready(authorized)
    g = GIANTS.get(program_key)
    if not g:
        raise ValueError(f"неизвестный гигант '{program_key}'. Доступно: {', '.join(GIANTS)}")

    findings: list[Finding] = []

    # 1) web + secrets по доменам гиганта (только те, что в scope-файле)
    web_targets = [d for d in g["web_scope"] if not d.startswith("*")]
    urls = [f"https://{d}" for d in web_targets]
    in_scope_urls = []
    for u in urls:
        try:
            scope.guard(u)
            in_scope_urls.append(u)
        except PermissionError:
            pass  # домен гиганта не в твоём scope-файле — пропускаем молча
    if in_scope_urls:
        findings += web.run(scope, store, http, authorized, in_scope_urls)
        findings += secrets.run(scope, store, http, authorized, in_scope_urls)
        # серьёзные классы: активная проверка SQLi/XSS (best-effort — нужен requests+bs4)
        try:
            findings += webvuln.run(scope, store, http, authorized, in_scope_urls)
        except (RuntimeError, Exception):
            pass  # web-vuln-scanner/зависимости недоступны — пропускаем, не роняя охоту

    # 2) MCP-поверхность через mcpscan
    for murl in g.get("mcp_endpoints", []):
        try:
            scope.guard(murl)
        except PermissionError:
            continue
        for f in _mcpscan_surface(murl):
            sev = f.get("severity", "info")
            findings.append(Finding(
                title=f"[MCP] {f.get('title', '')}",
                severity=sev,
                target=f.get("target", murl),
                module="giants/mcp",
                description=f.get("category", ""),
                evidence=f.get("evidence", "") or f.get("title", ""),
                remediation=f.get("recommendation", ""),
                cvss_vector=_MCP_CVSS.get(sev, ""),
            ))

    # 3) AI-эндпоинты через agentstrike (llm-модуль)
    ai = g.get("ai_endpoints", [])
    if ai:
        for url in ai:
            try:
                scope.guard(url)
            except PermissionError:
                continue
            findings += llm.run(scope, store, http, authorized, [url])

    for f in findings:
        store.add_finding(f)
    return findings
