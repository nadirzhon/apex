"""Мост MCP для APEX.

Выставляет движок как набор MCP-инструментов, чтобы Claude/агент вёл весь
энгейджмент разговором — но строго в границах scope. Scope-гейт действует
на уровне ядра: ни один инструмент не тронет цель вне программы.

Запуск:
    pip install "apex-bounty[mcp]"        # ставит fastmcp
    APEX_SCOPE=program.json APEX_AUTHORIZED=1 python -m apex.mcp_server

Подключение в Claude Code:
    claude mcp add apex -- python -m apex.mcp_server
(переменные окружения APEX_SCOPE / APEX_AUTHORIZED передать серверу).
"""
from __future__ import annotations

import os

try:
    from fastmcp import FastMCP
except ImportError as e:  # мягкая деградация — ядро работает и без MCP
    raise SystemExit(
        "Для моста MCP нужен fastmcp: pip install 'apex-bounty[mcp]'"
    ) from e

from .http import SafeHTTP
from .report import write as write_report
from .scope import Scope
from .store import Store
from .modules import recon, web, secrets, mobile

mcp = FastMCP("apex")

_SCOPE_PATH = os.environ.get("APEX_SCOPE", "program.json")
_AUTHORIZED = os.environ.get("APEX_AUTHORIZED", "") in ("1", "true", "yes")
_STATE = os.environ.get("APEX_STATE", ".apex/state.json")


def _ctx() -> tuple[Scope, Store, SafeHTTP]:
    scope = Scope.load(_SCOPE_PATH)
    store = Store(_STATE)
    store.program = scope.program
    return scope, store, SafeHTTP(rate_limit_rps=scope.rate_limit_rps)


@mcp.tool()
def scope_show() -> str:
    """Показать загруженный scope программы bug bounty (границы разрешённого)."""
    return Scope.load(_SCOPE_PATH).summary()


@mcp.tool()
def scope_check(target: str) -> dict:
    """Проверить, входит ли цель (домен/URL/пакет) в scope. Ничего не отправляет."""
    scope = Scope.load(_SCOPE_PATH)
    return {"target": target, "in_scope": scope.in_scope_target(target),
            "program": scope.program}


@mcp.tool()
def run_recon() -> dict:
    """Разведка in-scope хостов (DNS + HTTP fingerprint). Только внутри scope."""
    scope, store, http = _ctx()
    recon.run(scope, store, http, _AUTHORIZED)
    store.save()
    return {"assets": len(store.assets),
            "urls": [a.value for a in store.assets.values() if a.kind == "url"]}


@mcp.tool()
def scan_web() -> dict:
    """Неразрушающие веб-проверки (заголовки, TLS, экспонированные файлы)."""
    scope, store, http = _ctx()
    new = web.run(scope, store, http, _AUTHORIZED)
    store.save()
    return {"new_findings": [f.to_dict() for f in new]}


@mcp.tool()
def scan_secrets() -> dict:
    """Поиск утёкших секретов в веб-контенте (внутри scope)."""
    scope, store, http = _ctx()
    new = secrets.run(scope, store, http, _AUTHORIZED)
    store.save()
    return {"new_findings": [f.to_dict() for f in new]}


@mcp.tool()
def scan_mobile(apk_path: str, package: str = "") -> dict:
    """Статический анализ локального APK (пакет должен быть в scope)."""
    scope, store, _ = _ctx()
    new = mobile.run(scope, store, apk_path, _AUTHORIZED, package)
    store.save()
    return {"new_findings": [f.to_dict() for f in new]}


@mcp.tool()
def findings_list() -> dict:
    """Все накопленные находки движка со сводкой по серьёзности."""
    store = Store(_STATE)
    return {"count": len(store.findings), "by_severity": store.by_severity(),
            "findings": [f.to_dict() for f in store.findings]}


@mcp.tool()
def advise() -> str:
    """План действий: приоритет находок по деньгам + пошаговое «что делать
    дальше» по каждой зацепке + гид по классам под большой чек."""
    from .advisor import advise as _advise
    return _advise(Store(_STATE))


@mcp.tool()
def generate_report() -> dict:
    """Сгенерировать отчёт (Markdown + HTML) по текущим находкам."""
    scope = Scope.load(_SCOPE_PATH)
    store = Store(_STATE)
    md, ht = write_report(scope, store)
    return {"markdown": md, "html": ht, "count": len(store.findings)}


if __name__ == "__main__":
    mcp.run()
