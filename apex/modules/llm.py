"""LLM / агентная поверхность: авторизованный red-team prompt-injection.

Единственный класс уязвимостей, где даже крупные компании ещё уязвимы, — их
AI-продукты (чат-агенты, ассистенты, RAG-эндпоинты) молоды и не вылизаны, как
классический код. Этот модуль натравливает agentstrike (генетический фаззер
prompt-injection) на LLM-эндпоинт СТРОГО внутри scope и превращает каждый
доказанный пробой в Finding APEX.

Доказательство — не «модель сказала что-то плохое», а **canary-маркер**: в
payload вшит уникальный токен, который агент не должен возвращать. Вернул →
он выполнил инструкцию, которую обязан был проигнорировать. Это неразрушающее
доказательство управляемости агента (OWASP LLM01), а не эксплуатация.

Требует пакет agentstrike (github.com/nadirzhon/agentstrike). Если он не
установлен, модуль ищет его рядом — в ~/Desktop/agentstrike или в
$APEX_AGENTSTRIKE_PATH — и подключает без установки.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from ..models import Finding
from ..scope import Scope
from ..store import Store

# severity-метка agentstrike → представительный вектор CVSS 3.1.
# Финальную серьёзность определяют привилегии агента (доступ к данным,
# инструментам, действиям) — здесь берётся консервативная база на сетевой,
# не требующей аутентификации инъекции. Уточняйте вектор под конкретный агент.
_CVSS_BY_SEVERITY = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def _import_agentstrike():
    """Мягкий импорт agentstrike: сперва как установленный пакет, затем из
    соседнего клона. Возвращает (run_campaign, HTTPTarget) или бросает
    RuntimeError с понятной подсказкой."""
    candidates = []
    env = os.environ.get("APEX_AGENTSTRIKE_PATH")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(Path.home() / "Desktop" / "agentstrike")
    try:
        from agentstrike.engine import run_campaign
        from agentstrike.targets.http import HTTPTarget
        return run_campaign, HTTPTarget
    except ImportError:
        pass
    for root in candidates:
        if (root / "agentstrike" / "__init__.py").exists():
            sys.path.insert(0, str(root))
            try:
                from agentstrike.engine import run_campaign
                from agentstrike.targets.http import HTTPTarget
                return run_campaign, HTTPTarget
            except ImportError:
                sys.path.pop(0)
    raise RuntimeError(
        "agentstrike не найден. Установите (pip install agentstrike) или "
        "клонируйте рядом (~/Desktop/agentstrike), либо задайте "
        "APEX_AGENTSTRIKE_PATH=/путь/к/agentstrike."
    )


def run(
    scope: Scope,
    store: Store,
    http,  # для единообразия сигнатуры модулей APEX; agentstrike ходит сам
    authorized: bool,
    targets: list[str] | None = None,
    *,
    field: str = "message",
    response_path: str = "response",
    headers: dict[str, str] | None = None,
    generations: int = 3,
) -> list[Finding]:
    """Прогнать red-team prompt-injection по LLM-эндпоинтам внутри scope.

    targets — список URL LLM-API (обязателен: не всякий URL — это агент).
    field / response_path — форма JSON запроса/ответа эндпоинта
      (тело `{field: prompt}`, ответ извлекается по `a.b.c` из JSON).
    """
    scope.assert_ready(authorized)
    if not targets:
        raise ValueError(
            "llm-модулю нужен явный --target LLM-эндпоинт "
            "(recon не угадывает, какой URL — это агент)."
        )

    run_campaign, HTTPTarget = _import_agentstrike()
    findings: list[Finding] = []

    for url in targets:
        scope.guard(url)  # fail-closed на каждую цель — вне scope не бьём
        target = HTTPTarget(
            url,
            field=field,
            response_path=response_path,
            headers=headers,
            method="POST",
        )
        result = run_campaign(target, generations=generations)

        for b in result.sorted_breaches():
            label = getattr(b.severity, "label", "high").lower()
            vector = _CVSS_BY_SEVERITY.get(label, _CVSS_BY_SEVERITY["high"])
            evidence = (
                f"Техника: {b.technique}\n"
                f"OWASP: {b.owasp}\n"
                f"Отправленный payload:\n{b.payload}\n\n"
                f"Что доказало пробой: {b.signal}\n"
                f"Фрагмент ответа агента:\n{b.response_excerpt}\n"
                f"Поколение генетического поиска: {b.generation} · "
                f"уверенность: {b.confidence}"
            )
            findings.append(
                Finding(
                    title=f"Prompt injection ({b.technique}): {b.title}",
                    severity=label,  # уточнится калькулятором CVSS ниже
                    target=url,
                    module="llm",
                    description=(
                        f"{b.owasp}. Агент выполнил инструкцию из недоверенного "
                        f"ввода — доказано canary-маркером, без разрушающего "
                        f"воздействия. Итоговая серьёзность зависит от привилегий "
                        f"агента (доступ к данным пользователей, инструментам, "
                        f"внешним действиям)."
                    ),
                    evidence=evidence,
                    remediation=b.remediation,
                    cvss_vector=vector,
                    references=[
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    ],
                )
            )

    for f in findings:
        store.add_finding(f)
    return findings
