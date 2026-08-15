"""Общий оркестратор узких APEX-агентов.

Оркестратор ничего не знает о внутренней логике проверок. Он строит план по
зависимостям, передаёт агентам единый контекст и собирает измеримый результат.
Это позволяет добавлять новые направления без разрастания CLI и ``cmd_run``.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

from .http import SafeHTTP
from .models import Finding
from .scope import Scope
from .store import Store


PROFILES: dict[str, tuple[str, ...]] = {
    "baseline": ("web", "secrets", "quality"),
    "passive": ("recon", "secrets", "quality"),
    "fast-baseline": ("go-recon", "web", "secrets", "quality"),
    "offline-review": ("quality",),
}


@dataclass
class AgentContext:
    scope: Scope
    store: Store
    http: SafeHTTP
    authorized: bool
    targets: list[str] | None = None


AgentRunner = Callable[[AgentContext], list[Finding]]


@dataclass(frozen=True)
class AgentSpec:
    name: str
    description: str
    runner: AgentRunner
    depends_on: tuple[str, ...] = ()
    network_access: bool = False


@dataclass
class AgentResult:
    name: str
    status: str
    duration_ms: int = 0
    assets_added: int = 0
    findings_added: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class RunSummary:
    requested: list[str]
    plan: list[str]
    results: list[AgentResult] = field(default_factory=list)
    dry_run: bool = False
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def ok(self) -> bool:
        return all(r.status in {"completed", "planned"} for r in self.results)

    def to_dict(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "plan": self.plan,
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ok": self.ok,
            "results": [r.to_dict() for r in self.results],
        }


class Orchestrator:
    """Реестр агентов и последовательный исполнитель их зависимостей."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentSpec] = {}

    @property
    def agents(self) -> dict[str, AgentSpec]:
        return dict(self._agents)

    def register(self, spec: AgentSpec) -> None:
        if not spec.name or spec.name in self._agents:
            raise ValueError(f"агент уже зарегистрирован или не имеет имени: {spec.name!r}")
        self._agents[spec.name] = spec

    def plan(self, requested: Iterable[str]) -> list[str]:
        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name not in self._agents:
                raise ValueError(f"неизвестный агент: {name}")
            if name in visiting:
                raise ValueError(f"циклическая зависимость агента: {name}")
            if name in visited:
                return
            visiting.add(name)
            for dependency in self._agents[name].depends_on:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)
            ordered.append(name)

        requested_list = list(dict.fromkeys(requested))
        if not requested_list:
            raise ValueError("не выбран ни один агент")
        for name in requested_list:
            visit(name)
        return ordered

    def run(
        self,
        context: AgentContext,
        requested: Iterable[str],
        *,
        dry_run: bool = False,
        continue_on_error: bool = False,
    ) -> RunSummary:
        requested_list = list(dict.fromkeys(requested))
        plan = self.plan(requested_list)
        summary = RunSummary(requested=requested_list, plan=plan, dry_run=dry_run)

        if dry_run:
            summary.results = [AgentResult(name=name, status="planned") for name in plan]
            summary.finished_at = time.time()
            return summary

        if any(self._agents[name].network_access for name in plan):
            context.scope.assert_ready(context.authorized)
        failed: set[str] = set()
        for name in plan:
            spec = self._agents[name]
            blocked_by = [dependency for dependency in spec.depends_on if dependency in failed]
            if blocked_by:
                failed.add(name)
                summary.results.append(AgentResult(
                    name=name,
                    status="skipped",
                    error=f"не выполнены зависимости: {', '.join(blocked_by)}",
                ))
                continue

            assets_before = len(context.store.assets)
            findings_before = len(context.store.findings)
            started = time.monotonic()
            try:
                spec.runner(context)
                context.store.save()
                summary.results.append(AgentResult(
                    name=name,
                    status="completed",
                    duration_ms=round((time.monotonic() - started) * 1000),
                    assets_added=len(context.store.assets) - assets_before,
                    findings_added=len(context.store.findings) - findings_before,
                ))
            except Exception as exc:  # граница агента: один сбой не теряет весь журнал
                failed.add(name)
                summary.results.append(AgentResult(
                    name=name,
                    status="failed",
                    duration_ms=round((time.monotonic() - started) * 1000),
                    error=f"{type(exc).__name__}: {exc}",
                ))
                if not continue_on_error:
                    break
        summary.finished_at = time.time()
        context.store.record_run(summary.to_dict())
        context.store.save()
        return summary


def builtin_orchestrator() -> Orchestrator:
    """MVP-реестр. Новое направление добавляется одной ``AgentSpec``."""
    from .modules import go_core, recon, secrets, web
    from . import quality

    orchestrator = Orchestrator()
    orchestrator.register(AgentSpec(
        name="recon",
        description="DNS и HTTP fingerprint объявленных scope-активов",
        runner=lambda c: recon.run(c.scope, c.store, c.http, c.authorized),
        network_access=True,
    ))
    orchestrator.register(AgentSpec(
        name="go-recon",
        description="Конкурентный HTTP fingerprint через APEX Go Core",
        runner=go_core.run,
        network_access=True,
    ))
    orchestrator.register(AgentSpec(
        name="web",
        description="Неразрушающие веб-проверки",
        runner=lambda c: web.run(c.scope, c.store, c.http, c.authorized, c.targets),
        network_access=True,
    ))
    orchestrator.register(AgentSpec(
        name="secrets",
        description="Поиск и маскирование секретов в HTML/JavaScript",
        runner=lambda c: secrets.run(c.scope, c.store, c.http, c.authorized, c.targets),
        network_access=True,
    ))
    orchestrator.register(AgentSpec(
        name="quality",
        description="Офлайн-оценка полноты доказательств и готовности к ручной проверке",
        runner=quality.run,
    ))
    return orchestrator
