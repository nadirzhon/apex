"""Контракт и поведение MVP-оркестратора без сетевых запросов."""
from pathlib import Path

from apex.http import SafeHTTP
from apex.orchestrator import AgentContext, AgentSpec, Orchestrator, builtin_orchestrator
from apex.scope import Scope
from apex.store import Store


def _context(tmp_path: Path) -> AgentContext:
    return AgentContext(
        scope=Scope(program="Test", authorized=True, in_scope=["example.com"]),
        store=Store(tmp_path / "state.json"),
        http=SafeHTTP(),
        authorized=True,
    )


def test_builtin_plan_resolves_dependencies():
    plan = builtin_orchestrator().plan(["go-recon", "web", "secrets", "quality"])
    assert plan == ["go-recon", "web", "secrets", "quality"]


def test_quality_can_run_as_offline_review():
    assert builtin_orchestrator().plan(["quality"]) == ["quality"]


def test_offline_agent_does_not_require_network_authorization(tmp_path):
    context = _context(tmp_path)
    context.authorized = False
    context.scope.authorized = False

    summary = builtin_orchestrator().run(context, ["quality"])

    assert summary.ok


def test_network_agent_requires_authorization(tmp_path):
    context = _context(tmp_path)
    context.authorized = False
    orchestrator = Orchestrator()
    orchestrator.register(AgentSpec(
        "network", "test", lambda current: [], network_access=True
    ))

    try:
        orchestrator.run(context, ["network"])
    except PermissionError:
        pass
    else:
        raise AssertionError("сетевой агент должен требовать авторизацию")


def test_dry_run_never_calls_agent(tmp_path):
    called = []
    orchestrator = Orchestrator()
    orchestrator.register(AgentSpec("one", "test", lambda context: called.append(True) or []))

    summary = orchestrator.run(_context(tmp_path), ["one"], dry_run=True)

    assert called == []
    assert summary.ok
    assert summary.results[0].status == "planned"


def test_agent_results_and_state_are_recorded(tmp_path):
    orchestrator = Orchestrator()
    orchestrator.register(AgentSpec("one", "test", lambda context: []))

    summary = orchestrator.run(_context(tmp_path), ["one"])

    assert summary.ok
    assert summary.results[0].status == "completed"
    assert (tmp_path / "state.json").exists()
    assert len(summary.results) == 1
    assert len(_context(tmp_path).store.runs) == 1


def test_failed_dependency_skips_dependent_agent(tmp_path):
    called = []
    orchestrator = Orchestrator()

    def fail(context):
        raise RuntimeError("boom")

    orchestrator.register(AgentSpec("first", "fails", fail))
    orchestrator.register(AgentSpec(
        "second", "depends", lambda context: called.append(True) or [], depends_on=("first",)
    ))

    summary = orchestrator.run(
        _context(tmp_path), ["second"], continue_on_error=True
    )

    assert called == []
    assert [result.status for result in summary.results] == ["failed", "skipped"]
    assert not summary.ok


def test_unknown_agent_is_rejected():
    orchestrator = Orchestrator()
    try:
        orchestrator.plan(["missing"])
    except ValueError as exc:
        assert "неизвестный агент" in str(exc)
    else:
        raise AssertionError("неизвестный агент должен быть отклонён")
