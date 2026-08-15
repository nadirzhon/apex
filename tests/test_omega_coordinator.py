from apex.ascend.awm import Priv
from apex.ascend.pipeline import AscendPipeline
from apex.coordinator import ResearchCoordinator, SpecialistOutcome
from apex.league import Specialist
from apex.scope import Scope
from apex.store import Store
from apex.task_graph import TaskBudget, TaskStatus


def pipeline(tmp_path):
    scope = Scope(program="lab", authorized=True, in_scope=["127.0.0.1", "localhost"])
    pl = AscendPipeline(scope, Store(tmp_path / "state.json"), authorized=True)
    pl.build_awm([{
        "key": "GET /api/orders/{id}",
        "method": "GET",
        "url": "http://127.0.0.1:8080/api/orders/1",
        "privilege": Priv.USER,
        "params": ["id"],
        "tenant_scoped": True,
    }])
    return pl


def specialists():
    return [
        Specialist("generic", frozenset({"web", "reasoning"}), priority=1),
        Specialist("authz", frozenset({"web", "reasoning", "access-control"}), priority=3),
    ]


def test_refresh_materializes_hypotheses_and_routes_specialist(tmp_path):
    c = ResearchCoordinator(pipeline(tmp_path), specialists())
    created = c.refresh_hypotheses()
    assert created
    batch = c.assignments()
    assert batch
    assert batch[0].specialist.name == "authz"
    assert batch[0].semantic_anchor


def test_success_updates_task_portfolio_and_memory(tmp_path):
    c = ResearchCoordinator(pipeline(tmp_path), specialists())
    assignment = c.assignments()[0]
    task = c.record(assignment, SpecialistOutcome(
        progress={"contrast": "confirmed"},
        success=True,
        tool_calls=3,
        cost_usd=0.04,
        evidence_ids=("e1", "e2"),
        reusable_lesson={"method": "compare principals with a negative control"},
    ))
    assert task.status == TaskStatus.SUCCEEDED
    assert task.evidence_ids == ["e1", "e2"]
    assert c.memory.activate([task.family.lower(), "access-control"])


def test_memory_does_not_feed_back_same_task(tmp_path):
    c = ResearchCoordinator(pipeline(tmp_path), specialists())
    assignment = c.assignments()[0]
    c.record(assignment, SpecialistOutcome(
        progress={"x": 1}, success=False, tool_calls=1, cost_usd=0.01,
        reusable_lesson={"method": "use differential controls"},
    ))
    # Same task is still active, but its own lesson must be excluded from its context.
    next_assignment = next(a for a in c.assignments() if a.task_id == assignment.task_id)
    assert next_assignment.memory == ()


def test_bounded_run_executes_registered_specialists(tmp_path):
    c = ResearchCoordinator(
        pipeline(tmp_path), specialists(),
        task_budget=TaskBudget(max_tool_calls=10, max_cost_usd=1, max_attempts=4, stagnation_limit=3),
        max_parallel=1,
    )

    def authz_runner(assignment):
        return SpecialistOutcome(
            progress={"done": assignment.hypothesis_id},
            success=True,
            tool_calls=2,
            cost_usd=0.02,
            evidence_ids=("proof",),
        )

    report = c.run({"authz": authz_runner}, max_rounds=4)
    assert report.successes >= 1
    assert report.total_tool_calls >= 2
    assert report.task_summary["status"]["succeeded"] >= 1


def test_missing_runner_pauses_task(tmp_path):
    c = ResearchCoordinator(pipeline(tmp_path), specialists(), max_parallel=1)
    report = c.run({}, max_rounds=1)
    assert any(t.status == TaskStatus.PAUSED for t in c.graph.tasks.values())
    assert report.task_summary["status"]["paused"] >= 1


def test_stale_assignment_rejected_after_explicit_replan(tmp_path):
    c = ResearchCoordinator(pipeline(tmp_path), specialists())
    assignment = c.assignments()[0]
    c.graph.replan(assignment.task_id, objective="new explicitly approved objective")
    try:
        c.record(assignment, SpecialistOutcome(progress={}, success=False, tool_calls=0, cost_usd=0))
        assert False, "stale semantic anchor should be rejected"
    except ValueError as exc:
        assert "stale" in str(exc)
