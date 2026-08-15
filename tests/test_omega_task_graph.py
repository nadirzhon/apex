import pytest

from apex.ascend.reasoning import Hypothesis
from apex.task_graph import AttemptResult, ResearchTask, ResearchTaskGraph, TaskBudget, TaskStatus


def hyp():
    return Hypothesis(
        klass="multi-step-chain",
        node_key="http://127.0.0.1:8080/final",
        param="(chain)",
        description="test whether workflow chain preserves authorization",
        expected_outcome="authorization invariant holds at every transition",
        negative_control="replay with a weaker principal",
    )


def test_hypothesis_becomes_dependency_aware_task():
    graph = ResearchTaskGraph()
    task = graph.add_hypothesis(hyp())
    assert "workflow" in task.required_capabilities
    assert task.semantic_anchor
    assert graph.ready() == [task]


def test_semantic_anchor_rejects_drift():
    graph = ResearchTaskGraph()
    task = graph.add_hypothesis(hyp())
    anchor = task.semantic_anchor
    task.objective = "silently changed objective"
    with pytest.raises(ValueError):
        graph.record_attempt(task.task_id, AttemptResult(progress={"x": 1}), anchor=anchor)


def test_stagnation_auto_pauses_repeated_nonprogress():
    graph = ResearchTaskGraph()
    task = graph.add_hypothesis(hyp(), budget=TaskBudget(max_tool_calls=50, max_cost_usd=2,
                                                        max_attempts=10, stagnation_limit=3))
    anchor = task.semantic_anchor
    for _ in range(3):
        graph.record_attempt(task.task_id, AttemptResult(progress={"same": True}, tool_calls=1), anchor=anchor)
    assert task.status == TaskStatus.PAUSED
    assert task.stagnant
    assert any("repeated progress" in note for note in task.notes)


def test_budget_governor_blocks_attempt_before_overrun():
    graph = ResearchTaskGraph()
    task = graph.add_hypothesis(hyp(), budget=TaskBudget(max_tool_calls=2, max_cost_usd=0.1,
                                                        max_attempts=4, stagnation_limit=3))
    anchor = task.semantic_anchor
    graph.record_attempt(task.task_id, AttemptResult(progress={"a": 1}, tool_calls=1, cost_usd=0.05), anchor=anchor)
    graph.record_attempt(task.task_id, AttemptResult(progress={"b": 1}, tool_calls=2, cost_usd=0.01), anchor=anchor)
    assert task.status == TaskStatus.PAUSED
    assert task.tool_calls == 1
    assert any("tool-call budget" in note for note in task.notes)


def test_dependencies_require_success():
    graph = ResearchTaskGraph()
    first = graph.add(ResearchTask("first", "observe login flow", "workflow"))
    graph.add(ResearchTask("second", "test role transition", "access", dependencies=("first",)))
    assert [t.task_id for t in graph.ready()] == ["first"]
    first.status = TaskStatus.SUCCEEDED
    assert {t.task_id for t in graph.ready()} == {"second"}


def test_dependency_cycle_rejected():
    graph = ResearchTaskGraph()
    graph.add(ResearchTask("a", "A", "x", dependencies=("b",)))
    graph.add(ResearchTask("b", "B", "x", dependencies=("a",)))
    with pytest.raises(ValueError):
        graph.ready()


def test_success_records_unique_evidence_and_summary():
    graph = ResearchTaskGraph()
    task = graph.add_hypothesis(hyp())
    anchor = task.semantic_anchor
    graph.record_attempt(task.task_id, AttemptResult(
        progress={"new-state": "s2"}, tool_calls=2, cost_usd=0.02,
        evidence_ids=("e1", "e1", "e2"), success=True,
    ), anchor=anchor)
    assert task.status == TaskStatus.SUCCEEDED
    assert task.evidence_ids == ["e1", "e2"]
    summary = graph.summary()
    assert summary["status"]["succeeded"] == 1
    assert summary["tool_calls"] == 2
