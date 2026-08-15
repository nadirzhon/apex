import pytest

from apex.ascend.awm import Priv
from apex.ascend.pipeline import AscendPipeline
from apex.coordinator import ResearchCoordinator
from apex.league import Specialist
from apex.model_planner import StructuredModelPlanner
from apex.scope import Scope
from apex.store import Store


def fake_response(request):
    assert request["store"] is False
    assert request["text"]["format"]["type"] == "json_schema"
    return {
        "parsed": {
            "objective_restated": "falsify object-level authorization hypothesis",
            "reasoning_summary": "compare principals and negative controls before any conclusion",
            "checks": ["establish legitimate baseline", "compare second principal"],
            "evidence_needed": ["baseline response", "principal contrast", "negative control"],
            "stop_conditions": ["responses are indistinguishable from benign denial"],
            "memory_cues": ["access-control", "differential"],
            "confidence": 0.62,
        }
    }


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


def test_planner_returns_strict_conservative_plan(tmp_path):
    planner = StructuredModelPlanner(transport=fake_response)
    specialist = Specialist("authz", frozenset({"web", "reasoning", "access-control"}), 2)
    coordinator = ResearchCoordinator(
        pipeline(tmp_path), [specialist], planner=planner.plan, max_parallel=1
    )
    assignment = coordinator.assignments()[0]
    assert assignment.plan is not None
    assert assignment.plan.confidence == 0.62
    assert "negative control" in assignment.plan.evidence_needed[-1]


def test_request_never_gives_model_execution_tools(tmp_path):
    captured = {}
    def transport(req):
        captured.update(req)
        return fake_response(req)
    planner = StructuredModelPlanner(transport=transport)
    specialist = Specialist("authz", frozenset({"web", "access-control"}), 1)
    coordinator = ResearchCoordinator(pipeline(tmp_path), [specialist], planner=planner.plan)
    coordinator.assignments()
    assert "tools" not in captured
    assert captured["store"] is False


def test_non_json_model_output_is_rejected():
    planner = StructuredModelPlanner(transport=lambda _: {
        "output": [{"type": "message", "content": [{"type": "output_text", "text": "not json"}]}]
    })
    class A:
        objective = "x"
        family = "x"
        expected_outcome = "x"
        negative_control = "x"
        specialist = Specialist("s", frozenset({"reasoning"}), 0)
        memory = ()
    with pytest.raises(ValueError):
        planner.plan(A())


def test_extra_fields_are_rejected():
    bad = fake_response({"store":False,"text":{"format":{"type":"json_schema"}}})["parsed"] | {"confirm": True}
    planner = StructuredModelPlanner(transport=lambda _: {"parsed": bad})
    class A:
        objective = "x"
        family = "x"
        expected_outcome = "x"
        negative_control = "x"
        specialist = Specialist("s", frozenset({"reasoning"}), 0)
        memory = ()
    with pytest.raises(ValueError):
        planner.plan(A())
