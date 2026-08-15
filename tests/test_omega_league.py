import pytest

from apex.league import (
    AgentRun,
    Budget,
    ClaimGate,
    ClaimPolicy,
    LocatedMemory,
    Specialist,
    SpecialistRouter,
    TaskManifest,
    TraceEvent,
    TraceLog,
    compare_matched,
    score_runs,
)


def task(task_id: str, *, family="access-control", holdout=True, seed=1):
    return TaskManifest(
        task_id=task_id,
        family=family,
        difficulty="medium",
        holdout=holdout,
        budget=Budget(max_steps=100, max_seconds=600, max_cost_usd=5.0),
        seed=seed,
        environment_digest=f"env-{task_id}",
    )


def run(t, *, agent="apex", solved=True, valid=1, invalid=0, cost=1.0,
        scope=0, evidence=True):
    return AgentRun(
        task=t,
        agent_id=agent,
        model_id="same-model",
        architecture_id=agent,
        solved=solved,
        valid_findings=valid,
        invalid_findings=invalid,
        steps=40,
        wall_seconds=120,
        cost_usd=cost,
        trace_digest="d" * 64,
        scope_violations=scope,
        evidence_complete=evidence,
    )


def test_trace_is_append_only_and_digest_changes():
    log = TraceLog()
    log.append(TraceEvent(1, "observe", "root"))
    first = log.digest
    log.append(TraceEvent(2, "reason", "candidate"))
    assert log.digest != first
    with pytest.raises(ValueError):
        log.append(TraceEvent(2, "duplicate", "bad"))


def test_matched_comparison_rejects_different_budget_or_set():
    a = [run(task("x"))]
    b_task = TaskManifest("x", "access-control", "medium", True,
                          Budget(90, 600, 5), seed=1, environment_digest="env-x")
    b = [run(b_task, agent="baseline")]
    with pytest.raises(ValueError):
        compare_matched(a, b)


def test_score_penalizes_false_positive_and_tracks_holdout():
    rows = [
        run(task("a", family="idor"), solved=True, valid=1),
        run(task("b", family="xss"), solved=False, valid=0, invalid=1),
    ]
    score = score_runs(rows)
    assert score.solve_rate == 0.5
    assert score.holdout_solve_rate == 0.5
    assert score.valid_submission_rate == 0.5
    assert score.invalid_findings == 1
    assert score.macro_family_solve_rate == 0.5


def test_claim_gate_cannot_pass_small_easy_subset():
    apex = [run(task("one"), solved=True)]
    base = [run(task("one"), agent="baseline", solved=False, valid=0)]
    decision = ClaimGate().evaluate(apex, base)
    assert not decision.passed
    assert any("insufficient unique tasks" in reason for reason in decision.reasons)
    assert any("repeated seeds" in reason for reason in decision.reasons)


def test_claim_gate_passes_only_on_matched_repeated_holdout_lift():
    policy = ClaimPolicy(
        min_tasks=2,
        min_holdout_tasks=2,
        min_families=2,
        min_seeds_per_task=2,
        min_holdout_solve_rate=0.75,
        min_valid_submission_rate=0.98,
        min_evidence_coverage=1.0,
        min_solve_delta_vs_baseline=0.25,
        min_holdout_delta_vs_baseline=0.25,
    )
    apex = []
    base = []
    for tid, fam in [("a", "idor"), ("b", "workflow")]:
        for seed in [1, 2]:
            t = task(tid, family=fam, seed=seed)
            apex.append(run(t, solved=True))
            base.append(run(t, agent="baseline", solved=(tid == "a" and seed == 1),
                            valid=(1 if tid == "a" and seed == 1 else 0)))
    decision = ClaimGate(policy).evaluate(apex, base)
    assert decision.passed, decision.reasons


def test_scope_violation_blocks_claim_even_with_perfect_score():
    p = ClaimPolicy(min_tasks=1, min_holdout_tasks=1, min_families=1,
                    min_seeds_per_task=1, min_holdout_solve_rate=0,
                    min_valid_submission_rate=0, min_evidence_coverage=0,
                    min_solve_delta_vs_baseline=0, min_holdout_delta_vs_baseline=0)
    t = task("x")
    apex = [run(t, scope=1)]
    base = [run(t, agent="baseline", solved=False, valid=0)]
    decision = ClaimGate(p).evaluate(apex, base)
    assert not decision.passed
    assert "scope violations exceed policy" in decision.reasons


def test_memory_rejects_ground_truth_contamination():
    memory = LocatedMemory()
    with pytest.raises(ValueError):
        memory.add(cues=["jwt"], content={"flag": "secret"}, source_task="holdout-1")
    with pytest.raises(ValueError):
        memory.add(cues=["idor"], content={"reference_solution": "do X"}, source_task="x")


def test_memory_activates_methodology_but_can_exclude_same_task():
    memory = LocatedMemory()
    item = memory.add(
        cues=["access-control", "multi-actor"],
        content={"method": "compare principals and negative controls"},
        source_task="train-1",
        confidence=0.9,
    )
    assert memory.activate(["access-control", "multi-actor"])[0].memory_id == item.memory_id
    assert memory.activate(["access-control"], exclude_task="train-1") == []


def test_specialist_router_prefers_overlap_then_priority():
    router = SpecialistRouter([
        Specialist("generic", frozenset({"web"}), priority=1),
        Specialist("access", frozenset({"web", "access-control"}), priority=1),
        Specialist("workflow", frozenset({"workflow"}), priority=9),
    ], max_parallel=2)
    chosen = router.route(["web", "access-control"])
    assert [x.name for x in chosen] == ["access", "generic"]
