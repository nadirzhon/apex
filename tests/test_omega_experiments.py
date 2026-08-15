from apex.experiments import AblationStudy, AdaptivePortfolio, mcnemar_exact, wilson_interval
from apex.league import AgentRun, Budget, Specialist, TaskManifest


def t(i, seed=1):
    return TaskManifest(str(i), "idor" if i % 2 else "workflow", "medium", True,
                        Budget(100, 600, 5), seed=seed, environment_digest=f"env-{i}")


def r(task, agent, solved, cost=1.0):
    return AgentRun(task, agent, "same-model", agent, solved,
                    1 if solved else 0, 0, 30, 100, cost, "a" * 64)


def test_wilson_interval_bounds_estimate():
    ci = wilson_interval(80, 100)
    assert 0 <= ci.low < ci.estimate < ci.high <= 1
    assert ci.estimate == 0.8


def test_mcnemar_exact_detects_directional_discordance():
    tasks = [t(i) for i in range(1, 13)]
    apex = [r(x, "apex", True) for x in tasks]
    baseline = [r(x, "base", i < 3) for i, x in enumerate(tasks)]
    sig = mcnemar_exact(apex, baseline)
    assert sig.apex_only == 10
    assert sig.baseline_only == 0
    assert sig.exact_p_value < 0.01


def test_ablation_study_quantifies_component_loss():
    tasks = [t(i) for i in range(1, 9)]
    baseline = [r(x, "base", i < 2) for i, x in enumerate(tasks)]
    full = [r(x, "full", True) for x in tasks]
    no_memory = [r(x, "no-memory", i < 5) for i, x in enumerate(tasks)]
    study = AblationStudy(baseline, full)
    result = study.evaluate("no-memory", no_memory)
    assert result.comparison_to_baseline.solve_rate_delta > 0
    assert result.comparison_to_full.solve_rate_delta > 0


def test_adaptive_portfolio_learns_family_specific_success_cost():
    specialists = [
        Specialist("generic", frozenset({"web", "access-control"}), 1),
        Specialist("authz", frozenset({"access-control"}), 2),
    ]
    p = AdaptivePortfolio(specialists, exploration=0.1)
    for _ in range(5):
        p.record(family="idor", specialist="authz", success=True, cost_usd=0.5)
        p.record(family="idor", specialist="generic", success=False, cost_usd=1.5)
    chosen = p.choose(family="idor", required_capabilities=["access-control"], limit=1)
    assert chosen[0].specialist.name == "authz"


def test_portfolio_keeps_untried_specialist_explorable():
    specialists = [
        Specialist("a", frozenset({"web"}), 0),
        Specialist("b", frozenset({"web"}), 0),
    ]
    p = AdaptivePortfolio(specialists, exploration=1.0)
    for _ in range(20):
        p.record(family="web", specialist="a", success=True, cost_usd=1)
    chosen = p.choose(family="web", required_capabilities=["web"], limit=2)
    assert {x.specialist.name for x in chosen} == {"a", "b"}
