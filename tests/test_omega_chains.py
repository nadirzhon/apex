from apex.ascend.chains import ChainReasoner
from apex.ascend.observations import Observation
from apex.ascend.pipeline import AscendPipeline
from apex.scope import Scope
from apex.store import Store


def pipeline(tmp_path):
    scope = Scope(program="lab", authorized=True, in_scope=["127.0.0.1", "localhost"])
    return AscendPipeline(scope, Store(tmp_path / "state.json"), authorized=True)


def record(pl, actor, target, action, before, after, privilege=1):
    return pl.record_observation(Observation(
        kind="http",
        actor=actor,
        target=target,
        action=action,
        state_before=before,
        state_after=after,
        facts={"privilege": privilege},
    ))


def test_chain_reasoner_finds_cross_endpoint_evidence_grounded_path(tmp_path):
    pl = pipeline(tmp_path)
    record(pl, "user", "http://127.0.0.1:8080/start", "GET /start", "s0", "s1", 1)
    record(pl, "user", "http://127.0.0.1:8080/token", "POST /token", "s1", "s2", 1)
    record(pl, "admin", "http://127.0.0.1:8080/private", "GET /private", "s2", "s3", 3)

    chains = pl.chain_candidates()
    assert chains
    best = chains[0]
    assert best.steps >= 2
    assert len(best.evidence_ids) >= 2
    assert len(best.targets) >= 2
    assert any("privilege" in reason for reason in best.reasons)


def test_chain_reasoner_avoids_cycles(tmp_path):
    pl = pipeline(tmp_path)
    record(pl, "u", "http://127.0.0.1:8080/a", "A", "s0", "s1")
    record(pl, "u", "http://127.0.0.1:8080/b", "B", "s1", "s2")
    record(pl, "u", "http://127.0.0.1:8080/c", "C", "s2", "s0")
    for chain in ChainReasoner(max_depth=8).search(pl.world):
        assert len(chain.states) == len(set(chain.states))


def test_chain_hypothesis_is_added_only_after_observed_multistep_path(tmp_path):
    pl = pipeline(tmp_path)
    assert not [h for h in pl.hypothesize() if h.klass == "multi-step-chain"]

    record(pl, "alice", "http://127.0.0.1:8080/a", "GET /a", "s0", "s1", 1)
    record(pl, "alice", "http://127.0.0.1:8080/b", "POST /b", "s1", "s2", 1)
    record(pl, "bob", "http://127.0.0.1:8080/c", "GET /c", "s2", "s3", 2)

    hypotheses = [h for h in pl.hypothesize() if h.klass == "multi-step-chain"]
    assert hypotheses
    assert "cross" in hypotheses[0].description or "principal" in hypotheses[0].description


def test_chain_score_rewards_multi_target_principal_contrast(tmp_path):
    pl = pipeline(tmp_path)
    record(pl, "alice", "http://127.0.0.1:8080/a", "A", "s0", "s1", 1)
    record(pl, "bob", "http://127.0.0.1:8080/b", "B", "s1", "s2", 2)
    record(pl, "bob", "http://127.0.0.1:8080/c", "C", "s2", "s3", 2)
    best = pl.chain_candidates()[0]
    assert best.score >= 0.55
    assert len(best.actors) == 2
    assert len(best.targets) == 3
