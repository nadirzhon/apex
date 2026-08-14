from apex.ascend.awm import Priv
from apex.ascend.evidence_graph import EvidenceNode
from apex.ascend.falsification import CheckResult
from apex.ascend.observations import Observation, ObservationLog
from apex.ascend.causal_model import ProvenanceWorldModel
from apex.ascend.pipeline import AscendPipeline
from apex.scope import Scope
from apex.store import Store


def _pipeline(tmp_path):
    scope = Scope(program="lab", authorized=True, in_scope=["127.0.0.1", "localhost"])
    store = Store(tmp_path / "state.json")
    pl = AscendPipeline(scope, store, authorized=True)
    pl.build_awm([{
        "key": "GET /api/orders/{id}",
        "method": "GET",
        "url": "http://127.0.0.1:8080/api/orders/1",
        "privilege": Priv.USER,
        "params": ["id"],
    }])
    return pl


def test_observation_log_is_immutable_and_has_lineage():
    log = ObservationLog()
    first = log.append(Observation(
        kind="http", actor="alice", target="http://127.0.0.1:8080/a",
        action="GET /a", state_before="s0", state_after="s1",
        response_fingerprint="r1",
    ))
    second = log.append(Observation(
        kind="http", actor="alice", target="http://127.0.0.1:8080/b",
        action="GET /b", state_before="s1", state_after="s2",
        parent_ids=(first.id,), response_fingerprint="r2",
    ))
    assert [item.id for item in log.lineage(second.id)] == [first.id, second.id]
    assert len(log.fingerprint()) == 64


def test_world_model_builds_grounded_causal_edges():
    world = ProvenanceWorldModel()
    obs = Observation(kind="http", actor="u", target="http://127.0.0.1:8080/x",
                      action="POST /x", state_before="before", state_after="after")
    world.ingest(obs)
    assert world.summary() == {"observations": 1, "states": 2, "causal_edges": 1}
    assert world.edges[0].evidence_ids == (obs.id,)


def test_pipeline_falsification_requires_all_controls(tmp_path):
    pl = _pipeline(tmp_path)
    hyp = pl.hypothesize()[0]
    plan = pl.falsification_plan(hyp.id)
    assert {"baseline", "negative-control", "repeat", "identity-swap"} <= plan.required_names

    incomplete = pl.evaluate_falsification(hyp.id, [CheckResult("baseline", True)])
    assert not incomplete.survived and "negative-control" in incomplete.missing

    complete = pl.evaluate_falsification(hyp.id, [
        CheckResult("baseline", True),
        CheckResult("negative-control", True),
        CheckResult("repeat", True),
        CheckResult("identity-swap", True),
    ])
    assert complete.survived


def test_replay_evidence_requires_real_observations(tmp_path):
    pl = _pipeline(tmp_path)
    hyp = pl.hypothesize()[0]
    baseline = pl.record_observation(Observation(
        kind="http", actor="victim", target="http://127.0.0.1:8080/api/orders/1",
        action="GET /api/orders/1", state_before="v0", state_after="v1",
        response_fingerprint="victim-data",
    ))
    control = pl.record_observation(Observation(
        kind="http", actor="control", target="http://127.0.0.1:8080/api/orders/1",
        action="GET /api/orders/999999", state_before="c0", state_after="c1",
        response_fingerprint="not-found",
    ))
    pl.assemble_replay_evidence(hyp.id, [
        EvidenceNode("baseline", "baseline", (baseline.id,)),
        EvidenceNode("control", "negative-control", (control.id,)),
    ])
    assert pl.evidence_graph.replayable(hyp.id, required_kinds={"baseline", "negative-control"})
    assert len(pl.evidence_graph.digest(hyp.id)) == 64


def test_pipeline_rejects_out_of_scope_observation(tmp_path):
    pl = _pipeline(tmp_path)
    try:
        pl.record_observation(Observation(kind="http", actor="x", target="https://example.com", action="GET /"))
        assert False, "out-of-scope observation must be rejected"
    except PermissionError:
        pass
