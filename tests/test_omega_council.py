from apex.ascend.awm import Priv
from apex.ascend.observations import Observation
from apex.ascend.pipeline import AscendPipeline
from apex.scope import Scope
from apex.store import Store


def _pipeline(tmp_path):
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


def test_council_does_not_admit_on_single_weak_signal(tmp_path):
    pl = _pipeline(tmp_path)
    hyp = pl.hypothesize()[0]
    decision = pl.deliberate(hyp.id)
    assert not decision.admitted
    assert {vote.strategy for vote in decision.votes} == {"structural", "semantic", "provenance"}


def test_council_admits_after_independent_principal_observations(tmp_path):
    pl = _pipeline(tmp_path)
    hyp = pl.hypothesize()[0]
    target = "http://127.0.0.1:8080/api/orders/1"
    pl.record_observation(Observation(kind="http", actor="alice", target=target,
                                      action="GET /api/orders/1", state_before="a0", state_after="a1"))
    pl.record_observation(Observation(kind="http", actor="bob", target=target,
                                      action="GET /api/orders/1", state_before="b0", state_after="b1"))
    decision = pl.deliberate(hyp.id)
    assert decision.admitted
    assert decision.support >= 0.60
