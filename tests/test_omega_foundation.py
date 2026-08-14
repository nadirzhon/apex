from apex.ascend.awm import AWM, Node, Priv
from apex.ascend.court import AdversarialCourt, Verdict
from apex.ascend.digital_twin import DigitalTwin
from apex.ascend.invariants import InvariantCompiler, InvariantKind
from apex.ascend.reasoning import Evidence, EvidenceLedger, HypothesisEngine


def test_twin_compiles_invariants():
    twin = DigitalTwin()
    twin.ingest_endpoint({
        "key": "PATCH /api/orders/{id}",
        "method": "PATCH",
        "url": "https://t.example/api/orders/1",
        "privilege": Priv.USER,
        "params": ["id"],
        "tenant_scoped": True,
    })
    kinds = {i.kind for i in InvariantCompiler().compile(twin)}
    assert {
        InvariantKind.OWNERSHIP,
        InvariantKind.ROLE_BOUNDARY,
        InvariantKind.TENANT_ISOLATION,
        InvariantKind.STATE_TRANSITION,
    } <= kinds


def test_reasoning_links_hypothesis_to_invariant():
    awm = AWM()
    awm.add_node(Node(
        key="GET /api/orders/{id}",
        url="https://t.example/api/orders/1",
        privilege=Priv.USER,
        params=["id"],
    ))
    twin = DigitalTwin()
    twin.ingest_endpoint({
        "key": "GET /api/orders/{id}",
        "url": "https://t.example/api/orders/1",
        "privilege": Priv.USER,
        "params": ["id"],
    })
    hyps = HypothesisEngine().generate(awm, twin, InvariantCompiler().compile(twin))
    assert hyps[0].klass == "IDOR/BOLA"
    assert hyps[0].invariant_id.startswith("inv-")
    assert hyps[0].negative_control


def test_evidence_and_court_gates():
    awm = AWM()
    awm.add_node(Node(key="GET /o/{id}", url="https://t.example/o/1", params=["id"]))
    twin = DigitalTwin()
    twin.ingest_endpoint({"key": "GET /o/{id}", "url": "https://t.example/o/1", "params": ["id"]})
    hyp = HypothesisEngine().generate(awm, twin, InvariantCompiler().compile(twin))[0]
    ledger = EvidenceLedger(hyp.id, prior=hyp.confidence)
    ledger.add(Evidence("differential", "positive controlled differential", 30.0))
    court = AdversarialCourt(0.90)

    assert court.review(
        hyp, ledger, scope_ok=True, independently_reproduced=False
    ).verdict == Verdict.PROVISIONAL
    assert court.review(
        hyp, ledger, scope_ok=True, independently_reproduced=True
    ).verdict == Verdict.CONFIRMED
    assert court.review(
        hyp, ledger, scope_ok=False, independently_reproduced=True
    ).verdict == Verdict.REJECTED
