from apex.ascend.awm import Priv
from apex.ascend.digital_twin import DigitalTwin
from apex.ascend.invariants import InvariantCompiler, InvariantKind
from apex.ascend.reasoning import Evidence, EvidenceLedger


def test_digital_twin_summary_and_invariants():
    twin = DigitalTwin()
    twin.ingest_endpoint({
        "key": "GET /items/{id}",
        "method": "GET",
        "url": "https://app.example/items/1",
        "privilege": Priv.USER,
        "params": ["id"],
    })
    summary = twin.summary()
    assert summary["endpoints"] == 1
    invariants = InvariantCompiler().compile(twin)
    kinds = {item.kind for item in invariants}
    assert InvariantKind.OWNERSHIP in kinds
    assert InvariantKind.ROLE_BOUNDARY in kinds


def test_evidence_ledger_moves_confidence_both_directions():
    positive = EvidenceLedger("h", prior=0.35)
    positive.add(Evidence("check", "supporting observation", 12.0))
    assert positive.confidence > 0.85

    negative = EvidenceLedger("h", prior=0.35)
    negative.add(Evidence("check", "refuting observation", 0.05))
    assert negative.confidence < 0.05
