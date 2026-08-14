from apex.ascend.benchmark import BenchmarkCase, score
from apex.ascend.court import AdversarialCourt, Verdict
from apex.ascend.quality import FindingQualityGate
from apex.ascend.reasoning import Evidence, EvidenceLedger, Hypothesis


def _hyp():
    return Hypothesis("IDOR/BOLA", "GET /o/{id}", "id", "ownership check",
                      invariant_id="inv-1", negative_control="missing object is denied")


def test_benchmark_metrics_are_explicit():
    s = score([
        BenchmarkCase("tp", True, True, 10),
        BenchmarkCase("tn", False, False, 20),
        BenchmarkCase("fp", False, True, 30),
        BenchmarkCase("fn", True, False, 40),
    ])
    assert (s.tp, s.fp, s.tn, s.fn) == (1, 1, 1, 1)
    assert s.precision == 0.5 and s.recall == 0.5 and s.f1 == 0.5
    assert s.false_positive_rate == 0.5 and s.mean_latency_ms == 25
    assert not s.publication_ready


def test_quality_gate_requires_confirmed_reproducible_evidence():
    h = _hyp()
    ledger = EvidenceLedger(h.id, prior=0.40)
    ledger.add(Evidence("differential", "controlled positive", 30.0, reproducible=True))
    court = AdversarialCourt().review(h, ledger, scope_ok=True, independently_reproduced=True)
    assert court.verdict == Verdict.CONFIRMED
    q = FindingQualityGate(0.90).evaluate(h, ledger, court)
    assert q.publishable and q.score >= 0.90


def test_quality_gate_rejects_provisional_result():
    h = _hyp()
    ledger = EvidenceLedger(h.id, prior=0.40)
    ledger.add(Evidence("differential", "controlled positive", 30.0, reproducible=True))
    court = AdversarialCourt().review(h, ledger, scope_ok=True, independently_reproduced=False)
    q = FindingQualityGate().evaluate(h, ledger, court)
    assert court.verdict == Verdict.PROVISIONAL
    assert not q.publishable
