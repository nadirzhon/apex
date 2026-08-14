"""Publication quality policy for confirmed ASCEND findings."""
from __future__ import annotations

from dataclasses import dataclass, field

from .court import CourtDecision, Verdict
from .reasoning import EvidenceLedger, Hypothesis


@dataclass(frozen=True)
class QualityDecision:
    publishable: bool
    score: float
    reasons: list[str] = field(default_factory=list)


class FindingQualityGate:
    """Conservative, deterministic final gate before a finding is publishable."""

    def __init__(self, minimum_score: float = 0.90):
        self.minimum_score = minimum_score

    def evaluate(self, hypothesis: Hypothesis, ledger: EvidenceLedger,
                 court: CourtDecision) -> QualityDecision:
        reasons: list[str] = []
        score = 0.0
        if hypothesis.invariant_id:
            score += 0.20
        else:
            reasons.append("hypothesis is not bound to a security invariant")
        if hypothesis.negative_control:
            score += 0.15
        else:
            reasons.append("negative control is missing")
        if ledger.evidence:
            score += 0.15
        else:
            reasons.append("evidence ledger is empty")
        if ledger.reproducible:
            score += 0.15
        else:
            reasons.append("evidence is not reproducible")
        score += 0.20 * ledger.confidence
        if court.verdict == Verdict.CONFIRMED:
            score += 0.15
        else:
            reasons.append(f"court verdict is {court.verdict.value}")
        score = min(score, 1.0)
        publishable = court.verdict == Verdict.CONFIRMED and score >= self.minimum_score
        if not publishable and score < self.minimum_score:
            reasons.append(f"quality score {score:.3f} below threshold {self.minimum_score:.3f}")
        return QualityDecision(publishable, score, reasons)
