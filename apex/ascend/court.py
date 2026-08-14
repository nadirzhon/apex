"""Adversarial review gate for hypothesis evidence.

The court separates an interesting signal from a publishable finding. It requires
scope, reproducibility, sufficient posterior confidence, and no unresolved skeptic
objections. This is a quality gate, not an execution engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .reasoning import EvidenceLedger, Hypothesis


class Verdict(str, Enum):
    REJECTED = "rejected"
    PROVISIONAL = "provisional"
    CONFIRMED = "confirmed"


@dataclass
class CourtDecision:
    hypothesis_id: str
    verdict: Verdict
    confidence: float
    reasons: list[str] = field(default_factory=list)


class AdversarialCourt:
    def __init__(self, confirmation_threshold: float = 0.90):
        self.confirmation_threshold = confirmation_threshold

    def review(
        self,
        hypothesis: Hypothesis,
        ledger: EvidenceLedger,
        *,
        scope_ok: bool,
        independently_reproduced: bool,
        skeptic_objections: list[str] | None = None,
    ) -> CourtDecision:
        objections = [o.strip() for o in (skeptic_objections or []) if o.strip()]
        reasons: list[str] = []

        if not scope_ok:
            return CourtDecision(
                hypothesis.id,
                Verdict.REJECTED,
                ledger.confidence,
                ["scope/policy gate failed"],
            )
        if ledger.confidence < 0.50:
            return CourtDecision(
                hypothesis.id,
                Verdict.REJECTED,
                ledger.confidence,
                ["evidence weighs against the hypothesis"],
            )
        if not independently_reproduced:
            reasons.append("independent reproduction missing")
        if objections:
            reasons.append("unresolved skeptic objections: " + "; ".join(objections))
        if ledger.confidence < self.confirmation_threshold:
            reasons.append(
                f"confidence {ledger.confidence:.3f} below threshold "
                f"{self.confirmation_threshold:.3f}"
            )
        if reasons:
            return CourtDecision(hypothesis.id, Verdict.PROVISIONAL, ledger.confidence, reasons)
        return CourtDecision(
            hypothesis.id,
            Verdict.CONFIRMED,
            ledger.confidence,
            ["scope, evidence, skepticism and reproduction gates passed"],
        )
