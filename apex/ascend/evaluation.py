"""Evaluation for blind challenge runs.

A strong system is not one number. We score discovery, precision, calibration,
evidence quality and speed separately, then apply a strict readiness gate.
"""
from __future__ import annotations

from dataclasses import dataclass

from .arena import ChallengeResult


@dataclass(frozen=True)
class ArenaScore:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    evidence_rate: float
    calibration_error: float
    mean_latency_ms: float

    @property
    def ten_of_ten(self) -> bool:
        return (
            self.precision >= 0.98
            and self.recall >= 0.90
            and self.f1 >= 0.94
            and self.evidence_rate >= 0.98
            and self.calibration_error <= 0.08
        )

    @property
    def fifty_of_ten(self) -> bool:
        """A deliberately extreme target so 10/10 becomes the floor, not the dream."""
        return (
            self.precision >= 0.995
            and self.recall >= 0.97
            and self.f1 >= 0.98
            and self.evidence_rate == 1.0
            and self.calibration_error <= 0.03
        )


def _key(klass: str, asset: str) -> tuple[str, str]:
    return klass.strip().lower(), asset.strip().lower()


def score_results(results: list[ChallengeResult]) -> ArenaScore:
    tp = fp = fn = 0
    evidence_hits = reported_total = 0
    calibration_sum = 0.0
    calibration_n = 0
    latencies: list[float] = []

    for result in results:
        truth = {_key(x.klass, x.asset) for x in result.ground_truth}
        reported = {_key(x.klass, x.asset): x for x in result.reported}
        matched = truth & set(reported)
        tp += len(matched)
        fp += len(set(reported) - truth)
        fn += len(truth - set(reported))
        latencies.append(max(0.0, result.latency_ms))

        for key, finding in reported.items():
            reported_total += 1
            if finding.evidence.strip():
                evidence_hits += 1
            y = 1.0 if key in truth else 0.0
            p = min(max(float(finding.confidence), 0.0), 1.0)
            calibration_sum += abs(p - y)
            calibration_n += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    evidence_rate = evidence_hits / reported_total if reported_total else 0.0
    calibration_error = calibration_sum / calibration_n if calibration_n else 0.0
    mean_latency = sum(latencies) / len(latencies) if latencies else 0.0
    return ArenaScore(tp, fp, fn, precision, recall, f1, evidence_rate,
                      calibration_error, mean_latency)
