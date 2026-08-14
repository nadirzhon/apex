"""Offline benchmark harness for ASCEND reasoning quality.

This module never sends network traffic. It scores hypothesis classification and
publication decisions against synthetic/lab ground truth so regressions become
measurable instead of anecdotal.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    expected_positive: bool
    predicted_positive: bool
    latency_ms: float = 0.0


@dataclass(frozen=True)
class BenchmarkScore:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    mean_latency_ms: float

    @property
    def publication_ready(self) -> bool:
        return self.precision >= 0.95 and self.false_positive_rate <= 0.02


def score(cases: list[BenchmarkCase]) -> BenchmarkScore:
    tp = sum(c.expected_positive and c.predicted_positive for c in cases)
    fp = sum((not c.expected_positive) and c.predicted_positive for c in cases)
    tn = sum((not c.expected_positive) and (not c.predicted_positive) for c in cases)
    fn = sum(c.expected_positive and (not c.predicted_positive) for c in cases)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    latency = sum(max(0.0, c.latency_ms) for c in cases) / len(cases) if cases else 0.0
    return BenchmarkScore(tp, fp, tn, fn, precision, recall, f1, fpr, latency)
