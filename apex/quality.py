"""Offline quality checks for APEX result records."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding
from .scope import Scope

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class QualityResult:
    accepted: bool
    reasons: tuple[str, ...]


def check(scope: Scope, finding: Finding, minimum_severity: str = "medium") -> QualityResult:
    if minimum_severity not in _RANK:
        raise ValueError(f"unknown minimum severity: {minimum_severity}")
    reasons: list[str] = []
    if not scope.in_scope_target(finding.target):
        reasons.append("outside scope")
    if _RANK.get(finding.severity, -1) < _RANK[minimum_severity]:
        reasons.append("below severity threshold")
    if len((finding.evidence or "").strip()) < 12:
        reasons.append("missing reproducible evidence")
    if not (finding.description or "").strip():
        reasons.append("missing description")
    return QualityResult(not reasons, tuple(reasons))
