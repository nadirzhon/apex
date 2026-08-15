"""Offline scope, severity and evidence-quality checks for APEX findings."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import Finding
from .scope import Scope

if TYPE_CHECKING:
    from .orchestrator import AgentContext

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


@dataclass(frozen=True)
class QualityReview:
    fingerprint: str
    score: int
    status: str
    notes: tuple[str, ...]


def review(finding: Finding) -> QualityReview:
    score = 0
    notes: list[str] = []

    if finding.target:
        score += 10
    else:
        notes.append("не указана точная цель")
    if finding.module:
        score += 5
    if finding.description and len(finding.description.strip()) >= 30:
        score += 15
    else:
        notes.append("описание слишком короткое")
    if finding.evidence and len(finding.evidence.strip()) >= 20:
        score += 25
    else:
        notes.append("нет достаточного воспроизводимого доказательства")
    if finding.remediation:
        score += 10
    else:
        notes.append("нет рекомендации по исправлению")
    if finding.cvss_vector and finding.cvss_score:
        score += 10
    else:
        notes.append("не обоснована серьёзность")
    if finding.references:
        score += 5
    else:
        notes.append("нет ссылок на стандарт или правила программы")

    evidence = finding.evidence.lower()
    if any(marker in evidence for marker in ("get ", "post ", "→", "status=", "http ")):
        score += 10
    else:
        notes.append("доказательство не содержит запроса или статуса ответа")
    if finding.target and finding.target.lower() in evidence:
        score += 5
    else:
        notes.append("цель не связана с доказательством")
    if 40 <= len(finding.evidence) <= 4000:
        score += 5

    # Полнота отчёта не доказывает уязвимость: статус всегда требует человека.
    if score >= 80:
        status = "ready_for_human_review"
    elif score >= 55:
        status = "needs_confirmation"
    else:
        status = "insufficient_evidence"

    return QualityReview(
        fingerprint=finding.fingerprint(),
        score=min(score, 100),
        status=status,
        notes=tuple(notes),
    )


def run(context: "AgentContext") -> list[Finding]:
    """Обновить метаданные существующих кандидатов, не создавая новых."""
    for finding in context.store.findings:
        result = review(finding)
        finding.quality_score = result.score
        finding.review_status = result.status
        finding.review_notes = list(result.notes)
    return []
