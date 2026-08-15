"""Модели данных: серьёзность, находки, активы + калькулятор CVSS 3.1."""
from __future__ import annotations

import math
import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score == 0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 base score (без зависимостей). Формулы — спецификация FIRST.
# ─────────────────────────────────────────────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}          # при S:U; для S:C L/H корректируются
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss31_base(vector: str) -> tuple[float, str]:
    """Вектор вида 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' → (score, severity)."""
    m: dict[str, str] = {}
    for part in vector.replace("CVSS:3.1/", "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    try:
        scope_changed = m["S"] == "C"
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_C if scope_changed else _PR)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as e:  # неполный/битый вектор
        raise ValueError(f"неполный CVSS-вектор, нет метрики {e}") from e

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploit), 10))
    else:
        base = _roundup(min(impact + exploit, 10))
    return base, Severity.from_cvss(base).value


def _roundup(x: float) -> float:
    """Round-half-up до одного знака, как в спецификации CVSS 3.1."""
    return math.ceil(x * 10) / 10.0


@dataclass
class Asset:
    kind: str                       # host | url | api | apk
    value: str
    source: str = "scope"
    meta: dict[str, Any] = field(default_factory=dict)
    added: float = field(default_factory=time.time)

    def key(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass
class Finding:
    title: str
    severity: str                   # значение Severity
    target: str                     # где найдено
    module: str                     # какой модуль нашёл
    description: str = ""
    evidence: str = ""              # воспроизводимое доказательство
    remediation: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    references: list[str] = field(default_factory=list)
    found_at: float = field(default_factory=time.time)
    quality_score: int = 0
    review_status: str = "unreviewed"
    review_notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.cvss_vector and not self.cvss_score:
            try:
                self.cvss_score, self.severity = cvss31_base(self.cvss_vector)
            except ValueError:
                pass

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        """Стабильный ID для дедупликации между повторными запусками."""
        canonical = "\x1f".join((
            self.module.strip().lower(),
            self.title.strip().lower(),
            self.target.strip().lower().rstrip("/"),
        ))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
