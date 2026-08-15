"""Research-grade attribution utilities for OMEGA League.

These primitives help answer a harder question than "did APEX score well?":
which architectural components actually caused the lift over a matched baseline?
No network or exploit execution lives here.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable

from .league import AgentRun, MatchedComparison, Specialist, compare_matched


@dataclass(frozen=True)
class ProportionInterval:
    estimate: float
    low: float
    high: float


def wilson_interval(successes: int, total: int, *, z: float = 1.959963984540054) -> ProportionInterval:
    if total <= 0:
        return ProportionInterval(0.0, 0.0, 1.0)
    if successes < 0 or successes > total:
        raise ValueError("successes must be in [0,total]")
    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z2 / (4 * total)) / total) / denom
    return ProportionInterval(p, max(0.0, center - margin), min(1.0, center + margin))


@dataclass(frozen=True)
class PairedSignificance:
    apex_only: int
    baseline_only: int
    discordant: int
    exact_p_value: float


def mcnemar_exact(apex_runs: Iterable[AgentRun], baseline_runs: Iterable[AgentRun]) -> PairedSignificance:
    apex = {r.task.matched_key: r for r in apex_runs}
    base = {r.task.matched_key: r for r in baseline_runs}
    if set(apex) != set(base):
        raise ValueError("paired significance requires identical matched keys")
    apex_only = sum(apex[k].solved and not base[k].solved for k in apex)
    base_only = sum(base[k].solved and not apex[k].solved for k in apex)
    n = apex_only + base_only
    if n == 0:
        p = 1.0
    else:
        tail = sum(math.comb(n, i) for i in range(0, min(apex_only, base_only) + 1)) / (2 ** n)
        p = min(1.0, 2 * tail)
    return PairedSignificance(apex_only, base_only, n, p)


@dataclass(frozen=True)
class VariantResult:
    variant: str
    comparison_to_baseline: MatchedComparison
    comparison_to_full: MatchedComparison | None
    significance_vs_baseline: PairedSignificance


class AblationStudy:
    """Require all variants to run on the same matched evaluation matrix."""

    def __init__(self, baseline_runs: Iterable[AgentRun], full_runs: Iterable[AgentRun]) -> None:
        self.baseline = tuple(baseline_runs)
        self.full = tuple(full_runs)
        compare_matched(self.full, self.baseline)  # validates matching immediately

    def evaluate(self, variant: str, runs: Iterable[AgentRun]) -> VariantResult:
        rows = tuple(runs)
        vs_base = compare_matched(rows, self.baseline)
        vs_full = None if variant == "full" else compare_matched(self.full, rows)
        sig = mcnemar_exact(rows, self.baseline)
        return VariantResult(variant, vs_base, vs_full, sig)


@dataclass
class ArmStats:
    successes: int = 0
    failures: int = 0
    total_cost: float = 0.0

    @property
    def trials(self) -> int:
        return self.successes + self.failures

    @property
    def mean_success(self) -> float:
        return (self.successes + 1) / (self.trials + 2)  # Beta(1,1) posterior mean

    @property
    def mean_cost(self) -> float:
        return self.total_cost / self.trials if self.trials else 1.0


@dataclass(frozen=True)
class PortfolioChoice:
    specialist: Specialist
    score: float


class AdaptivePortfolio:
    """Budget-aware specialist selector for controlled benchmark runs.

    It learns only aggregate success/cost statistics by vulnerability family; no
    benchmark labels or solutions are stored. Exploration pressure prevents one
    early-winning specialist from monopolizing all future tasks.
    """

    def __init__(self, specialists: Iterable[Specialist], *, exploration: float = 0.35) -> None:
        self.specialists = tuple(specialists)
        self.exploration = max(0.0, float(exploration))
        self._stats: dict[tuple[str, str], ArmStats] = {}

    def record(self, *, family: str, specialist: str, success: bool, cost_usd: float) -> None:
        if cost_usd < 0:
            raise ValueError("cost must be non-negative")
        key = (family.lower(), specialist)
        stats = self._stats.setdefault(key, ArmStats())
        if success:
            stats.successes += 1
        else:
            stats.failures += 1
        stats.total_cost += cost_usd

    def choose(self, *, family: str, required_capabilities: Iterable[str], limit: int = 2) -> tuple[PortfolioChoice, ...]:
        family = family.lower()
        required = {x.lower() for x in required_capabilities}
        total_trials = 1 + sum(s.trials for (fam, _), s in self._stats.items() if fam == family)
        ranked: list[PortfolioChoice] = []
        for specialist in self.specialists:
            caps = {x.lower() for x in specialist.capabilities}
            overlap = len(required & caps)
            if not overlap:
                continue
            stats = self._stats.get((family, specialist.name), ArmStats())
            exploit = stats.mean_success / max(stats.mean_cost, 0.05)
            explore = self.exploration * math.sqrt(math.log(total_trials + 1) / (stats.trials + 1))
            capability_bonus = overlap / max(len(required), 1)
            score = exploit + explore + 0.15 * capability_bonus + 0.01 * specialist.priority
            ranked.append(PortfolioChoice(specialist, score))
        ranked.sort(key=lambda x: (-x.score, x.specialist.name))
        return tuple(ranked[: max(0, int(limit))])
