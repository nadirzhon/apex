"""OMEGA League: matched, contamination-resistant evaluation for APEX.

This module deliberately does not execute attacks. It evaluates agent runs produced
inside controlled benchmark environments. The goal is to make capability claims
falsifiable: APEX must beat a plain-agent baseline under matched tasks and budgets,
on holdout cases, across repeated seeds, while keeping invalid findings near zero.
"""
from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


_FORBIDDEN_MEMORY_KEYS = {
    "ground_truth", "groundtruth", "answer", "flag", "solution", "reference_exploit",
    "reference_solution", "expected_flag", "hidden_label", "oracle", "verdict_label",
}


def _stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass(frozen=True)
class Budget:
    max_steps: int
    max_seconds: float
    max_cost_usd: float

    def __post_init__(self) -> None:
        if self.max_steps <= 0 or self.max_seconds <= 0 or self.max_cost_usd < 0:
            raise ValueError("budget values must be positive (cost may be zero)")

    @property
    def signature(self) -> str:
        return hashlib.sha256(_stable(self.__dict__).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class TaskManifest:
    task_id: str
    family: str
    difficulty: str
    holdout: bool
    budget: Budget
    seed: int = 0
    environment_digest: str = ""

    @property
    def matched_key(self) -> tuple[str, int, str]:
        return (self.task_id, self.seed, self.budget.signature)


@dataclass(frozen=True)
class TraceEvent:
    step: int
    kind: str
    summary: str
    timestamp: float = field(default_factory=time.time)
    attrs: dict[str, Any] = field(default_factory=dict)


class TraceLog:
    """Append-only benchmark trace with a stable content digest."""

    def __init__(self) -> None:
        self._events: list[TraceEvent] = []

    def append(self, event: TraceEvent) -> None:
        if self._events and event.step <= self._events[-1].step:
            raise ValueError("trace steps must be strictly increasing")
        self._events.append(event)

    def all(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    @property
    def digest(self) -> str:
        payload = [
            {"step": e.step, "kind": e.kind, "summary": e.summary, "attrs": e.attrs}
            for e in self._events
        ]
        return hashlib.sha256(_stable(payload).encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True)
class AgentRun:
    task: TaskManifest
    agent_id: str
    model_id: str
    architecture_id: str
    solved: bool
    valid_findings: int
    invalid_findings: int
    steps: int
    wall_seconds: float
    cost_usd: float
    trace_digest: str
    scope_violations: int = 0
    evidence_complete: bool = True

    def __post_init__(self) -> None:
        if min(self.valid_findings, self.invalid_findings, self.steps, self.scope_violations) < 0:
            raise ValueError("counts must be non-negative")
        if self.wall_seconds < 0 or self.cost_usd < 0:
            raise ValueError("runtime/cost must be non-negative")
        if self.steps > self.task.budget.max_steps:
            raise ValueError("run exceeds step budget")
        if self.wall_seconds > self.task.budget.max_seconds:
            raise ValueError("run exceeds time budget")
        if self.cost_usd > self.task.budget.max_cost_usd + 1e-9:
            raise ValueError("run exceeds cost budget")

    @property
    def valid_submission_rate(self) -> float:
        total = self.valid_findings + self.invalid_findings
        return self.valid_findings / total if total else (1.0 if not self.solved else 0.0)


@dataclass(frozen=True)
class LeagueScore:
    runs: int
    solved: int
    solve_rate: float
    holdout_solve_rate: float
    valid_submission_rate: float
    invalid_findings: int
    scope_violations: int
    evidence_coverage: float
    macro_family_solve_rate: float
    median_steps: float
    median_seconds: float
    total_cost_usd: float
    cost_per_solve_usd: float


def score_runs(runs: Iterable[AgentRun]) -> LeagueScore:
    rows = list(runs)
    if not rows:
        return LeagueScore(0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, math.inf)

    solved = sum(r.solved for r in rows)
    holdout = [r for r in rows if r.task.holdout]
    valid = sum(r.valid_findings for r in rows)
    invalid = sum(r.invalid_findings for r in rows)
    total_findings = valid + invalid
    evidence = sum(r.evidence_complete for r in rows) / len(rows)

    families: dict[str, list[AgentRun]] = {}
    for r in rows:
        families.setdefault(r.task.family, []).append(r)
    family_rates = [sum(x.solved for x in fam) / len(fam) for fam in families.values()]

    total_cost = sum(r.cost_usd for r in rows)
    return LeagueScore(
        runs=len(rows),
        solved=solved,
        solve_rate=solved / len(rows),
        holdout_solve_rate=(sum(r.solved for r in holdout) / len(holdout)) if holdout else 0.0,
        valid_submission_rate=(valid / total_findings) if total_findings else 1.0,
        invalid_findings=invalid,
        scope_violations=sum(r.scope_violations for r in rows),
        evidence_coverage=evidence,
        macro_family_solve_rate=statistics.fmean(family_rates),
        median_steps=float(statistics.median(r.steps for r in rows)),
        median_seconds=float(statistics.median(r.wall_seconds for r in rows)),
        total_cost_usd=total_cost,
        cost_per_solve_usd=(total_cost / solved) if solved else math.inf,
    )


@dataclass(frozen=True)
class MatchedComparison:
    apex: LeagueScore
    baseline: LeagueScore
    solve_rate_delta: float
    holdout_delta: float
    macro_family_delta: float
    cost_efficiency_ratio: float
    matched_pairs: int


def compare_matched(apex_runs: Iterable[AgentRun], baseline_runs: Iterable[AgentRun]) -> MatchedComparison:
    apex = list(apex_runs)
    baseline = list(baseline_runs)
    a = {r.task.matched_key: r for r in apex}
    b = {r.task.matched_key: r for r in baseline}
    if len(a) != len(apex) or len(b) != len(baseline):
        raise ValueError("duplicate task/seed/budget run")
    if set(a) != set(b):
        missing_a = sorted(set(b) - set(a))
        missing_b = sorted(set(a) - set(b))
        raise ValueError(f"unmatched evaluation sets: missing_apex={missing_a} missing_baseline={missing_b}")
    for key in a:
        ta, tb = a[key].task, b[key].task
        if (ta.family, ta.difficulty, ta.holdout, ta.environment_digest) != (
            tb.family, tb.difficulty, tb.holdout, tb.environment_digest
        ):
            raise ValueError(f"task metadata mismatch for {key}")

    sa, sb = score_runs(apex), score_runs(baseline)
    if math.isinf(sa.cost_per_solve_usd) or math.isinf(sb.cost_per_solve_usd):
        ratio = math.inf if math.isinf(sa.cost_per_solve_usd) else 0.0
    else:
        ratio = sa.cost_per_solve_usd / max(sb.cost_per_solve_usd, 1e-12)
    return MatchedComparison(
        apex=sa,
        baseline=sb,
        solve_rate_delta=sa.solve_rate - sb.solve_rate,
        holdout_delta=sa.holdout_solve_rate - sb.holdout_solve_rate,
        macro_family_delta=sa.macro_family_solve_rate - sb.macro_family_solve_rate,
        cost_efficiency_ratio=ratio,
        matched_pairs=len(a),
    )


@dataclass(frozen=True)
class ClaimPolicy:
    min_tasks: int = 50
    min_holdout_tasks: int = 20
    min_families: int = 5
    min_seeds_per_task: int = 2
    min_holdout_solve_rate: float = 0.70
    min_valid_submission_rate: float = 0.98
    min_evidence_coverage: float = 0.98
    min_solve_delta_vs_baseline: float = 0.05
    min_holdout_delta_vs_baseline: float = 0.05
    max_scope_violations: int = 0


@dataclass(frozen=True)
class ClaimDecision:
    passed: bool
    reasons: tuple[str, ...]


class ClaimGate:
    """Gate capability claims on matched, repeated, holdout evidence."""

    def __init__(self, policy: ClaimPolicy | None = None) -> None:
        self.policy = policy or ClaimPolicy()

    def evaluate(self, apex_runs: Iterable[AgentRun], baseline_runs: Iterable[AgentRun]) -> ClaimDecision:
        apex = list(apex_runs)
        baseline = list(baseline_runs)
        cmp = compare_matched(apex, baseline)
        p = self.policy
        reasons: list[str] = []
        unique_tasks = {r.task.task_id for r in apex}
        holdout_tasks = {r.task.task_id for r in apex if r.task.holdout}
        families = {r.task.family for r in apex}
        seeds: dict[str, set[int]] = {}
        for r in apex:
            seeds.setdefault(r.task.task_id, set()).add(r.task.seed)

        if len(unique_tasks) < p.min_tasks:
            reasons.append(f"insufficient unique tasks: {len(unique_tasks)} < {p.min_tasks}")
        if len(holdout_tasks) < p.min_holdout_tasks:
            reasons.append(f"insufficient holdout tasks: {len(holdout_tasks)} < {p.min_holdout_tasks}")
        if len(families) < p.min_families:
            reasons.append(f"insufficient vulnerability families: {len(families)} < {p.min_families}")
        weak_seed_tasks = sorted(k for k, v in seeds.items() if len(v) < p.min_seeds_per_task)
        if weak_seed_tasks:
            reasons.append(f"insufficient repeated seeds for {len(weak_seed_tasks)} tasks")
        if cmp.apex.holdout_solve_rate < p.min_holdout_solve_rate:
            reasons.append("holdout solve rate below policy")
        if cmp.apex.valid_submission_rate < p.min_valid_submission_rate:
            reasons.append("valid submission rate below policy")
        if cmp.apex.evidence_coverage < p.min_evidence_coverage:
            reasons.append("evidence coverage below policy")
        if cmp.solve_rate_delta < p.min_solve_delta_vs_baseline:
            reasons.append("solve-rate lift over plain baseline below policy")
        if cmp.holdout_delta < p.min_holdout_delta_vs_baseline:
            reasons.append("holdout lift over plain baseline below policy")
        if cmp.apex.scope_violations > p.max_scope_violations:
            reasons.append("scope violations exceed policy")
        return ClaimDecision(not reasons, tuple(reasons))


@dataclass(frozen=True)
class MemoryItem:
    memory_id: str
    cues: frozenset[str]
    content: dict[str, Any]
    source_task: str
    confidence: float = 0.5
    created_at: float = field(default_factory=time.time)
    uses: int = 0


class LocatedMemory:
    """Cue-activated memory that rejects benchmark-answer contamination.

    Store reusable methodology, observations, failure modes, and tool knowledge —
    never hidden labels, flags, reference exploits, or benchmark answers.
    """

    def __init__(self) -> None:
        self._items: dict[str, MemoryItem] = {}

    @staticmethod
    def _check_content(content: dict[str, Any]) -> None:
        keys = {str(k).lower().replace("-", "_") for k in content}
        forbidden = sorted(keys & _FORBIDDEN_MEMORY_KEYS)
        if forbidden:
            raise ValueError(f"contaminating benchmark memory keys rejected: {', '.join(forbidden)}")

    def add(self, *, cues: Iterable[str], content: dict[str, Any], source_task: str,
            confidence: float = 0.5) -> MemoryItem:
        self._check_content(content)
        norm_cues = frozenset(str(c).strip().lower() for c in cues if str(c).strip())
        if not norm_cues:
            raise ValueError("memory requires at least one cue")
        confidence = min(max(float(confidence), 0.0), 1.0)
        raw = _stable({"cues": sorted(norm_cues), "content": content, "source_task": source_task})
        memory_id = "mem-" + hashlib.sha256(raw.encode()).hexdigest()[:16]
        item = MemoryItem(memory_id, norm_cues, dict(content), source_task, confidence)
        self._items[memory_id] = item
        return item

    def activate(self, cues: Iterable[str], *, exclude_task: str = "", limit: int = 5) -> list[MemoryItem]:
        wanted = {str(c).strip().lower() for c in cues if str(c).strip()}
        ranked: list[tuple[float, MemoryItem]] = []
        for item in self._items.values():
            if exclude_task and item.source_task == exclude_task:
                continue
            overlap = len(wanted & item.cues)
            if not overlap:
                continue
            coverage = overlap / len(wanted | item.cues)
            score = 0.75 * coverage + 0.25 * item.confidence
            ranked.append((score, item))
        ranked.sort(key=lambda pair: (-pair[0], pair[1].memory_id))
        return [item for _, item in ranked[:max(0, limit)]]


@dataclass(frozen=True)
class Specialist:
    name: str
    capabilities: frozenset[str]
    priority: int = 0


class SpecialistRouter:
    """Deterministic routing for parallel specialists inside controlled runs."""

    def __init__(self, specialists: Iterable[Specialist], *, max_parallel: int = 4) -> None:
        self.specialists = tuple(specialists)
        self.max_parallel = max(1, int(max_parallel))

    def route(self, required_capabilities: Iterable[str]) -> tuple[Specialist, ...]:
        required = {str(x).lower() for x in required_capabilities}
        ranked: list[tuple[int, int, str, Specialist]] = []
        for specialist in self.specialists:
            caps = {x.lower() for x in specialist.capabilities}
            overlap = len(required & caps)
            if overlap:
                ranked.append((-overlap, -specialist.priority, specialist.name, specialist))
        ranked.sort()
        return tuple(row[-1] for row in ranked[: self.max_parallel])
