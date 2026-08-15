"""Persistent research task graph and budget governance for APEX.

This module addresses context loss, semantic drift, and wasted loops. It does not
execute tools itself. It keeps research objectives explicit, dependency-aware, and
bounded by configurable cost/call/attempt policies.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .ascend.reasoning import Hypothesis


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass(frozen=True)
class TaskBudget:
    max_tool_calls: int = 40
    max_cost_usd: float = 0.30
    max_attempts: int = 8
    stagnation_limit: int = 3

    def __post_init__(self) -> None:
        if min(self.max_tool_calls, self.max_attempts, self.stagnation_limit) <= 0:
            raise ValueError("call/attempt/stagnation budgets must be positive")
        if self.max_cost_usd < 0:
            raise ValueError("cost budget must be non-negative")


@dataclass
class ResearchTask:
    task_id: str
    objective: str
    family: str
    expected_outcome: str = ""
    negative_control: str = ""
    required_capabilities: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    budget: TaskBudget = field(default_factory=TaskBudget)
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    progress_fingerprints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def semantic_anchor(self) -> str:
        raw = _stable({
            "objective": self.objective,
            "family": self.family,
            "expected_outcome": self.expected_outcome,
            "negative_control": self.negative_control,
            "required_capabilities": self.required_capabilities,
        })
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    @property
    def stagnant(self) -> bool:
        n = self.budget.stagnation_limit
        if len(self.progress_fingerprints) < n:
            return False
        tail = self.progress_fingerprints[-n:]
        return len(set(tail)) == 1

    @property
    def exhausted(self) -> bool:
        return (
            self.tool_calls >= self.budget.max_tool_calls
            or self.cost_usd >= self.budget.max_cost_usd
            or self.attempts >= self.budget.max_attempts
        )


@dataclass(frozen=True)
class AttemptResult:
    progress: dict[str, Any]
    tool_calls: int = 0
    cost_usd: float = 0.0
    evidence_ids: tuple[str, ...] = ()
    success: bool = False
    note: str = ""


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str


class BudgetGovernor:
    def can_continue(self, task: ResearchTask) -> BudgetDecision:
        if task.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}:
            return BudgetDecision(False, f"task already terminal: {task.status.value}")
        if task.stagnant:
            return BudgetDecision(False, "stagnation threshold reached")
        if task.tool_calls >= task.budget.max_tool_calls:
            return BudgetDecision(False, "tool-call budget exhausted")
        if task.cost_usd >= task.budget.max_cost_usd:
            return BudgetDecision(False, "cost budget exhausted")
        if task.attempts >= task.budget.max_attempts:
            return BudgetDecision(False, "attempt budget exhausted")
        return BudgetDecision(True, "within budget")


class ResearchTaskGraph:
    """Dependency-aware persistent task graph with anti-drift anchors."""

    def __init__(self) -> None:
        self.tasks: dict[str, ResearchTask] = {}
        self.governor = BudgetGovernor()

    def add(self, task: ResearchTask) -> ResearchTask:
        if task.task_id in self.tasks:
            raise ValueError(f"duplicate task id: {task.task_id}")
        self.tasks[task.task_id] = task
        return task

    def add_hypothesis(self, hypothesis: Hypothesis, *, budget: TaskBudget | None = None,
                       dependencies: Iterable[str] = ()) -> ResearchTask:
        task = ResearchTask(
            task_id=f"task-{hypothesis.id}",
            objective=hypothesis.description,
            family=hypothesis.klass,
            expected_outcome=hypothesis.expected_outcome,
            negative_control=hypothesis.negative_control,
            required_capabilities=self._capabilities_for(hypothesis),
            dependencies=tuple(dependencies),
            budget=budget or TaskBudget(),
        )
        return self.add(task)

    def validate_dependencies(self) -> None:
        for task in self.tasks.values():
            missing = [dep for dep in task.dependencies if dep not in self.tasks]
            if missing:
                raise ValueError(f"task {task.task_id} has missing dependencies: {missing}")
        # cycle detection
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visited:
                return
            if task_id in visiting:
                raise ValueError(f"dependency cycle detected at {task_id}")
            visiting.add(task_id)
            for dep in self.tasks[task_id].dependencies:
                visit(dep)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in self.tasks:
            visit(task_id)

    def ready(self) -> list[ResearchTask]:
        self.validate_dependencies()
        out: list[ResearchTask] = []
        for task in self.tasks.values():
            if task.status not in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.PAUSED}:
                continue
            if not all(self.tasks[d].status == TaskStatus.SUCCEEDED for d in task.dependencies):
                continue
            if self.governor.can_continue(task).allowed:
                out.append(task)
        out.sort(key=self._priority_key)
        return out

    def record_attempt(self, task_id: str, result: AttemptResult, *, anchor: str) -> ResearchTask:
        task = self.tasks[task_id]
        if anchor != task.semantic_anchor:
            raise ValueError("semantic anchor mismatch: task objective drift detected")
        decision = self.governor.can_continue(task)
        if not decision.allowed:
            task.status = TaskStatus.PAUSED
            task.notes.append(decision.reason)
            return task
        if result.tool_calls < 0 or result.cost_usd < 0:
            raise ValueError("attempt usage must be non-negative")
        if task.tool_calls + result.tool_calls > task.budget.max_tool_calls:
            task.status = TaskStatus.PAUSED
            task.notes.append("attempt would exceed tool-call budget")
            return task
        if task.cost_usd + result.cost_usd > task.budget.max_cost_usd + 1e-12:
            task.status = TaskStatus.PAUSED
            task.notes.append("attempt would exceed cost budget")
            return task

        task.status = TaskStatus.RUNNING
        task.attempts += 1
        task.tool_calls += result.tool_calls
        task.cost_usd += result.cost_usd
        fingerprint = hashlib.sha256(_stable(result.progress).encode()).hexdigest()[:20]
        task.progress_fingerprints.append(fingerprint)
        task.evidence_ids.extend(x for x in result.evidence_ids if x not in task.evidence_ids)
        if result.note:
            task.notes.append(result.note)
        if result.success:
            task.status = TaskStatus.SUCCEEDED
        elif task.stagnant or task.exhausted:
            task.status = TaskStatus.PAUSED
            if task.stagnant:
                task.notes.append("auto-paused: repeated progress fingerprint")
            elif task.exhausted:
                task.notes.append("auto-paused: budget exhausted")
        return task

    def fail(self, task_id: str, reason: str) -> ResearchTask:
        task = self.tasks[task_id]
        task.status = TaskStatus.FAILED
        task.notes.append(reason)
        return task

    def replan(self, task_id: str, *, objective: str | None = None,
               expected_outcome: str | None = None, negative_control: str | None = None) -> str:
        """Explicitly change a semantic goal and return its new anchor."""
        task = self.tasks[task_id]
        if objective is not None:
            task.objective = objective
        if expected_outcome is not None:
            task.expected_outcome = expected_outcome
        if negative_control is not None:
            task.negative_control = negative_control
        task.status = TaskStatus.PENDING
        task.progress_fingerprints.clear()
        task.notes.append("explicit semantic replan")
        return task.semantic_anchor

    def summary(self) -> dict[str, Any]:
        counts = {status.value: 0 for status in TaskStatus}
        for task in self.tasks.values():
            counts[task.status.value] += 1
        return {
            "tasks": len(self.tasks),
            "status": counts,
            "tool_calls": sum(t.tool_calls for t in self.tasks.values()),
            "cost_usd": round(sum(t.cost_usd for t in self.tasks.values()), 6),
            "evidence_ids": len({e for t in self.tasks.values() for e in t.evidence_ids}),
        }

    @staticmethod
    def _priority_key(task: ResearchTask) -> tuple[int, float, str]:
        # Tasks closer to budget exhaustion get deprioritized; fewer attempts first.
        remaining_calls = task.budget.max_tool_calls - task.tool_calls
        return (task.attempts, -remaining_calls, task.task_id)

    @staticmethod
    def _capabilities_for(hypothesis: Hypothesis) -> tuple[str, ...]:
        klass = hypothesis.klass.lower()
        caps = ["web", "reasoning"]
        if any(x in klass for x in ("idor", "bola", "tenant", "access")):
            caps.append("access-control")
        if any(x in klass for x in ("workflow", "state", "chain")):
            caps.append("workflow")
        if any(x in klass for x in ("bfla", "privesc", "role")):
            caps.append("privilege")
        return tuple(dict.fromkeys(caps))
