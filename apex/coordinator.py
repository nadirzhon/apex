"""Integrated OMEGA research coordinator.

This module wires together hypotheses, persistent task state, cue-activated memory,
adaptive specialist selection, and budget governance. It remains execution-agnostic:
specialists are callbacks supplied by the caller, so APEX can use deterministic
modules or authorized model/tool workers without embedding a hidden network client.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Any

from .ascend.pipeline import AscendPipeline
from .league import LocatedMemory, MemoryItem, Specialist
from .experiments import AdaptivePortfolio, PortfolioChoice
from .task_graph import AttemptResult, ResearchTask, ResearchTaskGraph, TaskBudget, TaskStatus


@dataclass(frozen=True)
class Assignment:
    task_id: str
    hypothesis_id: str
    objective: str
    family: str
    semantic_anchor: str
    specialist: Specialist
    memory: tuple[MemoryItem, ...]
    expected_outcome: str
    negative_control: str


@dataclass(frozen=True)
class SpecialistOutcome:
    progress: dict[str, Any]
    success: bool
    tool_calls: int
    cost_usd: float
    evidence_ids: tuple[str, ...] = ()
    note: str = ""
    reusable_lesson: dict[str, Any] | None = None


SpecialistRunner = Callable[[Assignment], SpecialistOutcome]


@dataclass
class CoordinatorReport:
    rounds: int = 0
    assignments: int = 0
    successes: int = 0
    failures: int = 0
    paused: int = 0
    total_tool_calls: int = 0
    total_cost_usd: float = 0.0
    task_summary: dict[str, Any] = field(default_factory=dict)


class ResearchCoordinator:
    """One bounded research loop over the APEX reasoning stack."""

    def __init__(
        self,
        pipeline: AscendPipeline,
        specialists: Iterable[Specialist],
        *,
        task_budget: TaskBudget | None = None,
        max_parallel: int = 3,
        memory_limit: int = 5,
    ) -> None:
        self.pipeline = pipeline
        self.specialists = tuple(specialists)
        if not self.specialists:
            raise ValueError("at least one specialist is required")
        self.task_budget = task_budget or TaskBudget()
        self.max_parallel = max(1, int(max_parallel))
        self.memory_limit = max(0, int(memory_limit))
        self.graph = ResearchTaskGraph()
        self.memory = LocatedMemory()
        self.portfolio = AdaptivePortfolio(self.specialists)
        self._task_to_hypothesis: dict[str, str] = {}
        self._hypothesis_to_task: dict[str, str] = {}

    def refresh_hypotheses(self) -> list[ResearchTask]:
        """Materialize new pipeline hypotheses as persistent tasks."""
        created: list[ResearchTask] = []
        for hypothesis in self.pipeline.hypothesize():
            if hypothesis.id in self._hypothesis_to_task:
                continue
            task = self.graph.add_hypothesis(hypothesis, budget=self.task_budget)
            self._task_to_hypothesis[task.task_id] = hypothesis.id
            self._hypothesis_to_task[hypothesis.id] = task.task_id
            created.append(task)
        return created

    def assignments(self) -> tuple[Assignment, ...]:
        self.refresh_hypotheses()
        out: list[Assignment] = []
        for task in self.graph.ready():
            if len(out) >= self.max_parallel:
                break
            hypothesis_id = self._task_to_hypothesis[task.task_id]
            cues = self._memory_cues(task)
            memories = tuple(self.memory.activate(cues, exclude_task=task.task_id,
                                                  limit=self.memory_limit))
            choices = self.portfolio.choose(
                family=task.family,
                required_capabilities=task.required_capabilities,
                limit=1,
            )
            if not choices:
                continue
            choice: PortfolioChoice = choices[0]
            out.append(Assignment(
                task_id=task.task_id,
                hypothesis_id=hypothesis_id,
                objective=task.objective,
                family=task.family,
                semantic_anchor=task.semantic_anchor,
                specialist=choice.specialist,
                memory=memories,
                expected_outcome=task.expected_outcome,
                negative_control=task.negative_control,
            ))
        return tuple(out)

    def record(self, assignment: Assignment, outcome: SpecialistOutcome) -> ResearchTask:
        task = self.graph.tasks[assignment.task_id]
        if assignment.semantic_anchor != task.semantic_anchor:
            raise ValueError("assignment semantic anchor is stale")
        updated = self.graph.record_attempt(
            assignment.task_id,
            AttemptResult(
                progress=outcome.progress,
                tool_calls=outcome.tool_calls,
                cost_usd=outcome.cost_usd,
                evidence_ids=outcome.evidence_ids,
                success=outcome.success,
                note=outcome.note,
            ),
            anchor=assignment.semantic_anchor,
        )
        self.portfolio.record(
            family=task.family,
            specialist=assignment.specialist.name,
            success=outcome.success,
            cost_usd=outcome.cost_usd,
        )
        if outcome.reusable_lesson:
            self.memory.add(
                cues=self._memory_cues(task),
                content=outcome.reusable_lesson,
                source_task=task.task_id,
                confidence=0.75 if outcome.success else 0.45,
            )
        return updated

    def run(self, runners: dict[str, SpecialistRunner], *, max_rounds: int = 8) -> CoordinatorReport:
        """Execute a bounded loop using explicitly supplied specialist callbacks."""
        report = CoordinatorReport()
        for _ in range(max(0, int(max_rounds))):
            batch = self.assignments()
            report.rounds += 1
            if not batch:
                break
            made_progress = False
            for assignment in batch:
                runner = runners.get(assignment.specialist.name)
                if runner is None:
                    task = self.graph.tasks[assignment.task_id]
                    task.status = TaskStatus.PAUSED
                    task.notes.append(f"no runner registered for specialist {assignment.specialist.name}")
                    continue
                outcome = runner(assignment)
                before = self.graph.tasks[assignment.task_id].status
                task = self.record(assignment, outcome)
                report.assignments += 1
                report.total_tool_calls += outcome.tool_calls
                report.total_cost_usd += outcome.cost_usd
                if outcome.success:
                    report.successes += 1
                    made_progress = True
                elif task.status == TaskStatus.PAUSED:
                    report.paused += 1
                else:
                    report.failures += 1
                if task.status != before:
                    made_progress = True
            if not made_progress:
                break
        report.task_summary = self.graph.summary()
        report.total_cost_usd = round(report.total_cost_usd, 6)
        return report

    def task_for_hypothesis(self, hypothesis_id: str) -> ResearchTask | None:
        task_id = self._hypothesis_to_task.get(hypothesis_id)
        return self.graph.tasks.get(task_id) if task_id else None

    @staticmethod
    def _memory_cues(task: ResearchTask) -> tuple[str, ...]:
        cues = [task.family.lower()]
        cues.extend(x.lower() for x in task.required_capabilities)
        return tuple(dict.fromkeys(cues))
