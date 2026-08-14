"""Falsification-first planning for ASCEND hypotheses.

The planner turns a hypothesis into checks designed to disprove it before a finding
can be promoted. Plans are abstract and execution-agnostic; they carry no network
or exploit implementation.
"""
from __future__ import annotations

from dataclasses import dataclass

from .reasoning import Hypothesis


@dataclass(frozen=True)
class FalsificationCheck:
    name: str
    purpose: str
    required: bool = True


@dataclass(frozen=True)
class FalsificationPlan:
    hypothesis_id: str
    checks: tuple[FalsificationCheck, ...]

    @property
    def required_names(self) -> set[str]:
        return {check.name for check in self.checks if check.required}


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    evidence_ids: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class FalsificationVerdict:
    hypothesis_id: str
    survived: bool
    missing: tuple[str, ...]
    failed: tuple[str, ...]
    evidence_ids: tuple[str, ...]


class FalsificationPlanner:
    def plan(self, hypothesis: Hypothesis) -> FalsificationPlan:
        checks = [
            FalsificationCheck("baseline", "establish legitimate expected behavior"),
            FalsificationCheck("negative-control", hypothesis.negative_control or "establish denial/error behavior"),
            FalsificationCheck("repeat", "independently reproduce the observation"),
        ]
        klass = hypothesis.klass.lower()
        if "idor" in klass or "bola" in klass or "tenant" in klass:
            checks.append(FalsificationCheck("identity-swap", "show the behavior depends on principal/ownership boundary"))
        if "bfla" in klass or "privesc" in klass:
            checks.append(FalsificationCheck("role-boundary", "compare allowed and disallowed privilege levels"))
        return FalsificationPlan(hypothesis.id, tuple(checks))

    def evaluate(self, plan: FalsificationPlan, results: list[CheckResult]) -> FalsificationVerdict:
        by_name = {result.name: result for result in results}
        missing = sorted(plan.required_names - set(by_name))
        failed = sorted(name for name in plan.required_names if name in by_name and not by_name[name].passed)
        evidence: list[str] = []
        for result in results:
            evidence.extend(result.evidence_ids)
        return FalsificationVerdict(
            hypothesis_id=plan.hypothesis_id,
            survived=not missing and not failed,
            missing=tuple(missing),
            failed=tuple(failed),
            evidence_ids=tuple(dict.fromkeys(evidence)),
        )
