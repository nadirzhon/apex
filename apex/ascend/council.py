"""Independent reasoning council for hypothesis triage.

The council does not generate traffic. Multiple strategies inspect different model
signals and vote independently so one heuristic cannot promote a hypothesis alone.
"""
from __future__ import annotations

from dataclasses import dataclass

from .awm import AWM
from .causal_model import ProvenanceWorldModel
from .digital_twin import DigitalTwin
from .reasoning import Hypothesis


@dataclass(frozen=True)
class ReasoningVote:
    strategy: str
    support: float
    rationale: str


@dataclass(frozen=True)
class CouncilDecision:
    hypothesis_id: str
    support: float
    quorum: int
    votes: tuple[ReasoningVote, ...]

    @property
    def admitted(self) -> bool:
        positive = sum(v.support >= 0.60 for v in self.votes)
        return positive >= self.quorum and self.support >= 0.60


class StructuralStrategy:
    name = "structural"

    def vote(self, hypothesis: Hypothesis, awm: AWM, twin: DigitalTwin,
             world: ProvenanceWorldModel) -> ReasoningVote:
        node = awm.nodes.get(hypothesis.node_key)
        if node and node.params:
            return ReasoningVote(self.name, 0.75, "object/role structure exposes a testable boundary")
        return ReasoningVote(self.name, 0.25, "no strong structural boundary")


class SemanticStrategy:
    name = "semantic"

    def vote(self, hypothesis: Hypothesis, awm: AWM, twin: DigitalTwin,
             world: ProvenanceWorldModel) -> ReasoningVote:
        endpoint = twin.endpoints.get(hypothesis.node_key)
        if endpoint and (endpoint.tenant_scoped or endpoint.object_params or endpoint.privilege > 0):
            return ReasoningVote(self.name, 0.70, "semantic model contains authorization-sensitive attributes")
        return ReasoningVote(self.name, 0.30, "semantic model has weak authorization signal")


class ProvenanceStrategy:
    name = "provenance"

    def vote(self, hypothesis: Hypothesis, awm: AWM, twin: DigitalTwin,
             world: ProvenanceWorldModel) -> ReasoningVote:
        node = awm.nodes.get(hypothesis.node_key)
        target = node.url if node else hypothesis.node_key
        actors = {obs.actor for obs in world.log.all() if obs.target == target}
        if len(actors) >= 2:
            return ReasoningVote(self.name, 0.80, "multiple principals observed on the same target")
        if actors:
            return ReasoningVote(self.name, 0.45, "only one principal observed; needs contrast")
        return ReasoningVote(self.name, 0.20, "no provenance observations yet")


class ReasoningCouncil:
    def __init__(self, strategies=None, quorum: int = 2) -> None:
        self.strategies = list(strategies or [StructuralStrategy(), SemanticStrategy(), ProvenanceStrategy()])
        self.quorum = max(1, int(quorum))

    def deliberate(self, hypothesis: Hypothesis, awm: AWM, twin: DigitalTwin,
                   world: ProvenanceWorldModel) -> CouncilDecision:
        votes = tuple(strategy.vote(hypothesis, awm, twin, world) for strategy in self.strategies)
        support = sum(v.support for v in votes) / len(votes) if votes else 0.0
        return CouncilDecision(hypothesis.id, support, self.quorum, votes)
