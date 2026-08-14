"""Causal/provenance layer above the semantic Digital Twin.

This module infers only conservative relations from recorded observations. It does
not send requests and does not treat correlation as a confirmed vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .observations import Observation, ObservationLog


@dataclass(frozen=True)
class CausalEdge:
    cause: str
    effect: str
    relation: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()


@dataclass
class CausalState:
    key: str
    actors: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    observation_ids: list[str] = field(default_factory=list)


class ProvenanceWorldModel:
    """State-transition knowledge graph grounded in immutable observations."""

    def __init__(self, log: ObservationLog | None = None) -> None:
        self.log = log or ObservationLog()
        self.states: dict[str, CausalState] = {}
        self.edges: list[CausalEdge] = []

    def ingest(self, observation: Observation) -> Observation:
        obs = self.log.append(observation)
        for state_key in (obs.state_before, obs.state_after):
            if not state_key:
                continue
            state = self.states.setdefault(state_key, CausalState(state_key))
            state.actors.add(obs.actor)
            state.targets.add(obs.target)
            if obs.id not in state.observation_ids:
                state.observation_ids.append(obs.id)
        if obs.state_before and obs.state_after and obs.state_before != obs.state_after:
            self._add_edge(CausalEdge(
                cause=obs.state_before,
                effect=obs.state_after,
                relation=obs.action or obs.kind,
                confidence=1.0,
                evidence_ids=(obs.id,),
            ))
        return obs

    def _add_edge(self, edge: CausalEdge) -> None:
        for current in self.edges:
            if current.cause == edge.cause and current.effect == edge.effect and current.relation == edge.relation:
                return
        self.edges.append(edge)

    def transitions_for_actor(self, actor: str) -> list[CausalEdge]:
        allowed: set[str] = set()
        for state in self.states.values():
            if actor in state.actors:
                allowed.add(state.key)
        return [edge for edge in self.edges if edge.cause in allowed or edge.effect in allowed]

    def contrasting_observations(self, target: str, actor_a: str, actor_b: str) -> list[tuple[Observation, Observation]]:
        a = [o for o in self.log.all() if o.target == target and o.actor == actor_a]
        b = [o for o in self.log.all() if o.target == target and o.actor == actor_b]
        pairs: list[tuple[Observation, Observation]] = []
        for left in a:
            for right in b:
                if left.action == right.action:
                    pairs.append((left, right))
        return pairs

    def summary(self) -> dict[str, int]:
        return {
            "observations": len(self.log.all()),
            "states": len(self.states),
            "causal_edges": len(self.edges),
        }
