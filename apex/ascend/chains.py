"""Evidence-grounded multi-step chain reasoning for ASCEND.

The chain reasoner searches the provenance-backed world model for state-transition
paths that cross meaningful security boundaries. It does not execute traffic or
construct payloads; it turns already-recorded observations into ranked, testable
multi-step hypotheses with explicit evidence lineage.
"""
from __future__ import annotations

from dataclasses import dataclass

from .awm import Priv
from .causal_model import CausalEdge, ProvenanceWorldModel
from .reasoning import Hypothesis


@dataclass(frozen=True)
class ChainCandidate:
    states: tuple[str, ...]
    relations: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    targets: tuple[str, ...]
    actors: tuple[str, ...]
    score: float
    reasons: tuple[str, ...]

    @property
    def steps(self) -> int:
        return max(0, len(self.states) - 1)


class ChainReasoner:
    """Bounded beam search across causal transitions.

    Scoring rewards paths that:
    - are grounded in distinct evidence observations;
    - span multiple targets/endpoints;
    - involve multiple principals;
    - reach states marked with higher privilege or tenant-sensitive metadata;
    - avoid cycles and repetitive relations.
    """

    def __init__(self, *, max_depth: int = 6, beam_width: int = 24) -> None:
        self.max_depth = max(2, int(max_depth))
        self.beam_width = max(1, int(beam_width))

    def search(self, world: ProvenanceWorldModel) -> list[ChainCandidate]:
        outgoing: dict[str, list[CausalEdge]] = {}
        for edge in world.edges:
            outgoing.setdefault(edge.cause, []).append(edge)

        frontier: list[tuple[tuple[str, ...], tuple[CausalEdge, ...]]] = [
            ((state,), tuple()) for state in sorted(outgoing)
        ]
        found: dict[tuple[str, ...], ChainCandidate] = {}

        for _depth in range(1, self.max_depth + 1):
            expanded: list[tuple[float, tuple[str, ...], tuple[CausalEdge, ...]]] = []
            for states, edges in frontier:
                last = states[-1]
                for edge in outgoing.get(last, []):
                    if edge.effect in states:
                        continue
                    next_states = states + (edge.effect,)
                    next_edges = edges + (edge,)
                    candidate = self._candidate(world, next_states, next_edges)
                    if candidate.steps >= 2:
                        found[candidate.states] = candidate
                    expanded.append((candidate.score, next_states, next_edges))

            expanded.sort(key=lambda row: (-row[0], row[1]))
            frontier = [(states, edges) for _, states, edges in expanded[: self.beam_width]]
            if not frontier:
                break

        return sorted(found.values(), key=lambda c: (-c.score, c.states))

    def hypotheses(self, world: ProvenanceWorldModel, *, min_score: float = 0.55) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for chain in self.search(world):
            if chain.score < min_score:
                continue
            start, end = chain.states[0], chain.states[-1]
            path = " -> ".join(chain.relations)
            target = chain.targets[-1] if chain.targets else end
            out.append(Hypothesis(
                klass="multi-step-chain",
                node_key=target,
                param="(chain)",
                description=(
                    f"Observed causal path {start} -> {end} spans {chain.steps} transitions "
                    f"({path}) and crosses security-relevant boundaries: "
                    + "; ".join(chain.reasons)
                ),
                confidence=min(0.90, 0.35 + 0.55 * chain.score),
                expected_outcome="each transition preserves authorization, tenant, and workflow invariants",
                negative_control="replay the chain with a principal lacking the required ownership/role at each boundary",
            ))
        return out

    def _candidate(self, world: ProvenanceWorldModel, states: tuple[str, ...],
                   edges: tuple[CausalEdge, ...]) -> ChainCandidate:
        evidence: list[str] = []
        targets: set[str] = set()
        actors: set[str] = set()
        reasons: list[str] = []

        for edge in edges:
            evidence.extend(edge.evidence_ids)
        for state_key in states:
            state = world.states.get(state_key)
            if not state:
                continue
            targets.update(state.targets)
            actors.update(state.actors)

        distinct_evidence = len(set(evidence))
        unique_relations = len({edge.relation for edge in edges})
        step_count = len(edges)

        score = 0.15
        score += min(0.25, 0.06 * distinct_evidence)
        score += min(0.20, 0.08 * max(0, len(targets) - 1))
        score += min(0.15, 0.08 * max(0, len(actors) - 1))
        score += min(0.15, 0.04 * step_count)
        score += min(0.10, 0.04 * max(0, unique_relations - 1))

        if len(targets) > 1:
            reasons.append(f"cross-endpoint path spans {len(targets)} targets")
        if len(actors) > 1:
            reasons.append(f"principal contrast spans {len(actors)} actors")
        if distinct_evidence >= step_count:
            reasons.append("every transition is provenance-backed")
        if unique_relations > 1:
            reasons.append("path combines distinct application actions")

        privilege_jump = self._privilege_signal(world, states)
        if privilege_jump:
            score += 0.15
            reasons.append(privilege_jump)

        return ChainCandidate(
            states=states,
            relations=tuple(edge.relation for edge in edges),
            evidence_ids=tuple(dict.fromkeys(evidence)),
            targets=tuple(sorted(targets)),
            actors=tuple(sorted(actors)),
            score=min(score, 1.0),
            reasons=tuple(reasons),
        )

    @staticmethod
    def _privilege_signal(world: ProvenanceWorldModel, states: tuple[str, ...]) -> str:
        levels: list[int] = []
        for state_key in states:
            state = world.states.get(state_key)
            if not state:
                continue
            # Observations may annotate a conservative numeric privilege in facts.
            for obs_id in state.observation_ids:
                obs = world.log.get(obs_id)
                if not obs:
                    continue
                raw = obs.facts.get("privilege")
                if isinstance(raw, int) and Priv.ANON <= raw <= Priv.ADMIN:
                    levels.append(raw)
        if levels and max(levels) > min(levels):
            return f"observed privilege level rises from {min(levels)} to {max(levels)}"
        return ""
