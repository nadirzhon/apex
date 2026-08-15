"""ASCEND pipeline: scope -> model -> invariants -> hypotheses -> evidence.

The pipeline remains fail-closed. Omega adds a semantic Digital Twin, immutable
observations with provenance, causal state modeling, browser/JavaScript-derived
discovery, independent reasoning votes, multi-step chain reasoning,
falsification-first planning, and replayable evidence without weakening scope.
"""
from __future__ import annotations

from typing import Callable

from ..models import Finding
from ..scope import Scope
from ..store import Store
from .awm import AWM, Node, Priv
from .causal_model import ProvenanceWorldModel
from .chains import ChainCandidate, ChainReasoner
from .council import CouncilDecision, ReasoningCouncil
from .court import AdversarialCourt, CourtDecision
from .differential import Resp, three_way
from .digital_twin import DigitalTwin
from .evidence_graph import EvidenceGraph, EvidenceNode, ReplayManifest
from .falsification import CheckResult, FalsificationPlan, FalsificationPlanner, FalsificationVerdict
from .invariants import InvariantCompiler, SecurityInvariant
from .observations import Observation, ObservationLog
from .reasoning import Evidence, EvidenceLedger, Hypothesis, HypothesisEngine


Fetcher = Callable[[str, str], Resp]
Gatekeeper = Callable[[Hypothesis], bool]
Reasoner = Callable[[Node], list[Hypothesis]]


class AscendPipeline:
    def __init__(self, scope: Scope, store: Store, authorized: bool):
        scope.assert_ready(authorized)
        self.scope = scope
        self.store = store
        self.awm = AWM()
        self.twin = DigitalTwin()
        self.observations = ObservationLog()
        self.world = ProvenanceWorldModel(self.observations)
        self.evidence_graph = EvidenceGraph(self.observations)
        self.invariants: list[SecurityInvariant] = []
        self.hypotheses: dict[str, Hypothesis] = {}
        self.evidence: dict[str, EvidenceLedger] = {}
        self._compiler = InvariantCompiler()
        self._reasoner = HypothesisEngine()
        self._chain_reasoner = ChainReasoner()
        self._council = ReasoningCouncil()
        self._court = AdversarialCourt()
        self._falsifier = FalsificationPlanner()

    def build_awm(self, endpoints: list[dict]) -> AWM:
        for ep in endpoints:
            url = ep.get("url", "")
            self.scope.guard(url)
            node = Node(
                key=ep.get("key") or f"{ep.get('method','GET')} {url}",
                method=ep.get("method", "GET"),
                url=url,
                status=ep.get("status", 0),
                privilege=ep.get("privilege", Priv.USER),
                params=ep.get("params", []),
                attrs=dict(ep.get("attrs", {})),
            )
            self.awm.add_node(node)
            self.twin.ingest_endpoint(ep)
        self.invariants = self._compiler.compile(self.twin)
        return self.awm

    def ingest_browser_inventory(self, inventory) -> AWM:
        return self.build_awm(inventory.endpoint_records())

    def ingest_js_analyses(self, analyzer, analyses) -> AWM:
        """Merge passive static JavaScript route hints into the model.

        Unknown HTTP methods remain UNKNOWN rather than being treated as safe GETs.
        Every URL still passes the normal scope guard in ``build_awm``.
        """
        return self.build_awm(analyzer.endpoint_records(analyses))

    def record_observation(self, observation: Observation) -> Observation:
        self.scope.guard(observation.target)
        return self.world.ingest(observation)

    def compile_invariants(self) -> list[SecurityInvariant]:
        self.invariants = self._compiler.compile(self.twin)
        return list(self.invariants)

    def chain_candidates(self) -> list[ChainCandidate]:
        return self._chain_reasoner.search(self.world)

    def hypothesize(self, reasoner: Reasoner | None = None) -> list[Hypothesis]:
        if not self.invariants:
            self.compile_invariants()
        hyps = self._reasoner.generate(self.awm, self.twin, self.invariants)
        hyps.extend(self._chain_reasoner.hypotheses(self.world))
        if reasoner:
            for node in self.awm.nodes.values():
                hyps.extend(reasoner(node))
        dedup: dict[str, Hypothesis] = {}
        for h in hyps:
            dedup[h.id] = h
        self.hypotheses = dedup
        return list(dedup.values())

    def deliberate(self, hypothesis_id: str) -> CouncilDecision:
        return self._council.deliberate(
            self.hypotheses[hypothesis_id], self.awm, self.twin, self.world
        )

    def falsification_plan(self, hypothesis_id: str) -> FalsificationPlan:
        return self._falsifier.plan(self.hypotheses[hypothesis_id])

    def evaluate_falsification(self, hypothesis_id: str,
                               results: list[CheckResult]) -> FalsificationVerdict:
        return self._falsifier.evaluate(self.falsification_plan(hypothesis_id), results)

    def assemble_replay_evidence(self, hypothesis_id: str,
                                 nodes: list[EvidenceNode]) -> ReplayManifest:
        if hypothesis_id not in self.hypotheses:
            raise KeyError(hypothesis_id)
        return self.evidence_graph.build(hypothesis_id, nodes)

    def validate(self, hyps: list[Hypothesis], fetch: Fetcher,
                 gatekeeper: Gatekeeper | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for h in hyps:
            if gatekeeper and not gatekeeper(h):
                continue
            node = self.awm.nodes.get(h.node_key)
            url = node.url if node else h.node_key
            self.scope.guard(url)

            baseline = fetch("victim", url)
            attacker = fetch("attacker", url)
            control = fetch("control", url)
            verdict = three_way(baseline, attacker, control)

            ledger = EvidenceLedger(h.id, prior=h.confidence)
            ledger.add(Evidence(
                source="three-way-differential",
                observation=verdict.as_evidence(),
                likelihood_ratio=25.0 if verdict.confirmed else 0.10,
                reproducible=True,
            ))
            self.evidence[h.id] = ledger

            if not verdict.confirmed:
                continue
            findings.append(Finding(
                title=f"{h.klass}: {h.node_key} (параметр {h.param})",
                severity="high", target=url, module="ascend",
                description=(h.description + " Подтверждено контролируемым "
                             "3-way differential validation."),
                evidence=(verdict.as_evidence()
                          + f" | invariant={h.invariant_id or 'unbound'}"
                          + f" | posterior={ledger.confidence:.3f}"),
                remediation=("Проверяй серверные authorization/workflow invariants "
                             "для каждого запроса и не доверяй идентификаторам клиента."),
                cvss_vector=h.cvss_vector,
            ))
        for finding in findings:
            self.store.add_finding(finding)
        return findings

    def review(self, hypothesis_id: str, *, independently_reproduced: bool,
               skeptic_objections: list[str] | None = None) -> CourtDecision:
        hypothesis = self.hypotheses[hypothesis_id]
        ledger = self.evidence.get(
            hypothesis_id, EvidenceLedger(hypothesis.id, prior=hypothesis.confidence)
        )
        node = self.awm.nodes.get(hypothesis.node_key)
        target = node.url if node else hypothesis.node_key
        return self._court.review(
            hypothesis,
            ledger,
            scope_ok=self.scope.in_scope_target(target),
            independently_reproduced=independently_reproduced,
            skeptic_objections=skeptic_objections,
        )
