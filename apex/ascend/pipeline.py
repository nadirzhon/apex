"""ASCEND pipeline: scope -> model -> invariants -> hypotheses -> evidence.

The pipeline remains fail-closed. The Omega foundation adds a semantic Digital Twin,
compiled security invariants, hypothesis confidence and an evidence ledger without
changing the existing three-way differential confirmation primitive.
"""
from __future__ import annotations

from typing import Callable

from ..models import Finding
from ..scope import Scope
from ..store import Store
from .awm import AWM, Node, Priv
from .court import AdversarialCourt, CourtDecision
from .differential import Resp, three_way
from .digital_twin import DigitalTwin
from .invariants import InvariantCompiler, SecurityInvariant
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
        self.invariants: list[SecurityInvariant] = []
        self.hypotheses: dict[str, Hypothesis] = {}
        self.evidence: dict[str, EvidenceLedger] = {}
        self._compiler = InvariantCompiler()
        self._reasoner = HypothesisEngine()
        self._court = AdversarialCourt()

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

    def compile_invariants(self) -> list[SecurityInvariant]:
        self.invariants = self._compiler.compile(self.twin)
        return list(self.invariants)

    def hypothesize(self, reasoner: Reasoner | None = None) -> list[Hypothesis]:
        if not self.invariants:
            self.compile_invariants()
        hyps = self._reasoner.generate(self.awm, self.twin, self.invariants)
        if reasoner:
            for node in self.awm.nodes.values():
                hyps.extend(reasoner(node))
        dedup: dict[str, Hypothesis] = {}
        for h in hyps:
            dedup[h.id] = h
        self.hypotheses = dedup
        return list(dedup.values())

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
                severity="high",
                target=url,
                module="ascend",
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

    def review(
        self,
        hypothesis_id: str,
        *,
        independently_reproduced: bool,
        skeptic_objections: list[str] | None = None,
    ) -> CourtDecision:
        """Run the publication-quality adversarial evidence gate for one hypothesis."""
        hypothesis = self.hypotheses[hypothesis_id]
        ledger = self.evidence.get(
            hypothesis_id,
            EvidenceLedger(hypothesis.id, prior=hypothesis.confidence),
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
