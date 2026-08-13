"""Deterministic hypothesis and evidence reasoning primitives for ASCEND.

No exploit execution lives here. The engine converts explicit model facts and
security invariants into testable hypotheses and tracks evidence probabilistically.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .awm import AWM
from .digital_twin import DigitalTwin
from .invariants import InvariantKind, SecurityInvariant


@dataclass
class Hypothesis:
    klass: str
    node_key: str
    param: str
    description: str
    cvss_vector: str = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    invariant_id: str = ""
    confidence: float = 0.35
    expected_outcome: str = ""
    negative_control: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        self.confidence = min(max(float(self.confidence), 0.001), 0.999)
        if not self.id:
            raw = f"{self.klass}\x00{self.node_key}\x00{self.param}\x00{self.invariant_id}".encode()
            self.id = f"hyp-{hashlib.sha256(raw).hexdigest()[:12]}"


@dataclass(frozen=True)
class Evidence:
    source: str
    observation: str
    likelihood_ratio: float
    reproducible: bool = True


@dataclass
class EvidenceLedger:
    hypothesis_id: str
    prior: float = 0.35
    evidence: list[Evidence] = field(default_factory=list)

    def add(self, evidence: Evidence) -> None:
        if evidence.likelihood_ratio <= 0:
            raise ValueError("likelihood_ratio must be > 0")
        self.evidence.append(evidence)

    @property
    def confidence(self) -> float:
        p = min(max(self.prior, 1e-6), 1 - 1e-6)
        odds = p / (1 - p)
        for item in self.evidence:
            odds *= item.likelihood_ratio
        return odds / (1 + odds)

    @property
    def reproducible(self) -> bool:
        return bool(self.evidence) and all(e.reproducible for e in self.evidence)


class HypothesisEngine:
    """Generate conservative hypotheses from AWM + semantic invariants."""

    def generate(self, awm: AWM, twin: DigitalTwin,
                 invariants: list[SecurityInvariant]) -> list[Hypothesis]:
        inv_by_target: dict[str, list[SecurityInvariant]] = {}
        for inv in invariants:
            inv_by_target.setdefault(inv.target, []).append(inv)

        out: list[Hypothesis] = []
        for node in awm.idor_candidates():
            ownership = next((i for i in inv_by_target.get(node.key, [])
                              if i.kind == InvariantKind.OWNERSHIP), None)
            for param in node.params:
                out.append(Hypothesis(
                    klass="IDOR/BOLA",
                    node_key=node.key,
                    param=param,
                    description=(f"Object-level authorization may be inconsistent for {node.key} "
                                 f"when parameter '{param}' references an object owned by another principal."),
                    invariant_id=ownership.id if ownership else "",
                    confidence=0.40,
                    expected_outcome="unauthorized principal is denied or receives no protected object data",
                    negative_control="a nonexistent object must resemble denial/error behavior, not protected data",
                ))

        for edge in awm.privilege_jumps():
            role_inv = next((i for i in inv_by_target.get(edge.dst, [])
                             if i.kind == InvariantKind.ROLE_BOUNDARY), None)
            out.append(Hypothesis(
                klass="BFLA/privesc",
                node_key=edge.dst,
                param="(role)",
                description=f"Transition {edge.src} → {edge.dst} may violate the required privilege boundary.",
                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                invariant_id=role_inv.id if role_inv else "",
                confidence=0.35,
                expected_outcome="weaker roles cannot reach privileged state or privileged data",
                negative_control="a role below the required privilege must be consistently denied",
            ))

        for ep in twin.endpoints.values():
            target_invs = inv_by_target.get(ep.key, [])
            tenant = next((i for i in target_invs if i.kind == InvariantKind.TENANT_ISOLATION), None)
            if tenant and ep.object_params:
                out.append(Hypothesis(
                    klass="tenant-isolation",
                    node_key=ep.key,
                    param=ep.object_params[0],
                    description=f"Tenant-scoped object access at {ep.key} may leak across tenant boundaries.",
                    invariant_id=tenant.id,
                    confidence=0.30,
                    expected_outcome="cross-tenant object references are denied without data disclosure",
                    negative_control="same-tenant authorized reference behaves differently from cross-tenant reference",
                ))

        return self._dedup(out)

    @staticmethod
    def _dedup(items: list[Hypothesis]) -> list[Hypothesis]:
        seen: set[str] = set()
        out: list[Hypothesis] = []
        for item in items:
            if item.id not in seen:
                seen.add(item.id)
                out.append(item)
        return out
