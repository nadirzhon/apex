"""Security invariant compiler for the APEX application Digital Twin."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from .awm import Priv
from .digital_twin import DigitalTwin, EndpointModel


class InvariantKind(str, Enum):
    OWNERSHIP = "ownership"
    ROLE_BOUNDARY = "role_boundary"
    TENANT_ISOLATION = "tenant_isolation"
    STATE_TRANSITION = "state_transition"
    SERVER_AUTHORITY = "server_authority"


@dataclass(frozen=True)
class SecurityInvariant:
    id: str
    kind: InvariantKind
    subject: str
    predicate: str
    target: str
    rationale: str
    severity: str = "high"


def _id(kind: InvariantKind, target: str, predicate: str) -> str:
    raw = f"{kind.value}\x00{target}\x00{predicate}".encode()
    return f"inv-{hashlib.sha256(raw).hexdigest()[:12]}"


class InvariantCompiler:
    """Derive conservative invariants from explicit application semantics."""

    def compile(self, twin: DigitalTwin) -> list[SecurityInvariant]:
        out: list[SecurityInvariant] = []
        for ep in twin.endpoints.values():
            out.extend(self._endpoint_invariants(ep))
        return self._dedup(out)

    def _endpoint_invariants(self, ep: EndpointModel) -> list[SecurityInvariant]:
        out: list[SecurityInvariant] = []
        if ep.object_params:
            pred = "a principal may access an object only when object-level authorization permits it"
            out.append(SecurityInvariant(
                _id(InvariantKind.OWNERSHIP, ep.key, pred),
                InvariantKind.OWNERSHIP,
                "principal",
                pred,
                ep.key,
                "Object identifiers cross a trust boundary and require server-side authorization.",
            ))
        if ep.privilege > Priv.ANON:
            pred = f"caller privilege must satisfy required level {int(ep.privilege)}"
            out.append(SecurityInvariant(
                _id(InvariantKind.ROLE_BOUNDARY, ep.key, pred),
                InvariantKind.ROLE_BOUNDARY,
                "caller role",
                pred,
                ep.key,
                "Protected functionality must not be reachable from a weaker role.",
            ))
        if ep.tenant_scoped:
            pred = "response and state changes must remain inside the caller tenant"
            out.append(SecurityInvariant(
                _id(InvariantKind.TENANT_ISOLATION, ep.key, pred),
                InvariantKind.TENANT_ISOLATION,
                "tenant",
                pred,
                ep.key,
                "Cross-tenant data flow violates isolation even when HTTP authorization succeeds.",
                severity="critical",
            ))
        if ep.mutates_state:
            pred = "state-changing operations must preserve authorization and workflow preconditions"
            out.append(SecurityInvariant(
                _id(InvariantKind.STATE_TRANSITION, ep.key, pred),
                InvariantKind.STATE_TRANSITION,
                "workflow state",
                pred,
                ep.key,
                "Mutation endpoints can violate state-machine rules without violating syntax.",
            ))
        return out

    @staticmethod
    def _dedup(items: list[SecurityInvariant]) -> list[SecurityInvariant]:
        seen: set[str] = set()
        out: list[SecurityInvariant] = []
        for item in items:
            if item.id not in seen:
                seen.add(item.id)
                out.append(item)
        return out
