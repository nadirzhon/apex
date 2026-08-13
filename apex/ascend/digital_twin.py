"""Digital Twin — semantic model above the raw endpoint/state graph.

The twin captures actors, resources, ownership, tenancy and endpoint semantics.
It does not execute traffic; it exists to make reasoning explicit and testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .awm import Priv


@dataclass
class Actor:
    key: str
    role: int = Priv.USER
    tenant: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Resource:
    key: str
    kind: str
    owner: str = ""
    tenant: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class EndpointModel:
    key: str
    method: str
    url: str
    privilege: int = Priv.USER
    resource_kind: str = ""
    object_params: list[str] = field(default_factory=list)
    mutates_state: bool = False
    tenant_scoped: bool = False
    attrs: dict[str, Any] = field(default_factory=dict)


class DigitalTwin:
    """Semantic application model used by invariant and hypothesis engines."""

    def __init__(self):
        self.actors: dict[str, Actor] = {}
        self.resources: dict[str, Resource] = {}
        self.endpoints: dict[str, EndpointModel] = {}

    def add_actor(self, actor: Actor) -> Actor:
        ex = self.actors.get(actor.key)
        if ex:
            ex.role = max(ex.role, actor.role)
            ex.tenant = actor.tenant or ex.tenant
            ex.attrs.update(actor.attrs)
            return ex
        self.actors[actor.key] = actor
        return actor

    def add_resource(self, resource: Resource) -> Resource:
        ex = self.resources.get(resource.key)
        if ex:
            ex.owner = resource.owner or ex.owner
            ex.tenant = resource.tenant or ex.tenant
            ex.attrs.update(resource.attrs)
            return ex
        self.resources[resource.key] = resource
        return resource

    def add_endpoint(self, endpoint: EndpointModel) -> EndpointModel:
        ex = self.endpoints.get(endpoint.key)
        if ex:
            ex.privilege = max(ex.privilege, endpoint.privilege)
            ex.resource_kind = endpoint.resource_kind or ex.resource_kind
            ex.mutates_state = ex.mutates_state or endpoint.mutates_state
            ex.tenant_scoped = ex.tenant_scoped or endpoint.tenant_scoped
            for p in endpoint.object_params:
                if p not in ex.object_params:
                    ex.object_params.append(p)
            ex.attrs.update(endpoint.attrs)
            return ex
        self.endpoints[endpoint.key] = endpoint
        return endpoint

    def ingest_endpoint(self, ep: dict[str, Any]) -> EndpointModel:
        method = str(ep.get("method", "GET")).upper()
        key = ep.get("key") or f"{method} {ep.get('url', '')}"
        attrs = dict(ep.get("attrs", {}))
        return self.add_endpoint(EndpointModel(
            key=key,
            method=method,
            url=ep.get("url", ""),
            privilege=ep.get("privilege", Priv.USER),
            resource_kind=ep.get("resource_kind", attrs.get("resource_kind", "")),
            object_params=list(ep.get("params", ep.get("object_params", []))),
            mutates_state=bool(ep.get("mutates_state", method in {"POST", "PUT", "PATCH", "DELETE"})),
            tenant_scoped=bool(ep.get("tenant_scoped", attrs.get("tenant_scoped", False))),
            attrs=attrs,
        ))

    def resources_of_kind(self, kind: str) -> list[Resource]:
        return [r for r in self.resources.values() if r.kind == kind]

    def summary(self) -> dict[str, int]:
        return {
            "actors": len(self.actors),
            "resources": len(self.resources),
            "endpoints": len(self.endpoints),
            "state_mutators": sum(1 for e in self.endpoints.values() if e.mutates_state),
            "tenant_scoped": sum(1 for e in self.endpoints.values() if e.tenant_scoped),
        }
