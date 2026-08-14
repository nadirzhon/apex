"""Provenance-first observations for ASCEND.

An Observation is an immutable fact recorded from a controlled interaction.
It intentionally separates facts from hypotheses: reasoners may interpret events,
but cannot rewrite what was observed.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class Observation:
    kind: str
    actor: str
    target: str
    action: str
    status: int = 0
    state_before: str = ""
    state_after: str = ""
    request_fingerprint: str = ""
    response_fingerprint: str = ""
    facts: dict[str, Any] = field(default_factory=dict)
    source: str = "runtime"
    parent_ids: tuple[str, ...] = ()
    observed_at: float = field(default_factory=time.time)
    id: str = ""

    def __post_init__(self) -> None:
        if self.id:
            return
        payload = {
            "kind": self.kind,
            "actor": self.actor,
            "target": self.target,
            "action": self.action,
            "status": self.status,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "request_fingerprint": self.request_fingerprint,
            "response_fingerprint": self.response_fingerprint,
            "facts": self.facts,
            "source": self.source,
            "parent_ids": list(self.parent_ids),
        }
        digest = hashlib.sha256(_stable(payload).encode("utf-8", "replace")).hexdigest()[:20]
        object.__setattr__(self, "id", f"obs-{digest}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["parent_ids"] = list(self.parent_ids)
        return data


class ObservationLog:
    """Append-only observation log with referential-integrity checks."""

    def __init__(self) -> None:
        self._items: dict[str, Observation] = {}
        self._order: list[str] = []

    def append(self, observation: Observation) -> Observation:
        missing = [parent for parent in observation.parent_ids if parent not in self._items]
        if missing:
            raise ValueError(f"unknown observation parents: {', '.join(missing)}")
        if observation.id not in self._items:
            self._items[observation.id] = observation
            self._order.append(observation.id)
        return self._items[observation.id]

    def get(self, observation_id: str) -> Observation | None:
        return self._items.get(observation_id)

    def all(self) -> list[Observation]:
        return [self._items[item_id] for item_id in self._order]

    def lineage(self, observation_id: str) -> list[Observation]:
        out: list[Observation] = []
        seen: set[str] = set()

        def visit(item_id: str) -> None:
            if item_id in seen:
                return
            item = self._items.get(item_id)
            if not item:
                return
            seen.add(item_id)
            for parent in item.parent_ids:
                visit(parent)
            out.append(item)

        visit(observation_id)
        return out

    def fingerprint(self) -> str:
        material = "\n".join(_stable(self._items[item_id].to_dict()) for item_id in self._order)
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
