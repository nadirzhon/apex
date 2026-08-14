"""Replayable evidence graph for ASCEND.

Findings should be grounded in a closed set of immutable observations and explicit
checks. The graph verifies references and produces a stable replay manifest hash.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .observations import ObservationLog


@dataclass(frozen=True)
class EvidenceNode:
    key: str
    kind: str
    observation_ids: tuple[str, ...]
    description: str = ""


@dataclass
class ReplayManifest:
    hypothesis_id: str
    nodes: list[EvidenceNode] = field(default_factory=list)

    def observation_ids(self) -> list[str]:
        out: list[str] = []
        for node in self.nodes:
            out.extend(node.observation_ids)
        return list(dict.fromkeys(out))


class EvidenceGraph:
    def __init__(self, log: ObservationLog) -> None:
        self.log = log
        self._manifests: dict[str, ReplayManifest] = {}

    def build(self, hypothesis_id: str, nodes: list[EvidenceNode]) -> ReplayManifest:
        for node in nodes:
            missing = [obs_id for obs_id in node.observation_ids if self.log.get(obs_id) is None]
            if missing:
                raise ValueError(f"evidence node {node.key} references unknown observations: {', '.join(missing)}")
        manifest = ReplayManifest(hypothesis_id, list(nodes))
        self._manifests[hypothesis_id] = manifest
        return manifest

    def manifest(self, hypothesis_id: str) -> ReplayManifest | None:
        return self._manifests.get(hypothesis_id)

    def replayable(self, hypothesis_id: str, *, required_kinds: set[str] | None = None) -> bool:
        manifest = self._manifests.get(hypothesis_id)
        if not manifest or not manifest.nodes:
            return False
        if not manifest.observation_ids():
            return False
        kinds = {node.kind for node in manifest.nodes}
        return (required_kinds or set()) <= kinds

    def digest(self, hypothesis_id: str) -> str:
        manifest = self._manifests.get(hypothesis_id)
        if not manifest:
            return ""
        payload = {
            "hypothesis_id": manifest.hypothesis_id,
            "nodes": [
                {
                    "key": node.key,
                    "kind": node.kind,
                    "observation_ids": list(node.observation_ids),
                    "description": node.description,
                }
                for node in manifest.nodes
            ],
            "observation_log": self.log.fingerprint(),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
