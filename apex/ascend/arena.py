"""Blind, loopback-only challenge arena for measuring autonomous reasoning.

The arena deliberately separates *ground truth* from the agent input. A solver only
receives a target descriptor and must return findings; labels are revealed to the
scorer after the run. Targets are restricted to localhost/loopback so this harness
cannot be pointed at arbitrary external infrastructure.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import urlparse


@dataclass(frozen=True)
class GroundTruth:
    finding_id: str
    klass: str
    asset: str


@dataclass(frozen=True)
class ReportedFinding:
    finding_id: str
    klass: str
    asset: str
    confidence: float = 0.0
    evidence: str = ""


@dataclass(frozen=True)
class BlindChallenge:
    name: str
    target: str
    ground_truth: tuple[GroundTruth, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ChallengeResult:
    name: str
    reported: tuple[ReportedFinding, ...]
    ground_truth: tuple[GroundTruth, ...]
    latency_ms: float


Solver = Callable[[str, dict[str, str]], Iterable[ReportedFinding]]


def assert_loopback_target(target: str) -> None:
    """Reject anything except localhost/loopback targets, fail-closed."""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = (parsed.hostname or "").strip().lower()
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise PermissionError(f"arena target must be loopback, got {target!r}") from exc
    if not addr.is_loopback:
        raise PermissionError(f"arena target must be loopback, got {target!r}")


class BlindArena:
    """Execute challenges without exposing labels to the solver."""

    def run(self, challenge: BlindChallenge, solver: Solver) -> ChallengeResult:
        assert_loopback_target(challenge.target)
        started = time.perf_counter()
        reported = tuple(solver(challenge.target, dict(challenge.metadata)))
        elapsed = (time.perf_counter() - started) * 1000.0
        return ChallengeResult(
            name=challenge.name,
            reported=reported,
            ground_truth=challenge.ground_truth,
            latency_ms=elapsed,
        )
