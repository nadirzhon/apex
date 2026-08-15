"""Structured model planning for OMEGA research tasks.

The model is a planner, not an executor. It receives a bounded assignment and
returns a strict plan. It cannot mark a vulnerability confirmed, make network
requests, or bypass scope. Concrete actions remain explicit scope-gated workers.

The default transport uses OpenAI's Responses API over HTTPS with ``store=false``.
Tests inject a fake transport, so the core test suite never requires credentials or
network access.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .coordinator import Assignment


@dataclass(frozen=True)
class PlanProposal:
    objective_restated: str
    reasoning_summary: str
    checks: tuple[str, ...]
    evidence_needed: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    memory_cues: tuple[str, ...]
    confidence: float


PlannerTransport = Callable[[dict[str, Any]], dict[str, Any]]


_PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "objective_restated": {"type": "string"},
        "reasoning_summary": {"type": "string"},
        "checks": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "evidence_needed": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "stop_conditions": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "memory_cues": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": [
        "objective_restated", "reasoning_summary", "checks", "evidence_needed",
        "stop_conditions", "memory_cues", "confidence",
    ],
}


class OpenAIResponsesTransport:
    """Minimal stdlib transport for the Responses API."""

    def __init__(self, *, api_key: str | None = None, model: str = "gpt-5.6",
                 timeout: float = 60.0) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is required for model planning")
        self.model = model
        self.timeout = timeout

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        body = dict(request)
        body.setdefault("model", self.model)
        body["store"] = False
        req = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "APEX-OMEGA-Planner/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise RuntimeError(f"OpenAI Responses API HTTP {exc.code}: {detail}") from exc


class StructuredModelPlanner:
    def __init__(self, transport: PlannerTransport | None = None, *, model: str = "gpt-5.6") -> None:
        self.transport = transport or OpenAIResponsesTransport(model=model)
        self.model = model

    def plan(self, assignment: Assignment) -> PlanProposal:
        memory = [
            {
                "cues": sorted(item.cues),
                "content": item.content,
                "confidence": item.confidence,
            }
            for item in assignment.memory
        ]
        prompt = {
            "objective": assignment.objective,
            "family": assignment.family,
            "expected_outcome": assignment.expected_outcome,
            "negative_control": assignment.negative_control,
            "specialist": assignment.specialist.name,
            "allowed_capabilities": sorted(assignment.specialist.capabilities),
            "methodology_memory": memory,
            "constraints": [
                "Plan only; do not claim a vulnerability is confirmed.",
                "Do not suggest actions outside the stated capabilities.",
                "Prefer falsification and negative controls before confirmation.",
                "Every proposed conclusion must name the evidence needed to support it.",
                "Stop when evidence cannot distinguish the hypothesis from a benign explanation.",
            ],
        }
        request = {
            "model": self.model,
            "store": False,
            "instructions": (
                "You are the planning layer of an authorized AppSec research system. "
                "Return a conservative evidence-first plan. You do not execute tools and "
                "you cannot confirm findings. Respect the supplied capabilities and stop conditions."
            ),
            "input": json.dumps(prompt, ensure_ascii=False),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "apex_research_plan",
                    "strict": True,
                    "schema": _PLAN_SCHEMA,
                }
            },
        }
        raw = self.transport(request)
        data = self._extract_json(raw)
        confidence = min(max(float(data["confidence"]), 0.0), 1.0)
        return PlanProposal(
            objective_restated=str(data["objective_restated"]),
            reasoning_summary=str(data["reasoning_summary"]),
            checks=tuple(str(x) for x in data["checks"]),
            evidence_needed=tuple(str(x) for x in data["evidence_needed"]),
            stop_conditions=tuple(str(x) for x in data["stop_conditions"]),
            memory_cues=tuple(str(x) for x in data["memory_cues"]),
            confidence=confidence,
        )

    @staticmethod
    def _extract_json(response: dict[str, Any]) -> dict[str, Any]:
        # Responses API output is an ordered list. Accept only assistant text output;
        # never interpret tool calls here because this component is planner-only.
        for item in response.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    try:
                        obj = json.loads(content["text"])
                    except json.JSONDecodeError as exc:
                        raise ValueError("model planner returned non-JSON output") from exc
                    StructuredModelPlanner._validate_shape(obj)
                    return obj
        # Some transports/tests may normalize the parsed structured object directly.
        if isinstance(response.get("parsed"), dict):
            obj = response["parsed"]
            StructuredModelPlanner._validate_shape(obj)
            return obj
        raise ValueError("model planner response contains no structured assistant output")

    @staticmethod
    def _validate_shape(obj: dict[str, Any]) -> None:
        required = set(_PLAN_SCHEMA["required"])
        if set(obj) != required:
            raise ValueError("model plan fields do not match strict schema")
        for key in ("checks", "evidence_needed", "stop_conditions", "memory_cues"):
            if not isinstance(obj[key], list) or len(obj[key]) > 8:
                raise ValueError(f"invalid model plan list: {key}")
        if not isinstance(obj["confidence"], (int, float)):
            raise ValueError("invalid model confidence")
