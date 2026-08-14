"""Build ASCEND endpoint hypotheses from an authorized HAR capture.

This module is offline: it parses the researcher's own HAR, normalizes endpoint
shapes and feeds them into the existing Digital Twin / invariant / hypothesis
pipeline. It does not send network traffic.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from ..scope import Scope
from ..store import Store
from .awm import Priv
from .pipeline import AscendPipeline, Hypothesis

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$")
_ID_NAMES = {"id", "uuid", "user", "user_id", "account_id", "order_id", "object_id", "resource_id"}


def _normalize_path(path: str) -> tuple[str, list[str]]:
    parts = []
    params: list[str] = []
    for part in (path or "/").split("/"):
        if not part:
            continue
        if _NUMERIC.match(part) or _UUID.match(part):
            parts.append("{id}")
            if "id" not in params:
                params.append("id")
        else:
            parts.append(part)
    return "/" + "/".join(parts), params


def _object_params(url: str) -> tuple[str, list[str]]:
    parsed = urlparse(url)
    path, params = _normalize_path(parsed.path)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        low = key.lower()
        if low in _ID_NAMES or low.endswith("_id") or low.endswith("id"):
            if key not in params:
                params.append(key)
    return path, params


def endpoints_from_har(scope: Scope, har_path: str) -> list[dict]:
    data = json.loads(Path(har_path).read_text(encoding="utf-8"))
    endpoints: list[dict] = []
    seen: set[str] = set()
    for entry in data.get("log", {}).get("entries", []):
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url", ""))
        method = str(request.get("method", "GET")).upper()
        if not url or not scope.in_scope_target(url):
            continue
        path, params = _object_params(url)
        host = urlparse(url).hostname or ""
        key = f"{method} {host}{path}"
        if key in seen:
            continue
        seen.add(key)
        endpoints.append({
            "key": key,
            "method": method,
            "url": url,
            "status": int(response.get("status", 0) or 0),
            "privilege": Priv.USER,
            "params": params,
            "mutates_state": method in {"POST", "PUT", "PATCH", "DELETE"},
            "attrs": {"source": "har"},
        })
    return endpoints


def hypotheses_from_har(scope: Scope, store: Store, authorized: bool,
                        har_path: str) -> list[Hypothesis]:
    pipeline = AscendPipeline(scope, store, authorized)
    pipeline.build_awm(endpoints_from_har(scope, har_path))
    return pipeline.hypothesize()
