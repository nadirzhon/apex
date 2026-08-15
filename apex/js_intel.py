"""Passive JavaScript intelligence for APEX.

The analyzer consumes JavaScript text already fetched from an authorized same-origin
source. It records in-scope route hints separately from cross-origin dependencies.
Only in-scope routes can become ASCEND endpoint records; external dependencies are
inventory facts and are never promoted to targets automatically.
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

_ROUTE_PATTERNS = [
    re.compile(r'''\bfetch\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''\b(?:axios\.(?:get|post|put|patch|delete)|axios)\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`]+)["'`]''', re.I),
    re.compile(r'''\b(?:url|endpoint|apiUrl|apiURL)\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
]
_METHOD_PATTERNS = [
    (re.compile(r'''\bfetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^{}]{0,500}?method\s*:\s*["']([A-Z]+)["']''', re.I | re.S), 2),
    (re.compile(r'''\baxios\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]''', re.I), 1),
    (re.compile(r'''\.open\s*\(\s*["']([A-Z]+)["']\s*,\s*["'`]([^"'`]+)["'`]''', re.I), 1),
]
_PATH_LITERAL = re.compile(r'''["'`]((?:/|https?://)[A-Za-z0-9_~!$&()*+,;=:@%./?#\[\]-]{2,300})["'`]''')
_SECRETISH = re.compile(r'''(?i)(?:api[_-]?key|token|secret|authorization|bearer)["'\s:=]+([A-Za-z0-9._~+\-/=]{12,})''')

@dataclass(frozen=True)
class RouteHint:
    method: str
    url: str
    source: str
    confidence: float
    mutating: bool = False

@dataclass(frozen=True)
class ExternalRouteHint:
    method: str
    url: str
    origin: str
    source: str
    confidence: float
    mutating: bool = False

@dataclass(frozen=True)
class RedactedSecretHint:
    kind: str
    fingerprint: str
    length: int

@dataclass
class JSAnalysis:
    script_url: str
    sha256: str
    routes: list[RouteHint] = field(default_factory=list)
    external_routes: list[ExternalRouteHint] = field(default_factory=list)
    secret_hints: list[RedactedSecretHint] = field(default_factory=list)

class JavaScriptAnalyzer:
    def __init__(self, root: str) -> None:
        self.root = root
        self.root_host = (urllib.parse.urlparse(root).hostname or "").lower()

    def analyze(self, script_url: str, source: str) -> JSAnalysis:
        if (urllib.parse.urlparse(script_url).hostname or "").lower() != self.root_host:
            raise PermissionError("JavaScript source is outside authorized host")
        analysis = JSAnalysis(script_url=script_url,
            sha256=hashlib.sha256(source.encode("utf-8", "replace")).hexdigest())
        routes: dict[tuple[str, str], RouteHint] = {}
        external: dict[tuple[str, str], ExternalRouteHint] = {}

        for rx, method_group in _METHOD_PATTERNS:
            for match in rx.finditer(source):
                text = match.group(0).lower()
                if "axios." in text or ".open" in text:
                    method, raw_url = match.group(1).upper(), match.group(2)
                else:
                    raw_url, method = match.group(1), match.group(method_group).upper()
                self._add(routes, external, method, raw_url, "request-call", 0.95)
        for rx in _ROUTE_PATTERNS:
            for match in rx.finditer(source):
                self._add(routes, external, "UNKNOWN", match.group(1), "request-hint", 0.80)
        for match in _PATH_LITERAL.finditer(source):
            raw = match.group(1)
            if self._endpointish(raw):
                self._add(routes, external, "UNKNOWN", raw, "literal", 0.50)
        for match in _SECRETISH.finditer(source):
            value = match.group(1)
            if value:
                analysis.secret_hints.append(RedactedSecretHint(
                    "secret-like-literal", hashlib.sha256(value.encode()).hexdigest()[:16], len(value)))

        analysis.routes = sorted(routes.values(), key=lambda x: (-x.confidence, x.url, x.method))
        analysis.external_routes = sorted(external.values(), key=lambda x: (-x.confidence, x.url, x.method))
        analysis.secret_hints = list(dict.fromkeys(analysis.secret_hints))
        return analysis

    def endpoint_records(self, analyses: Iterable[JSAnalysis]) -> list[dict]:
        records: dict[tuple[str, str], dict] = {}
        for analysis in analyses:
            for route in analysis.routes:
                parsed = urllib.parse.urlparse(route.url)
                method = route.method
                records[(method, route.url)] = {
                    "key": f"{method} {parsed.path or '/'}", "method": method, "url": route.url,
                    "status": 0, "params": sorted(urllib.parse.parse_qs(parsed.query).keys()),
                    "mutates_state": method in {"POST", "PUT", "PATCH", "DELETE"},
                    "attrs": {"source": "javascript-static", "script_url": analysis.script_url,
                              "confidence": route.confidence, "hint_source": route.source,
                              "method_confirmed": method != "UNKNOWN"},
                }
        return sorted(records.values(), key=lambda r: (r["url"], r["method"]))

    def external_dependencies(self, analyses: Iterable[JSAnalysis]) -> list[dict]:
        deps: dict[tuple[str, str], dict] = {}
        for analysis in analyses:
            for route in analysis.external_routes:
                deps[(route.method, route.url)] = {
                    "method": route.method, "url": route.url, "origin": route.origin,
                    "mutating": route.mutating, "confidence": route.confidence,
                    "source": route.source, "script_url": analysis.script_url,
                    "in_scope": False, "targetable": False,
                }
        return sorted(deps.values(), key=lambda x: (x["origin"], x["url"], x["method"]))

    def _add(self, routes, external, method: str, raw_url: str, source: str, confidence: float) -> None:
        url = self._normalize_any(raw_url)
        if not url:
            return
        parsed = urllib.parse.urlparse(url)
        method = method.upper()
        mutating = method in {"POST", "PUT", "PATCH", "DELETE"}
        if (parsed.hostname or "").lower() == self.root_host:
            hint = RouteHint(method, url, source, confidence, mutating)
            key = (method, url)
            if key not in routes or confidence > routes[key].confidence:
                routes[key] = hint
        else:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            hint = ExternalRouteHint(method, url, origin, source, confidence, mutating)
            key = (method, url)
            if key not in external or confidence > external[key].confidence:
                external[key] = hint

    def _normalize_any(self, raw: str) -> str:
        raw = raw.strip()
        if not raw or any(x in raw for x in ("${", "{{", "<%")):
            return ""
        absolute = urllib.parse.urljoin(self.root, raw)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        return urllib.parse.urldefrag(absolute)[0]

    @staticmethod
    def _endpointish(raw: str) -> bool:
        lower = raw.lower()
        if any(lower.endswith(ext) for ext in (".js", ".css", ".jpg", ".jpeg", ".png", ".webp", ".svg", ".woff", ".woff2", ".ico")):
            return False
        return any(token in lower for token in ("/api/", "/graphql", "/submit", "/contact", "/lead", "/form", "/webhook", "/auth", "/login", "/session", "/orders", "/users", "/account"))
