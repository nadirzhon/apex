"""Passive JavaScript intelligence for APEX.

The analyzer consumes JavaScript text that has already been fetched through an
authorized, same-origin observation path. It extracts route and request hints but
never executes JavaScript and never sends requests to discovered endpoints.
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
_SECRETISH = re.compile(
    r'''(?i)(?:api[_-]?key|token|secret|authorization|bearer)["'\s:=]+([A-Za-z0-9._~+\-/=]{12,})'''
)


@dataclass(frozen=True)
class RouteHint:
    method: str
    url: str
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
    secret_hints: list[RedactedSecretHint] = field(default_factory=list)


class JavaScriptAnalyzer:
    def __init__(self, root: str) -> None:
        self.root = root
        self.root_host = (urllib.parse.urlparse(root).hostname or "").lower()

    def analyze(self, script_url: str, source: str) -> JSAnalysis:
        if (urllib.parse.urlparse(script_url).hostname or "").lower() != self.root_host:
            raise PermissionError("JavaScript source is outside authorized host")
        analysis = JSAnalysis(
            script_url=script_url,
            sha256=hashlib.sha256(source.encode("utf-8", "replace")).hexdigest(),
        )
        routes: dict[tuple[str, str], RouteHint] = {}

        # Method-aware patterns first.
        for rx, method_group in _METHOD_PATTERNS:
            for match in rx.finditer(source):
                if "axios." in match.group(0).lower():
                    method = match.group(1).upper()
                    raw_url = match.group(2)
                elif ".open" in match.group(0).lower():
                    method = match.group(1).upper()
                    raw_url = match.group(2)
                else:
                    raw_url = match.group(1)
                    method = match.group(method_group).upper()
                self._add(routes, method, raw_url, "request-call", 0.95)

        for rx in _ROUTE_PATTERNS:
            for match in rx.finditer(source):
                raw_url = match.group(1)
                self._add(routes, "UNKNOWN", raw_url, "request-hint", 0.80)

        # Literal routes are lower confidence; retain only endpoint-looking paths.
        for match in _PATH_LITERAL.finditer(source):
            raw = match.group(1)
            if not self._endpointish(raw):
                continue
            self._add(routes, "UNKNOWN", raw, "literal", 0.50)

        for match in _SECRETISH.finditer(source):
            value = match.group(1)
            if not value:
                continue
            analysis.secret_hints.append(RedactedSecretHint(
                kind="secret-like-literal",
                fingerprint=hashlib.sha256(value.encode()).hexdigest()[:16],
                length=len(value),
            ))

        analysis.routes = sorted(routes.values(), key=lambda x: (-x.confidence, x.url, x.method))
        analysis.secret_hints = list(dict.fromkeys(analysis.secret_hints))
        return analysis

    def endpoint_records(self, analyses: Iterable[JSAnalysis]) -> list[dict]:
        records: dict[tuple[str, str], dict] = {}
        for analysis in analyses:
            for route in analysis.routes:
                parsed = urllib.parse.urlparse(route.url)
                host = (parsed.hostname or self.root_host).lower()
                if host != self.root_host:
                    continue
                method = route.method if route.method != "UNKNOWN" else "GET"
                key = (method, route.url)
                records[key] = {
                    "key": f"{method} {parsed.path or '/'}",
                    "method": method,
                    "url": route.url,
                    "status": 0,
                    "params": sorted(urllib.parse.parse_qs(parsed.query).keys()),
                    "mutates_state": method.upper() in {"POST", "PUT", "PATCH", "DELETE"},
                    "attrs": {
                        "source": "javascript-static",
                        "script_url": analysis.script_url,
                        "confidence": route.confidence,
                        "hint_source": route.source,
                    },
                }
        return sorted(records.values(), key=lambda r: (r["url"], r["method"]))

    def _add(self, routes: dict[tuple[str, str], RouteHint], method: str,
             raw_url: str, source: str, confidence: float) -> None:
        url = self._normalize(raw_url)
        if not url:
            return
        parsed = urllib.parse.urlparse(url)
        if (parsed.hostname or "").lower() != self.root_host:
            return
        method = method.upper()
        hint = RouteHint(
            method=method,
            url=url,
            source=source,
            confidence=confidence,
            mutating=method in {"POST", "PUT", "PATCH", "DELETE"},
        )
        key = (method, url)
        current = routes.get(key)
        if current is None or hint.confidence > current.confidence:
            routes[key] = hint

    def _normalize(self, raw: str) -> str:
        raw = raw.strip()
        if not raw or any(x in raw for x in ("${", "{{", "<%")):
            return ""
        absolute = urllib.parse.urljoin(self.root, raw)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            return ""
        if (parsed.hostname or "").lower() != self.root_host:
            return ""
        return urllib.parse.urldefrag(absolute)[0]

    @staticmethod
    def _endpointish(raw: str) -> bool:
        lower = raw.lower()
        if any(lower.endswith(ext) for ext in (
            ".js", ".css", ".jpg", ".jpeg", ".png", ".webp", ".svg", ".woff", ".woff2", ".ico"
        )):
            return False
        return any(token in lower for token in (
            "/api/", "/graphql", "/submit", "/contact", "/lead", "/form", "/webhook",
            "/auth", "/login", "/session", "/orders", "/users", "/account",
        ))
