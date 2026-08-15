"""Passive route-intelligence for already-fetched loopback lab HTML.

No requests are sent here. The helper extracts same-origin route literals from
HTML attributes and inline JavaScript and can resolve simple dynamic ID routes
against numeric identifiers already observed in the response body.
"""
from __future__ import annotations

import re
import urllib.parse
from html.parser import HTMLParser


_CALL_PREFIXES = (
    re.compile(r'''\bfetch\s*\(\s*["'`]([^"'`]{1,240})["'`]''', re.I),
    re.compile(r'''\baxios(?:\.(?:get|post|put|patch|delete))?\s*\(\s*["'`]([^"'`]{1,240})["'`]''', re.I),
    re.compile(r'''\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`]{1,240})["'`]''', re.I),
)
_ROUTE_LITERAL = re.compile(
    r'''["'`]((?:https?://[^"'`\s<>]{3,300}|/[A-Za-z0-9_~!$&()*+,;=:@%./?\[\]-]{2,300}))["'`]'''
)
_DYNAMIC_SANDWICH = re.compile(
    r'''["'`](/[^"'`\r\n]{1,180})["'`]\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*["'`]([^"'`\r\n]{0,120})["'`]'''
)
_DYNAMIC_PREFIX = re.compile(
    r'''["'`](/[^"'`\r\n]{1,180}(?:/|=))["'`]\s*\+'''
)
_ENDPOINT_WORDS = ("order", "trade", "account", "user", "profile", "api", "detail", "view", "receipt")
_SECRETISH = re.compile(r"(?i)(authorization|bearer|api[_-]?key|secret|token)\s*[:=]\s*[^,;}\r\n]{1,160}")


class _AttrParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        for key, value in attrs:
            if not value:
                continue
            k = (key or "").lower()
            if k in {"href", "action", "formaction", "data-url", "data-href", "data-endpoint", "data-route"}:
                self.values.append(value)
            elif k.startswith("on") or k.startswith("data-"):
                self.values.extend(m.group(1) for m in _ROUTE_LITERAL.finditer(value))


def _same_origin(root: str, url: str) -> bool:
    a, b = urllib.parse.urlparse(root), urllib.parse.urlparse(url)
    return (a.scheme, (a.hostname or "").lower(), a.port) == (
        b.scheme, (b.hostname or "").lower(), b.port
    )


def _endpointish(raw: str) -> bool:
    low = raw.lower()
    if low.startswith(('/static/', '/assets/', '/css/', '/js/')):
        return False
    return any(word in low for word in _ENDPOINT_WORDS)


def extract_same_origin_hints(
    root: str,
    page_url: str,
    body: str,
    *,
    numeric_ids: tuple[str, ...] = (),
    limit: int = 48,
) -> tuple[str, ...]:
    """Extract bounded same-origin endpoint candidates from observed markup/script."""
    raw: list[str] = []
    parser = _AttrParser()
    parser.feed(body)
    raw.extend(parser.values)
    for rx in _CALL_PREFIXES:
        raw.extend(m.group(1) for m in rx.finditer(body))
    raw.extend(m.group(1) for m in _ROUTE_LITERAL.finditer(body) if _endpointish(m.group(1)))

    # Resolve common dynamic client routes, including '/order/' + id + '/receipt'.
    sandwich_spans: list[tuple[int, int]] = []
    for m in _DYNAMIC_SANDWICH.finditer(body):
        prefix, suffix = m.group(1), m.group(2)
        if not _endpointish(prefix + suffix):
            continue
        sandwich_spans.append(m.span())
        for oid in numeric_ids[:4]:
            raw.append(prefix + oid + suffix)

    # Prefix-only fallback when there is no literal suffix.
    for m in _DYNAMIC_PREFIX.finditer(body):
        if any(a <= m.start() and m.end() <= b for a, b in sandwich_spans):
            continue
        prefix = m.group(1)
        if not _endpointish(prefix):
            continue
        for oid in numeric_ids[:4]:
            raw.append(prefix + oid)

    out: list[str] = []
    for value in raw:
        value = value.strip()
        if not value or value.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        if '${' in value or '{{' in value or '<%' in value:
            continue
        absolute = urllib.parse.urljoin(page_url, value)
        absolute = urllib.parse.urldefrag(absolute)[0]
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in {'http', 'https'} or not _same_origin(root, absolute):
            continue
        if not _endpointish(parsed.path + ('?' + parsed.query if parsed.query else '')):
            continue
        if absolute not in out:
            out.append(absolute)
        if len(out) >= limit:
            break
    return tuple(out)


def extract_route_contexts(body: str, *, limit: int = 12, radius: int = 180) -> tuple[str, ...]:
    """Return short redacted excerpts around endpoint-looking route literals."""
    contexts: list[str] = []
    positions: list[tuple[int, int]] = []
    for rx in (*_CALL_PREFIXES, _DYNAMIC_SANDWICH, _DYNAMIC_PREFIX):
        for match in rx.finditer(body):
            value = match.group(1)
            if _endpointish(value):
                positions.append(match.span())
    for match in _ROUTE_LITERAL.finditer(body):
        if _endpointish(match.group(1)):
            positions.append(match.span())
    for start, end in sorted(positions):
        excerpt = body[max(0, start - radius): min(len(body), end + radius)]
        excerpt = _SECRETISH.sub(lambda m: m.group(1) + '=<redacted>', excerpt)
        excerpt = ' '.join(excerpt.split())
        if excerpt and excerpt not in contexts:
            contexts.append(excerpt[:700])
        if len(contexts) >= limit:
            break
    return tuple(contexts)
