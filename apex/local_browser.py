"""Loopback-only browser exploration for isolated web security benchmarks.

Unlike the production observer, this module may exercise client-side controls to
learn SPA routes and request shapes.  It remains non-destructive at the network
boundary: every mutating HTTP request is aborted before it leaves Chromium.  The
module refuses non-loopback roots and cross-origin navigation/subresources.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from .local_lab import assert_loopback_target

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


@dataclass(frozen=True)
class BrowserRequestFact:
    method: str
    url: str
    resource_type: str
    blocked: bool
    status: int = 0


@dataclass(frozen=True)
class ControlFact:
    kind: str
    selector: str
    name: str = ""
    field_type: str = ""
    placeholder: str = ""
    text: str = ""


@dataclass(frozen=True)
class LocalBrowserSnapshot:
    url: str
    title: str
    dom_sha256: str
    links: tuple[str, ...]
    controls: tuple[ControlFact, ...]
    requests: tuple[BrowserRequestFact, ...]
    storage_keys: tuple[str, ...] = ()


@dataclass
class LocalBrowserInventory:
    root: str
    snapshots: list[LocalBrowserSnapshot] = field(default_factory=list)
    blocked_mutations: list[BrowserRequestFact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    def endpoint_hints(self) -> list[dict[str, Any]]:
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for snap in self.snapshots:
            for fact in snap.requests:
                if not _same_origin(self.root, fact.url):
                    continue
                parsed = urllib.parse.urlparse(fact.url)
                clean = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, "")
                )
                key = (fact.method, clean)
                out[key] = {
                    "method": fact.method,
                    "url": clean,
                    "path": parsed.path or "/",
                    "params": sorted(urllib.parse.parse_qs(parsed.query).keys()),
                    "blocked_mutation": fact.blocked and fact.method not in _SAFE_METHODS,
                    "resource_type": fact.resource_type,
                }
        return sorted(out.values(), key=lambda x: (x["url"], x["method"]))


class LocalPlaywrightExplorer:
    def __init__(self, root: str, *, max_pages: int = 8, max_actions: int = 24) -> None:
        assert_loopback_target(root)
        self.root = root.rstrip("/") + "/"
        self.max_pages = max(1, int(max_pages))
        self.max_actions = max(0, int(max_actions))

    @staticmethod
    def _safe_fill_value(field_type: str, name: str) -> str:
        low = (field_type or "").lower()
        lname = (name or "").lower()
        if low == "email" or "email" in lname:
            return "apex-discovery@example.invalid"
        if low == "number":
            return "1"
        if low in {"checkbox", "radio", "file", "hidden", "submit", "button"}:
            return ""
        if low == "password" or "pass" in lname:
            return "APEX_DISCOVERY"
        return "APEX_DISCOVERY"

    def observe(self) -> LocalBrowserInventory:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("install playwright and chromium for local browser exploration") from exc

        inventory = LocalBrowserInventory(self.root)
        queue = [self.root]
        seen: set[str] = set()
        action_count = 0

        with sync_playwright() as p:  # pragma: no cover - integration only
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            while queue and len(seen) < self.max_pages:
                requested = queue.pop(0)
                if requested in seen or not _same_origin(self.root, requested):
                    continue
                seen.add(requested)
                page = context.new_page()
                request_facts: list[BrowserRequestFact] = []

                def route_handler(route):
                    req = route.request
                    method = req.method.upper()
                    url = req.url
                    if not _same_origin(self.root, url):
                        request_facts.append(BrowserRequestFact(method, url, req.resource_type, True, 0))
                        return route.abort()
                    if method not in _SAFE_METHODS:
                        fact = BrowserRequestFact(method, url, req.resource_type, True, 0)
                        request_facts.append(fact)
                        inventory.blocked_mutations.append(fact)
                        return route.abort()
                    return route.continue_()

                page.route("**/*", route_handler)
                page.on("response", lambda r: request_facts.append(BrowserRequestFact(
                    r.request.method.upper(), r.url, r.request.resource_type, False, r.status
                )))
                try:
                    page.goto(requested, wait_until="networkidle", timeout=20_000)
                except Exception as exc:
                    inventory.notes.append(f"navigation warning {requested}: {type(exc).__name__}")
                if not _same_origin(self.root, page.url):
                    page.close()
                    continue

                raw = page.evaluate("""() => {
                    const esc = (s) => (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/[^a-zA-Z0-9_-]/g, '\\$&');
                    const controls = [...document.querySelectorAll('input,textarea,select,button,[role="button"]')].slice(0,80).map((e, i) => {
                      let selector = '';
                      if (e.id) selector = '#' + esc(e.id);
                      else if (e.name) selector = e.tagName.toLowerCase() + '[name="' + String(e.name).replace(/"/g,'\\"') + '"]';
                      else selector = e.tagName.toLowerCase() + ':nth-of-type(' + ([...e.parentElement.children].filter(x => x.tagName===e.tagName).indexOf(e)+1) + ')';
                      return {kind:e.tagName.toLowerCase(),selector,name:e.name||'',field_type:e.type||'',placeholder:e.placeholder||'',text:(e.innerText||e.value||'').trim().slice(0,160)};
                    });
                    return {
                      title: document.title,
                      html: document.documentElement.outerHTML,
                      links: [...document.querySelectorAll('a[href]')].map(a => a.href),
                      controls,
                      storage_keys: [...Object.keys(localStorage), ...Object.keys(sessionStorage)]
                    };
                }""")
                controls = tuple(ControlFact(**x) for x in raw["controls"])

                # Exercise a bounded subset of controls. Text-like fields receive a
                # harmless sentinel. Submit/button clicks are allowed to run client
                # logic, but mutating network calls are aborted by route_handler.
                for control in controls:
                    if action_count >= self.max_actions:
                        break
                    try:
                        loc = page.locator(control.selector).first
                        if loc.count() == 0 or not loc.is_visible(timeout=500):
                            continue
                        if control.kind in {"input", "textarea"}:
                            value = self._safe_fill_value(control.field_type, control.name)
                            if value:
                                loc.fill(value, timeout=1000)
                                action_count += 1
                        elif control.kind == "select":
                            options = loc.locator("option")
                            if options.count() > 1:
                                loc.select_option(index=1, timeout=1000)
                                action_count += 1
                    except Exception:
                        continue

                # Click a few likely action controls after filling; mutations cannot
                # leave the browser, but their attempted endpoint becomes evidence.
                for control in controls:
                    if action_count >= self.max_actions:
                        break
                    if control.kind != "button" and control.field_type not in {"submit", "button"}:
                        continue
                    try:
                        loc = page.locator(control.selector).first
                        if loc.count() and loc.is_visible(timeout=500):
                            loc.click(timeout=1500, no_wait_after=True)
                            page.wait_for_timeout(250)
                            action_count += 1
                    except Exception:
                        continue

                links = tuple(sorted({
                    urllib.parse.urldefrag(x)[0]
                    for x in raw["links"]
                    if _same_origin(self.root, x)
                }))
                snapshot = LocalBrowserSnapshot(
                    url=page.url,
                    title=raw["title"],
                    dom_sha256=hashlib.sha256(raw["html"].encode("utf-8", "replace")).hexdigest(),
                    links=links,
                    controls=controls,
                    requests=tuple(request_facts),
                    storage_keys=tuple(sorted(set(raw["storage_keys"]))),
                )
                inventory.snapshots.append(snapshot)
                for link in links:
                    if link not in seen and len(queue) < self.max_pages * 2:
                        queue.append(link)
                page.close()

            browser.close()
        return inventory
