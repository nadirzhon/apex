"""Safe browser observation for modern JS/SPA applications.

The observer is discovery-only: it records DOM structure, same-origin links, forms,
and browser network activity while blocking mutating HTTP methods. It is designed to
feed provenance-backed APEX models without submitting forms or executing exploit
payloads. Playwright support is optional; pure-data normalization stays stdlib-only.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

from .scope import Scope


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower()


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return (pa.scheme.lower(), (pa.hostname or "").lower(), pa.port) == (
        pb.scheme.lower(), (pb.hostname or "").lower(), pb.port
    )


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True)
class FormField:
    name: str
    field_type: str = "text"
    required: bool = False


@dataclass(frozen=True)
class FormDescriptor:
    action: str
    method: str
    fields: tuple[FormField, ...] = ()

    @property
    def mutating(self) -> bool:
        return self.method.upper() not in SAFE_METHODS


@dataclass(frozen=True)
class NetworkEvent:
    method: str
    url: str
    resource_type: str = ""
    status: int = 0
    blocked: bool = False
    reason: str = ""


@dataclass(frozen=True)
class BrowserSnapshot:
    url: str
    title: str
    dom_sha256: str
    links: tuple[str, ...]
    forms: tuple[FormDescriptor, ...]
    network: tuple[NetworkEvent, ...]
    storage_keys: tuple[str, ...] = ()
    console_errors: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        return _stable_hash({
            "url": self.url,
            "title": self.title,
            "dom_sha256": self.dom_sha256,
            "links": self.links,
            "forms": [
                {"action": f.action, "method": f.method,
                 "fields": [(x.name, x.field_type, x.required) for x in f.fields]}
                for f in self.forms
            ],
            "network": [e.__dict__ for e in self.network],
            "storage_keys": self.storage_keys,
        })


@dataclass(frozen=True)
class BrowserPolicy:
    max_pages: int = 12
    allow_cross_origin_subresources: bool = False
    allowed_methods: frozenset[str] = frozenset(SAFE_METHODS)

    def __post_init__(self) -> None:
        if self.max_pages <= 0:
            raise ValueError("max_pages must be positive")
        if any(m.upper() not in SAFE_METHODS for m in self.allowed_methods):
            raise ValueError("browser observation policy cannot allow mutating methods")


class BrowserInventory:
    """Normalize browser snapshots into endpoint/model inputs for APEX."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.snapshots: dict[str, BrowserSnapshot] = {}

    def add(self, snapshot: BrowserSnapshot) -> None:
        if not _same_origin(self.root, snapshot.url):
            raise PermissionError("snapshot is outside browser inventory origin")
        self.snapshots[snapshot.url] = snapshot

    def endpoint_records(self) -> list[dict[str, Any]]:
        records: dict[tuple[str, str], dict[str, Any]] = {}
        for snap in self.snapshots.values():
            self._add_record(records, "GET", snap.url, source="navigation")
            for event in snap.network:
                if event.blocked or event.method.upper() not in SAFE_METHODS:
                    continue
                if not _same_origin(self.root, event.url):
                    continue
                self._add_record(records, event.method.upper(), event.url,
                                 source=f"browser:{event.resource_type or 'network'}",
                                 status=event.status)
            for form in snap.forms:
                if not _same_origin(self.root, form.action):
                    continue
                # Forms are modeled as attack-surface facts even when mutation is blocked.
                key = (form.method.upper(), form.action)
                records[key] = {
                    "key": f"{form.method.upper()} {urllib.parse.urlparse(form.action).path or '/'}",
                    "method": form.method.upper(),
                    "url": form.action,
                    "status": 0,
                    "params": [f.name for f in form.fields if f.name],
                    "mutates_state": form.mutating,
                    "attrs": {
                        "source": "browser:form",
                        "field_types": {f.name: f.field_type for f in form.fields if f.name},
                        "required_fields": [f.name for f in form.fields if f.required and f.name],
                    },
                }
        return sorted(records.values(), key=lambda r: (r["url"], r["method"]))

    @staticmethod
    def _add_record(records: dict, method: str, url: str, *, source: str, status: int = 0) -> None:
        parsed = urllib.parse.urlparse(url)
        params = sorted(urllib.parse.parse_qs(parsed.query).keys())
        clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
        records[(method, clean)] = {
            "key": f"{method} {parsed.path or '/'}",
            "method": method,
            "url": clean,
            "status": status,
            "params": params,
            "mutates_state": method not in SAFE_METHODS,
            "attrs": {"source": source},
        }


class PlaywrightObserver:
    """Optional safe Playwright adapter.

    Navigation is same-origin only. Mutating methods are aborted at the browser
    routing layer. Cross-origin subresources are blocked unless policy explicitly
    permits them; cross-origin navigations are always rejected.
    """

    def __init__(self, scope: Scope, root: str, authorized: bool,
                 *, policy: BrowserPolicy | None = None) -> None:
        scope.assert_ready(authorized)
        scope.guard(root)
        if urllib.parse.urlparse(root).scheme.lower() != "https":
            raise ValueError("browser production observation requires https:// root")
        self.scope = scope
        self.root = root.rstrip("/") + "/"
        self.policy = policy or BrowserPolicy()

    def observe(self) -> BrowserInventory:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - optional runtime dependency
            raise RuntimeError("install APEX with the 'browser' extra and run playwright install chromium") from exc

        inventory = BrowserInventory(self.root)
        queue = [self.root]
        seen: set[str] = set()
        network: list[NetworkEvent] = []

        with sync_playwright() as p:  # pragma: no cover - browser integration
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            def route_handler(route):
                req = route.request
                method = req.method.upper()
                url = req.url
                if method not in self.policy.allowed_methods:
                    network.append(NetworkEvent(method, url, req.resource_type, blocked=True,
                                                reason="mutating method blocked"))
                    return route.abort()
                if not _same_origin(self.root, url) and not self.policy.allow_cross_origin_subresources:
                    network.append(NetworkEvent(method, url, req.resource_type, blocked=True,
                                                reason="cross-origin request blocked"))
                    return route.abort()
                return route.continue_()

            page.route("**/*", route_handler)
            page.on("response", lambda response: network.append(NetworkEvent(
                response.request.method.upper(), response.url, response.request.resource_type,
                response.status, False, ""
            )))

            while queue and len(seen) < self.policy.max_pages:
                url = queue.pop(0)
                if url in seen:
                    continue
                self.scope.guard(url)
                if not _same_origin(self.root, url):
                    continue
                seen.add(url)
                network.clear()
                page.goto(url, wait_until="domcontentloaded")
                if not _same_origin(self.root, page.url):
                    raise PermissionError("cross-origin browser navigation blocked")

                raw = page.evaluate("""() => ({
                    title: document.title,
                    html: document.documentElement.outerHTML,
                    links: [...document.querySelectorAll('a[href]')].map(a => a.href),
                    forms: [...document.forms].map(f => ({
                      action: f.action || location.href,
                      method: (f.method || 'get').toUpperCase(),
                      fields: [...f.elements].filter(e => e.name).map(e => ({
                        name: e.name,
                        field_type: e.type || e.tagName.toLowerCase(),
                        required: !!e.required
                      }))
                    })),
                    storage_keys: [...Object.keys(localStorage), ...Object.keys(sessionStorage)]
                })""")
                links = tuple(sorted({
                    urllib.parse.urldefrag(x)[0] for x in raw["links"]
                    if _same_origin(self.root, x)
                }))
                forms = tuple(FormDescriptor(
                    action=f["action"], method=f["method"],
                    fields=tuple(FormField(x["name"], x["field_type"], bool(x["required"])) for x in f["fields"]),
                ) for f in raw["forms"])
                snap = BrowserSnapshot(
                    url=page.url,
                    title=raw["title"],
                    dom_sha256=hashlib.sha256(raw["html"].encode("utf-8", "replace")).hexdigest(),
                    links=links,
                    forms=forms,
                    network=tuple(network),
                    storage_keys=tuple(sorted(set(raw["storage_keys"]))),
                )
                inventory.add(snap)
                for link in links:
                    if link not in seen and len(seen) + len(queue) < self.policy.max_pages * 2:
                        queue.append(link)

            browser.close()
        return inventory
