import pytest

from apex.ascend.pipeline import AscendPipeline
from apex.browser_observer import (
    BrowserInventory,
    BrowserPolicy,
    BrowserSnapshot,
    FormDescriptor,
    FormField,
    NetworkEvent,
)
from apex.scope import Scope
from apex.store import Store


def snapshot():
    return BrowserSnapshot(
        url="https://app.example.test/",
        title="App",
        dom_sha256="a" * 64,
        links=("https://app.example.test/account", "https://app.example.test/orders?id=7"),
        forms=(
            FormDescriptor(
                action="https://app.example.test/contact",
                method="POST",
                fields=(FormField("email", "email", True), FormField("message", "textarea", True)),
            ),
        ),
        network=(
            NetworkEvent("GET", "https://app.example.test/api/me", "fetch", 200),
            NetworkEvent("POST", "https://app.example.test/api/telemetry", "fetch", 0, True,
                         "mutating method blocked"),
            NetworkEvent("GET", "https://cdn.other.test/a.js", "script", 0, True,
                         "cross-origin request blocked"),
        ),
        storage_keys=("theme", "session_hint"),
    )


def test_policy_never_allows_mutating_method():
    with pytest.raises(ValueError):
        BrowserPolicy(allowed_methods=frozenset({"GET", "POST"}))


def test_inventory_models_observed_gets_and_forms_without_submission():
    inv = BrowserInventory("https://app.example.test/")
    inv.add(snapshot())
    rows = inv.endpoint_records()
    methods_urls = {(r["method"], r["url"]) for r in rows}
    assert ("GET", "https://app.example.test/") in methods_urls
    assert ("GET", "https://app.example.test/api/me") in methods_urls
    assert ("POST", "https://app.example.test/contact") in methods_urls
    assert ("POST", "https://app.example.test/api/telemetry") not in methods_urls
    form = next(r for r in rows if r["method"] == "POST")
    assert form["mutates_state"] is True
    assert form["params"] == ["email", "message"]


def test_inventory_rejects_cross_origin_snapshot():
    inv = BrowserInventory("https://app.example.test/")
    bad = BrowserSnapshot("https://evil.test/", "x", "b" * 64, (), (), ())
    with pytest.raises(PermissionError):
        inv.add(bad)


def test_browser_inventory_feeds_ascend_scope_gated_model(tmp_path):
    inv = BrowserInventory("https://app.example.test/")
    inv.add(snapshot())
    scope = Scope(program="owned", authorized=True, in_scope=["app.example.test"])
    pl = AscendPipeline(scope, Store(tmp_path / "state.json"), authorized=True)
    pl.ingest_browser_inventory(inv)
    assert "GET /api/me" in pl.awm.nodes
    assert "POST /contact" in pl.awm.nodes
    assert pl.twin.endpoints["POST /contact"].mutates_state is True


def test_query_parameters_become_object_candidates():
    snap = BrowserSnapshot(
        url="https://app.example.test/orders?id=7&view=full",
        title="Orders", dom_sha256="c" * 64, links=(), forms=(), network=(),
    )
    inv = BrowserInventory("https://app.example.test/")
    inv.add(snap)
    row = next(r for r in inv.endpoint_records() if "/orders" in r["url"])
    assert row["params"] == ["id", "view"]


def test_snapshot_fingerprint_is_stable():
    assert snapshot().fingerprint == snapshot().fingerprint
