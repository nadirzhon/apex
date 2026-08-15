import json

from apex.modules.go_core import import_events
from apex.store import Store


def test_import_go_core_jsonl(tmp_path):
    store = Store(tmp_path / "state.json")
    lines = [
        json.dumps({
            "type": "asset", "kind": "url", "value": "https://example.com",
            "source": "go-core", "meta": {"status": 200, "title": "Example"},
        }),
        json.dumps({"type": "summary", "total": 1, "successful": 1, "failed": 0}),
    ]

    summary = import_events(lines, store)

    assert summary["successful"] == 1
    asset = store.assets["url:https://example.com"]
    assert asset.source == "go-core"
    assert asset.meta["title"] == "Example"


def test_import_go_core_rejects_invalid_json(tmp_path):
    store = Store(tmp_path / "state.json")
    try:
        import_events(["not-json"], store)
    except RuntimeError as exc:
        assert "JSONL" in str(exc)
    else:
        raise AssertionError("invalid core output must fail closed")
