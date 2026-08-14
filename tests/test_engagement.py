import json
import os
import tempfile
from pathlib import Path

from apex.engagement import AccountRef, EngagementManifest
from apex.scope import Scope


def _write_manifest(root: Path, data):
    path = root / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _raises(exc_type, fn, contains=""):
    try:
        fn()
    except exc_type as exc:
        if contains:
            assert contains in str(exc)
        return
    raise AssertionError(f"expected {exc_type.__name__}")


def test_manifest_requires_targets():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scope.json").write_text("{}", encoding="utf-8")
        path = _write_manifest(root, {"scope_file": "scope.json", "targets": []})
        _raises(ValueError, lambda: EngagementManifest.load(path), "at least one target")


def test_manifest_fails_closed_on_out_of_scope_target():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scope.json").write_text("{}", encoding="utf-8")
        path = _write_manifest(root, {
            "scope_file": "scope.json",
            "targets": ["https://other.example/path"],
        })
        manifest = EngagementManifest.load(path)
        scope = Scope(program="T", authorized=True, in_scope=["allowed.example"])
        _raises(PermissionError, lambda: manifest.validate_against_scope(scope))


def test_active_validation_is_explicit_opt_in():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scope.json").write_text("{}", encoding="utf-8")
        path = _write_manifest(root, {
            "scope_file": "scope.json",
            "targets": ["https://allowed.example"],
            "modules": ["webvuln"],
            "policy": {"active_web_validation": False},
        })
        manifest = EngagementManifest.load(path)
        scope = Scope(program="T", authorized=True, in_scope=["allowed.example"])
        _raises(
            PermissionError,
            lambda: manifest.validate_against_scope(scope),
            "active validation",
        )


def test_account_headers_resolve_from_env():
    old = os.environ.get("APEX_TEST_HEADERS")
    os.environ["APEX_TEST_HEADERS"] = '{"Cookie":"s=test"}'
    try:
        ref = AccountRef("attacker", "APEX_TEST_HEADERS")
        assert ref.headers() == {"Cookie": "s=test"}
        assert ref.single_header() == "Cookie: s=test"
    finally:
        if old is None:
            os.environ.pop("APEX_TEST_HEADERS", None)
        else:
            os.environ["APEX_TEST_HEADERS"] = old


if __name__ == "__main__":
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); n += 1; print(f"  ok  {name}")
    print(f"\n{n} engagement tests passed")
