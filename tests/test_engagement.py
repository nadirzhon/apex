import json

import pytest

from apex.engagement import AccountRef, EngagementManifest
from apex.scope import Scope


def _write_manifest(tmp_path, data):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_manifest_requires_targets(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text("{}", encoding="utf-8")
    path = _write_manifest(tmp_path, {"scope_file": "scope.json", "targets": []})
    with pytest.raises(ValueError, match="at least one target"):
        EngagementManifest.load(path)


def test_manifest_fails_closed_on_out_of_scope_target(tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    path = _write_manifest(tmp_path, {
        "scope_file": "scope.json",
        "targets": ["https://other.example/path"],
    })
    manifest = EngagementManifest.load(path)
    scope = Scope(program="T", authorized=True, in_scope=["allowed.example"])
    with pytest.raises(PermissionError):
        manifest.validate_against_scope(scope)


def test_active_validation_is_explicit_opt_in(tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    path = _write_manifest(tmp_path, {
        "scope_file": "scope.json",
        "targets": ["https://allowed.example"],
        "modules": ["webvuln"],
        "policy": {"active_web_validation": False},
    })
    manifest = EngagementManifest.load(path)
    scope = Scope(program="T", authorized=True, in_scope=["allowed.example"])
    with pytest.raises(PermissionError, match="active validation"):
        manifest.validate_against_scope(scope)


def test_account_headers_resolve_from_env(monkeypatch):
    monkeypatch.setenv("APEX_TEST_HEADERS", '{"Cookie":"s=test"}')
    ref = AccountRef("attacker", "APEX_TEST_HEADERS")
    assert ref.headers() == {"Cookie": "s=test"}
    assert ref.single_header() == "Cookie: s=test"
