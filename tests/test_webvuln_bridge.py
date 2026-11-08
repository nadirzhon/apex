"""Regression tests for the web-vuln-scanner bridge discovery and graceful degradation."""
from __future__ import annotations

import json
from pathlib import Path

from apex.modules import webvuln
from apex.scope import Scope


def _scope(tmp_path: Path) -> Scope:
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "program": "self-test",
        "authorized": True,
        "researcher": "ci",
        "rate_limit_rps": 2,
        "in_scope": ["example.com", "*.example.com"],
        "out_of_scope": [],
        "rules": "test",
    }))
    return Scope.load(str(p))


class _FakeStore:
    def __init__(self):
        self.added = []

    def add_finding(self, f):
        self.added.append(f)


def test_candidate_roots_prefers_env(monkeypatch):
    monkeypatch.setenv("APEX_WEBVULN_PATH", "/custom/path")
    roots = webvuln._candidate_roots()
    assert roots and str(roots[0]) == "/custom/path"


def test_candidate_roots_includes_sensible_defaults(monkeypatch):
    monkeypatch.delenv("APEX_WEBVULN_PATH", raising=False)
    roots = [str(r) for r in webvuln._candidate_roots()]
    # at least one plausible co-located default is probed
    assert any(r.endswith("web-vuln-scanner") for r in roots)


def test_import_scanner_missing_is_graceful(monkeypatch):
    monkeypatch.setattr(webvuln, "_candidate_roots", lambda: [Path("/nonexistent/xyz")])
    cls, reason = webvuln._import_scanner()
    assert cls is None
    assert reason and "web-vuln-scanner" in reason


def test_run_degrades_without_scanner(monkeypatch, tmp_path, capsys):
    """When the scanner is unavailable, run() returns [] and never raises a traceback."""
    monkeypatch.setattr(webvuln, "_candidate_roots", lambda: [Path("/nonexistent/xyz")])
    out = webvuln.run(_scope(tmp_path), _FakeStore(), None, True, ["https://example.com"])
    assert out == []
    assert "пропущено" in capsys.readouterr().out


def test_run_requires_explicit_targets(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        webvuln.run(_scope(tmp_path), _FakeStore(), None, True, [])
