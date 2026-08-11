"""Тесты новых компонентов APEX: giants, llm-гейт, advisor."""
import pytest

from apex.scope import Scope
from apex.store import Store
from apex.models import Finding
from apex import giants
from apex.modules import llm
from apex import advisor


def _scope(authorized=True, in_scope=None):
    return Scope(program="test", authorized=authorized,
                 in_scope=in_scope or ["example.com", "https://example.com"])


def _store(tmp_path):
    return Store(tmp_path / "state.json")


# ── giants: каталог ──────────────────────────────────────────────────────
def test_giants_catalog_nonempty():
    progs = giants.list_programs()
    keys = {p["key"] for p in progs}
    assert {"anthropic", "openai", "microsoft", "xai", "google"} <= keys
    for p in progs:
        assert p["reward"] and p["platform"] and "prompt_injection" in p


# ── giants: гейт fail-closed ─────────────────────────────────────────────
def test_giants_hunt_refuses_without_authorization(tmp_path):
    with pytest.raises(PermissionError):
        giants.hunt("anthropic", _scope(authorized=False), _store(tmp_path), None, False)


def test_giants_hunt_unknown_program(tmp_path):
    with pytest.raises(ValueError):
        giants.hunt("nosuchgiant", _scope(), _store(tmp_path), None, True)


# ── llm: гейт fail-closed ────────────────────────────────────────────────
def test_llm_refuses_without_authorization(tmp_path):
    with pytest.raises(PermissionError):
        llm.run(_scope(authorized=False), _store(tmp_path), None, False,
                ["https://example.com"])


def test_llm_requires_target(tmp_path):
    with pytest.raises(ValueError):
        llm.run(_scope(), _store(tmp_path), None, True, [])


# ── advisor: маппинг и план ──────────────────────────────────────────────
def test_advisor_maps_prompt_injection():
    f = Finding(title="Prompt injection (tool_hijack)", severity="critical",
                target="x", module="llm")
    assert advisor._match(f) == "prompt_injection"


def test_advisor_maps_mcp_url_to_ssrf():
    f = Finding(title="Unconstrained `url` parameter on `page_fetch`",
                severity="medium", target="page_fetch", module="giants/mcp")
    assert advisor._match(f) == "ssrf"


def test_advisor_ssrf_playbook_exists():
    assert "ssrf" in advisor.PLAYBOOKS
    assert advisor.PLAYBOOKS["ssrf"].reward


def test_advise_produces_plan(tmp_path):
    store = _store(tmp_path)
    store.add_finding(Finding(title="Экспонирован /.env", severity="critical",
                              target="https://example.com/.env", module="secrets"))
    text = advisor.advise(store)
    assert "ПЛАН ДЕЙСТВИЙ" in text
    assert "example.com" in text
