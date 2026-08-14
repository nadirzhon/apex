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


# ── webvuln: серьёзные классы ────────────────────────────────────────────
def test_webvuln_gate_and_target():
    from apex.modules import webvuln
    import pytest as _p
    # без авторизации — отказ
    with _p.raises(PermissionError):
        webvuln.run(_scope(authorized=False), Store("/tmp/x.json"), None, False, ["http://x"])
    # без цели — ошибка (активные payload'ы не по угадайке)
    with _p.raises(ValueError):
        webvuln.run(_scope(), Store("/tmp/x.json"), None, True, [])


def test_advisor_maps_sqli_and_xss():
    fs = Finding(title="SQL Injection: param=id", severity="critical", target="x", module="webvuln")
    fx = Finding(title="Reflected XSS: param=q", severity="high", target="x", module="webvuln")
    assert advisor._match(fs) == "sqli"
    assert advisor._match(fx) == "xss"
    assert "sqli" in advisor.PLAYBOOKS and "xss" in advisor.PLAYBOOKS
    assert "critical" in advisor.PLAYBOOKS["sqli"].reward.lower()


# ── arsenal: боевые инструменты под гейтом ───────────────────────────────
def test_arsenal_gate():
    from apex.modules import arsenal
    import pytest as _p
    with _p.raises(PermissionError):
        arsenal.run_nuclei(_scope(authorized=False), Store("/tmp/x.json"), False, ["http://x"])
    with _p.raises(PermissionError):
        arsenal.run_sqlmap(_scope(authorized=False), Store("/tmp/x.json"), False, ["http://x"])


def test_arsenal_have_detects_tools(monkeypatch):
    from apex.modules import arsenal

    def fake_which(tool):
        return f"/usr/bin/{tool}" if tool == "sqlmap" else None

    monkeypatch.setattr(arsenal.shutil, "which", fake_which)
    assert arsenal.have("sqlmap") is True
    assert arsenal.have("nonexistent_tool_xyz") is False


# ── kali: мост к контейнеру под гейтом ───────────────────────────────────
def test_kali_gate():
    from apex.modules import kali
    import pytest as _p
    with _p.raises(PermissionError):
        kali.run_ffuf(_scope(authorized=False), Store("/tmp/x.json"), False, "http://x")
    with _p.raises(PermissionError):
        kali.run_nuclei(_scope(authorized=False), Store("/tmp/x.json"), False, "http://x")


def test_kali_available_is_bool():
    from apex.modules import kali
    assert isinstance(kali.kali_available(), bool)
