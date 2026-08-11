"""Тесты ядра: scope-гейт, CVSS, детект секретов. Запуск: python -m pytest -q
(или python tests/test_core.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apex.scope import Scope
from apex.models import cvss31_base, Severity
from apex.modules.secrets import _scan_text


def _scope():
    return Scope(
        program="T", authorized=True, in_scope=["*.example.com", "com.example.app"],
        out_of_scope=["blog.example.com", "*.staging.example.com"],
    )


def test_scope_wildcard_and_apex():
    s = _scope()
    assert s.in_scope_target("example.com")            # апекс покрыт *.example.com
    assert s.in_scope_target("https://api.example.com/x")
    assert s.in_scope_target("a.b.example.com")


def test_scope_out_of_scope_wins():
    s = _scope()
    assert not s.in_scope_target("blog.example.com")
    assert not s.in_scope_target("x.staging.example.com")
    assert not s.in_scope_target("evil.com")


def test_scope_apk():
    s = _scope()
    assert s.is_apk_in_scope("com.example.app")
    assert not s.is_apk_in_scope("com.other.app")


def test_guard_raises():
    s = _scope()
    raised = False
    try:
        s.guard("evil.com")
    except PermissionError:
        raised = True
    assert raised


def test_assert_ready_requires_flag():
    s = _scope()
    for bad in (lambda: s.assert_ready(False),):
        try:
            bad(); assert False, "должно было бросить"
        except PermissionError:
            pass
    s.assert_ready(True)  # ок


def test_cvss_critical():
    score, sev = cvss31_base("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8 and sev == Severity.CRITICAL.value


def test_cvss_scope_changed():
    score, _ = cvss31_base("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0


def test_secret_detection_and_mask():
    fs = _scan_text('const k="AKIAIOSFODNN7EXAMPLE";', "u")
    assert any("AWS Access Key" in f.title for f in fs)
    assert "AKIAIOSFODNN7EXAMPLE" not in fs[0].evidence  # замаскировано


if __name__ == "__main__":
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); n += 1; print(f"  ok  {name}")
    print(f"\n{n} тестов пройдено")
