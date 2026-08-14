"""Offline self-checks used before an autonomous engagement starts."""
from __future__ import annotations

import importlib
from dataclasses import dataclass

from .scope import Scope


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


def _expect_permission(fn) -> bool:
    try:
        fn()
    except PermissionError:
        return True
    return False


def run() -> list[Check]:
    checks: list[Check] = []

    modules = [
        "apex.scope",
        "apex.store",
        "apex.report",
        "apex.advisor",
        "apex.ascend.pipeline",
        "apex.engagement",
        "apex.quality",
    ]
    for name in modules:
        try:
            importlib.import_module(name)
            checks.append(Check(f"import:{name}", True))
        except Exception as exc:
            checks.append(Check(f"import:{name}", False, repr(exc)))

    scope = Scope(program="selfcheck", authorized=True, in_scope=["allowed.example"])
    checks.append(Check(
        "scope:operator-confirmation",
        _expect_permission(lambda: scope.assert_ready(False)),
        "assert_ready(False) must fail closed",
    ))
    checks.append(Check(
        "scope:out-of-scope",
        _expect_permission(lambda: scope.guard("https://outside.example")),
        "guard(outside) must fail closed",
    ))
    checks.append(Check(
        "scope:in-scope",
        scope.in_scope_target("https://allowed.example/path"),
        "configured in-scope target must be recognized",
    ))
    return checks


def assert_healthy() -> list[Check]:
    checks = run()
    failed = [item for item in checks if not item.ok]
    if failed:
        detail = "; ".join(f"{item.name}: {item.detail}" for item in failed)
        raise ValueError(f"APEX preflight failed: {detail}")
    return checks
