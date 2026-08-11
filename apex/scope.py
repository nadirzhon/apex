"""Scope-движок — сердце APEX и главный предохранитель.

APEX не отправит НИ ОДНОГО запроса к цели, пока она не подтверждена как
входящая в scope авторизованной программы bug bounty. Fail-closed: любое
сомнение — запрет.

Формат scope-файла (JSON):
{
  "program": "Example Corp VDP",
  "platform": "hackerone",
  "authorized": true,
  "researcher": "nadirzhon",
  "rate_limit_rps": 2,
  "in_scope":  ["*.example.com", "api.example.com", "com.example.app"],
  "out_of_scope": ["blog.example.com", "*.dev.example.com"],
  "rules": "No DoS. No social engineering. Non-destructive testing only."
}
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Scope:
    program: str
    authorized: bool = False
    researcher: str = ""
    platform: str = ""
    rate_limit_rps: float = 2.0
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rules: str = ""
    _path: str = ""

    # ── загрузка ──────────────────────────────────────────────────────────
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(
            program=data.get("program", ""),
            authorized=bool(data.get("authorized", False)),
            researcher=data.get("researcher", ""),
            platform=data.get("platform", ""),
            rate_limit_rps=float(data.get("rate_limit_rps", 2.0)),
            in_scope=[s.strip().lower() for s in data.get("in_scope", [])],
            out_of_scope=[s.strip().lower() for s in data.get("out_of_scope", [])],
            rules=data.get("rules", ""),
            _path=str(p),
        )

    # ── проверка авторизации ──────────────────────────────────────────────
    def assert_ready(self, authorized_flag: bool) -> None:
        """Бросает PermissionError, если движок не готов отправлять трафик."""
        if not self.in_scope:
            raise PermissionError("scope пуст: in_scope не задан")
        if not self.authorized:
            raise PermissionError(
                "scope не помечен authorized:true — подтвердите право на "
                "тестирование этой программы в scope-файле"
            )
        if not authorized_flag:
            raise PermissionError(
                "нет флага --i-am-authorized — запуск разрешён только при "
                "явном подтверждении оператора"
            )

    # ── принадлежность цели ──────────────────────────────────────────────
    @staticmethod
    def _host_of(target: str) -> str:
        t = target.strip().lower()
        if "://" in t:
            t = urlparse(t).hostname or ""
        # обрезать порт/путь для голого host
        t = t.split("/")[0].split(":")[0]
        return t

    def _matches(self, host: str, patterns: list[str]) -> bool:
        for pat in patterns:
            # wildcard-домен *.example.com покрывает и сам example.com
            if pat.startswith("*."):
                base = pat[2:]
                if host == base or host.endswith("." + base):
                    return True
            elif fnmatch.fnmatch(host, pat) or host == pat:
                return True
        return False

    def is_apk_in_scope(self, package: str) -> bool:
        pkg = package.strip().lower()
        # мобильные пакеты вида com.example.app сверяем как строки/паттерны
        if self._matches(pkg, self.out_of_scope):
            return False
        return self._matches(pkg, self.in_scope)

    def in_scope_target(self, target: str) -> bool:
        """True только если host входит в in_scope и НЕ в out_of_scope."""
        host = self._host_of(target)
        if not host:
            # возможно, это идентификатор пакета мобильного приложения
            return self.is_apk_in_scope(target)
        if self._matches(host, self.out_of_scope):
            return False
        return self._matches(host, self.in_scope)

    def guard(self, target: str) -> None:
        """Бросает PermissionError, если цель вне scope."""
        if not self.in_scope_target(target):
            raise PermissionError(
                f"цель '{target}' ВНЕ scope программы «{self.program}» — отказ"
            )

    def summary(self) -> str:
        return (
            f"программа: {self.program or '—'} ({self.platform or '—'})\n"
            f"authorized: {self.authorized}  researcher: {self.researcher or '—'}\n"
            f"in_scope: {', '.join(self.in_scope) or '—'}\n"
            f"out_of_scope: {', '.join(self.out_of_scope) or '—'}\n"
            f"rate_limit: {self.rate_limit_rps} rps\n"
            f"rules: {self.rules or '—'}"
        )
