"""Declarative engagement configuration for APEX autonomous runs.

The manifest contains targets, module selection and references to locally supplied
account headers. Secrets are never stored in the manifest: account headers are
resolved from environment variables at runtime.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scope import Scope


_ALLOWED_MODULES = {"recon", "web", "secrets", "ascend_har", "webvuln"}


@dataclass(frozen=True)
class AccountRef:
    name: str
    headers_env: str

    def headers(self) -> dict[str, str]:
        """Resolve account headers from an environment variable.

        Accepted values:
        - JSON object: {"Cookie": "session=...", "Authorization": "Bearer ..."}
        - a single HTTP header: "Cookie: session=..."
        """
        raw = os.getenv(self.headers_env, "").strip()
        if not raw:
            raise ValueError(
                f"account '{self.name}' requires environment variable {self.headers_env}"
            )
        if raw.startswith("{"):
            data = json.loads(raw)
            if not isinstance(data, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in data.items()
            ):
                raise ValueError(f"{self.headers_env} must contain a JSON object of string headers")
            return dict(data)
        if ":" not in raw:
            raise ValueError(
                f"{self.headers_env} must be JSON headers or a single 'Name: value' header"
            )
        key, value = raw.split(":", 1)
        return {key.strip(): value.strip()}

    def single_header(self) -> str:
        headers = self.headers()
        if len(headers) != 1:
            raise ValueError(
                f"account '{self.name}' must resolve to exactly one header for HAR replay"
            )
        key, value = next(iter(headers.items()))
        return f"{key}: {value}"


@dataclass(frozen=True)
class EngagementPolicy:
    """Local execution policy layered on top of the program scope.

    Active web validation is deliberately opt-in. Even when enabled, the same
    scope guard and explicit authorization flag remain mandatory.
    """

    active_web_validation: bool = False
    crawl_active_targets: bool = False
    minimum_report_severity: str = "medium"


@dataclass
class EngagementManifest:
    name: str
    scope_file: str
    targets: list[str]
    modules: list[str] = field(default_factory=lambda: ["recon", "web", "secrets"])
    har_files: list[str] = field(default_factory=list)
    accounts: dict[str, AccountRef] = field(default_factory=dict)
    policy: EngagementPolicy = field(default_factory=EngagementPolicy)
    state_file: str = ".apex/state.json"
    out_dir: str = ".apex"

    @classmethod
    def load(cls, path: str | Path) -> "EngagementManifest":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        base = p.parent

        scope_file = str(data.get("scope_file", "")).strip()
        if not scope_file:
            raise ValueError("engagement manifest requires scope_file")
        scope_path = Path(scope_file)
        if not scope_path.is_absolute():
            scope_path = (base / scope_path).resolve()

        targets = [str(x).strip() for x in data.get("targets", []) if str(x).strip()]
        if not targets:
            raise ValueError("engagement manifest requires at least one target")

        modules = [str(x).strip() for x in data.get("modules", ["recon", "web", "secrets"])]
        unknown = sorted(set(modules) - _ALLOWED_MODULES)
        if unknown:
            raise ValueError(f"unsupported engagement modules: {', '.join(unknown)}")

        accounts: dict[str, AccountRef] = {}
        for name, cfg in (data.get("accounts") or {}).items():
            if not isinstance(cfg, dict) or not cfg.get("headers_env"):
                raise ValueError(f"account '{name}' requires headers_env")
            accounts[str(name)] = AccountRef(str(name), str(cfg["headers_env"]))

        policy_data = data.get("policy") or {}
        policy = EngagementPolicy(
            active_web_validation=bool(policy_data.get("active_web_validation", False)),
            crawl_active_targets=bool(policy_data.get("crawl_active_targets", False)),
            minimum_report_severity=str(policy_data.get("minimum_report_severity", "medium")),
        )

        har_files: list[str] = []
        for item in data.get("har_files", []):
            hp = Path(str(item))
            if not hp.is_absolute():
                hp = (base / hp).resolve()
            har_files.append(str(hp))

        out_dir = str(data.get("out_dir", ".apex"))
        state_file = str(data.get("state_file", ".apex/state.json"))
        if not Path(out_dir).is_absolute():
            out_dir = str((base / out_dir).resolve())
        if not Path(state_file).is_absolute():
            state_file = str((base / state_file).resolve())

        return cls(
            name=str(data.get("name") or p.stem),
            scope_file=str(scope_path),
            targets=targets,
            modules=modules,
            har_files=har_files,
            accounts=accounts,
            policy=policy,
            state_file=state_file,
            out_dir=out_dir,
        )

    def validate_against_scope(self, scope: Scope) -> None:
        """Fail before any network work if any configured target is out of scope."""
        for target in self.targets:
            scope.guard(target)
        if "ascend_har" in self.modules:
            if not self.har_files:
                raise ValueError("ascend_har module requires har_files")
            if "attacker" not in self.accounts:
                raise ValueError("ascend_har module requires accounts.attacker")
        if "webvuln" in self.modules and not self.policy.active_web_validation:
            raise PermissionError(
                "webvuln is active validation; set policy.active_web_validation=true "
                "only when the program rules explicitly allow it"
            )

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope_file": self.scope_file,
            "targets": list(self.targets),
            "modules": list(self.modules),
            "har_files": list(self.har_files),
            "accounts": sorted(self.accounts),
            "policy": {
                "active_web_validation": self.policy.active_web_validation,
                "crawl_active_targets": self.policy.crawl_active_targets,
                "minimum_report_severity": self.policy.minimum_report_severity,
            },
            "state_file": self.state_file,
            "out_dir": self.out_dir,
        }
