"""Хранилище активов и находок движка (JSON-файл в каталоге движка)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Asset, Finding


class Store:
    def __init__(self, path: str | Path = ".apex/state.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.assets: dict[str, Asset] = {}
        self.findings: list[Finding] = []
        self.runs: list[dict[str, Any]] = []
        self.program: str = ""
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.program = data.get("program", "")
        for a in data.get("assets", []):
            asset = Asset(**a)
            self.assets[asset.key()] = asset
        for f in data.get("findings", []):
            self.findings.append(Finding(**f))
        self.runs = list(data.get("runs", []))[-100:]

    def save(self) -> None:
        data: dict[str, Any] = {
            "program": self.program,
            "assets": [a.__dict__ for a in self.assets.values()],
            "findings": [f.to_dict() for f in self.findings],
            "runs": self.runs[-100:],
        }
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def add_asset(self, asset: Asset) -> bool:
        if asset.key() in self.assets:
            return False
        self.assets[asset.key()] = asset
        return True

    def add_finding(self, f: Finding) -> bool:
        fingerprint = f.fingerprint()
        for ex in self.findings:
            if ex.fingerprint() == fingerprint:
                return False
        self.findings.append(f)
        return True

    def record_run(self, run: dict[str, Any]) -> None:
        """Хранить ограниченный журнал для сравнения качества запусков."""
        self.runs.append(run)
        self.runs = self.runs[-100:]

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out
