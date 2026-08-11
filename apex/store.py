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

    def save(self) -> None:
        data: dict[str, Any] = {
            "program": self.program,
            "assets": [a.__dict__ for a in self.assets.values()],
            "findings": [f.to_dict() for f in self.findings],
        }
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def add_asset(self, asset: Asset) -> bool:
        if asset.key() in self.assets:
            return False
        self.assets[asset.key()] = asset
        return True

    def add_finding(self, f: Finding) -> None:
        # дедуп по (title, target)
        for ex in self.findings:
            if ex.title == f.title and ex.target == f.target:
                return
        self.findings.append(f)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out
