"""Мост Python APEX → конкурентное Go-ядро APEX Core."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Iterable

from ..models import Asset, Finding
from ..orchestrator import AgentContext
from ..store import Store


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = PROJECT_ROOT / ".apex" / "bin" / "apex-core"


def binary_path() -> Path | None:
    configured = os.environ.get("APEX_GO_CORE", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.append(DEFAULT_BINARY)
    discovered = shutil.which("apex-core")
    if discovered:
        candidates.append(Path(discovered))
    return next((path for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)


def build(output: str | Path = DEFAULT_BINARY) -> Path:
    """Собрать stdlib-only Go Core без загрузки внешних зависимостей."""
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not shutil.which("go"):
        raise RuntimeError("Go toolchain не установлен")
    process = subprocess.run(
        ["go", "build", "-o", str(destination), "./cmd/apex-core"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or "не удалось собрать apex-core")
    return destination


def import_events(lines: Iterable[str], store: Store) -> dict[str, object]:
    """Импортировать JSONL атомарно понятными моделями Python-слоя."""
    summary: dict[str, object] = {}
    errors: list[str] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"apex-core вернул некорректный JSONL: {exc}") from exc
        event_type = event.get("type")
        if event_type == "asset":
            value = str(event.get("value") or event.get("target") or "").strip()
            if not value:
                raise RuntimeError("apex-core вернул asset без value")
            store.add_asset(Asset(
                kind=str(event.get("kind") or "url"),
                value=value,
                source=str(event.get("source") or "go-core"),
                meta=dict(event.get("meta") or {}),
            ))
        elif event_type == "error":
            errors.append(f"{event.get('target', '—')}: {event.get('error', 'unknown error')}")
        elif event_type == "summary":
            summary = dict(event)
    summary["errors"] = errors
    return summary


def run(context: AgentContext, workers: int = 16) -> list[Finding]:
    context.scope.assert_ready(context.authorized)
    if not context.scope._path:
        raise RuntimeError("Go Core требует scope, загруженный из JSON-файла")
    executable = binary_path()
    if executable is None:
        raise RuntimeError(
            "apex-core не собран; выполни `python -m apex.cli core --build`"
        )

    command = [
        str(executable), "-scope", context.scope._path,
        "-authorized", "-workers", str(max(1, min(workers, 64))),
    ]
    for target in context.targets or []:
        context.scope.guard(target)
        command.extend(["-target", target])
    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or f"apex-core exit {process.returncode}")
    summary = import_events(process.stdout.splitlines(), context.store)
    if int(summary.get("successful", 0)) == 0 and int(summary.get("failed", 0)) > 0:
        errors = summary.get("errors") or []
        raise RuntimeError("все Go-пробы завершились ошибкой: " + "; ".join(errors[:3]))
    return []
