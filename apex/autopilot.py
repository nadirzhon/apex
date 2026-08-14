"""Autonomous, scope-gated engagement runner.

APEX Autopilot connects the existing discovery, safe analysis, controlled HAR
replay, reasoning, reporting and advisory components into one deterministic run.
It never creates accounts, bypasses the scope gate, or stores account secrets in files.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .advisor import advise
from .engagement import EngagementManifest
from .http import SafeHTTP
from .quality import check as quality_check
from .report import write as write_report
from .scope import Scope
from .selfcheck import assert_healthy
from .store import Store
from .modules import recon, web, secrets, webvuln


@dataclass(frozen=True)
class AutopilotResult:
    engagement: str
    assets: int
    findings: int
    severity: dict[str, int]
    report_markdown: str
    report_html: str
    advisor_path: str
    quality_path: str
    hypotheses_path: str
    state_file: str
    accepted_findings: int = 0
    rejected_findings: int = 0
    hypotheses: int = 0
    har_replays: int = 0


def _targets(store: Store, manifest: EngagementManifest) -> list[str]:
    discovered = [a.value for a in store.assets.values() if a.kind == "url"]
    ordered: list[str] = []
    for value in [*manifest.targets, *discovered]:
        if value not in ordered:
            ordered.append(value)
    return ordered


def _write_quality(scope: Scope, store: Store, manifest: EngagementManifest) -> tuple[str, int, int]:
    rows = []
    accepted = 0
    for finding in store.findings:
        result = quality_check(scope, finding, manifest.policy.minimum_report_severity)
        accepted += int(result.accepted)
        rows.append({
            "title": finding.title,
            "target": finding.target,
            "severity": finding.severity,
            "accepted": result.accepted,
            "reasons": list(result.reasons),
        })
    rejected = len(rows) - accepted
    path = Path(manifest.out_dir) / "quality.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "program": scope.program,
            "minimum_severity": manifest.policy.minimum_report_severity,
            "accepted": accepted,
            "rejected": rejected,
            "results": rows,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return str(path), accepted, rejected


def _write_hypotheses(manifest: EngagementManifest, hypotheses: dict[str, object]) -> str:
    path = Path(manifest.out_dir) / "hypotheses.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "engagement": manifest.name,
                "count": len(hypotheses),
                "hypotheses": [asdict(item) for item in hypotheses.values()],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(path)


def run(manifest_path: str, authorized: bool) -> AutopilotResult:
    """Run one complete authorized engagement from a declarative manifest."""
    assert_healthy()
    manifest = EngagementManifest.load(manifest_path)
    scope = Scope.load(manifest.scope_file)
    scope.assert_ready(authorized)
    manifest.validate_against_scope(scope)

    store = Store(manifest.state_file)
    store.program = scope.program
    http = SafeHTTP(rate_limit_rps=scope.rate_limit_rps)

    if "recon" in manifest.modules:
        recon.run(scope, store, http, authorized)
        store.save()

    targets = _targets(store, manifest)
    for target in targets:
        scope.guard(target)

    if "web" in manifest.modules:
        web.run(scope, store, http, authorized, targets)
        store.save()

    if "secrets" in manifest.modules:
        secrets.run(scope, store, http, authorized, targets)
        store.save()

    all_hypotheses: dict[str, object] = {}
    har_replays = 0
    if "ascend_har" in manifest.modules:
        from .ascend.autorize import run as autorize_run
        from .ascend.har_model import hypotheses_from_har

        attacker_header = manifest.accounts["attacker"].single_header()
        for har_file in manifest.har_files:
            for hypothesis in hypotheses_from_har(scope, store, authorized, har_file):
                all_hypotheses[hypothesis.id] = hypothesis
            autorize_run(scope, store, http, authorized, har_file, attacker_header)
            har_replays += 1
            store.save()

    hypotheses_path = _write_hypotheses(manifest, all_hypotheses)

    if "webvuln" in manifest.modules:
        for target in manifest.targets:
            webvuln.run(
                scope,
                store,
                http,
                authorized,
                [target],
                crawl=manifest.policy.crawl_active_targets,
            )
            store.save()

    md, ht = write_report(scope, store, manifest.out_dir)
    advisor_path = Path(manifest.out_dir) / "advisor.txt"
    advisor_path.parent.mkdir(parents=True, exist_ok=True)
    advisor_path.write_text(advise(store), encoding="utf-8")
    quality_path, accepted, rejected = _write_quality(scope, store, manifest)

    return AutopilotResult(
        engagement=manifest.name,
        assets=len(store.assets),
        findings=len(store.findings),
        severity=store.by_severity(),
        report_markdown=md,
        report_html=ht,
        advisor_path=str(advisor_path),
        quality_path=quality_path,
        hypotheses_path=hypotheses_path,
        state_file=manifest.state_file,
        accepted_findings=accepted,
        rejected_findings=rejected,
        hypotheses=len(all_hypotheses),
        har_replays=har_replays,
    )
