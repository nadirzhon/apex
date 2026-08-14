"""Standalone CLI entrypoint for APEX Autopilot.

Usage:
    python -m apex.auto_cli --manifest engagement.json --i-am-authorized
"""
from __future__ import annotations

import argparse
import sys

from .autopilot import run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apex-autopilot",
        description="Autonomous, scope-gated APEX engagement runner",
    )
    parser.add_argument("--manifest", required=True, help="JSON engagement manifest")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="explicit confirmation that the engagement is authorized",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args.manifest, args.i_am_authorized)
    except PermissionError as exc:
        print(f"[GATE REFUSED] {exc}", file=sys.stderr)
        return 3
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(f"[autopilot] {result.engagement}")
    print(f"  assets: {result.assets}")
    print(f"  findings: {result.findings} {result.severity}")
    print(
        f"  quality: accepted={result.accepted_findings} "
        f"rejected={result.rejected_findings}"
    )
    print(f"  hypotheses: {result.hypotheses}")
    print(f"  HAR replays: {result.har_replays}")
    print(f"  state: {result.state_file}")
    print(f"  hypotheses: {result.hypotheses_path}")
    print(f"  report: {result.report_markdown} | {result.report_html}")
    print(f"  advisor: {result.advisor_path}")
    print(f"  quality: {result.quality_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
