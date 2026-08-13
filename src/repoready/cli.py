"""Command-line interface for RepoReady."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import SEVERITY_ORDER, scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check whether a Git repository is ready to publish.")
    parser.add_argument("path", nargs="?", default=".", type=Path, help="repository to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = scan_repository(args.path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"RepoReady: {report.repository}\n")
        for finding in report.findings:
            print(f"{finding.severity:<5}  {finding.check:<16} {finding.message}")
        print(f"\nResult: {report.result}")
        if report.result == "BLOCK":
            print("Do not publish until blocking findings are resolved.")
    return SEVERITY_ORDER[report.result]


if __name__ == "__main__":
    raise SystemExit(main())

