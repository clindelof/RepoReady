"""Command-line interface for RepoReady."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .baseline import read_baseline, write_baseline
from .formats import render_json, render_sarif, render_text
from .scanner import SEVERITY_ORDER, scan_repository


COMMANDS = {"scan", "baseline", "install-hook"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check whether a Git repository is ready to publish.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a repository")
    scan.add_argument("path", nargs="?", default=".", type=Path)
    scan.add_argument("--staged", action="store_true", help="scan only staged changes")
    scan.add_argument("--config", type=Path, help="configuration file (default: .repoready.toml)")
    scan.add_argument("--baseline", type=Path, help="baseline file (default: .repoready-baseline.json when present)")
    scan.add_argument("--github", action="store_true", help="inspect GitHub metadata using authenticated gh CLI")
    scan.add_argument("--gitleaks", action="store_true", help="run an optional redacted Gitleaks history scan")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", type=Path, help="write the report to a file")
    scan.add_argument("--fail-on", choices=("warn", "block", "never"), default="warn")
    scan.add_argument("--json", action="store_true", help="deprecated alias for --format json")

    baseline = subparsers.add_parser("baseline", help="manage reviewed findings")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_sub.add_parser("create", help="create or replace a baseline")
    create.add_argument("path", nargs="?", default=".", type=Path)
    create.add_argument("--config", type=Path)
    create.add_argument("--output", type=Path, default=Path(".repoready-baseline.json"))
    create.add_argument("--reason", default="Reviewed RepoReady finding")
    create.add_argument("--expires", help="optional expiration date (YYYY-MM-DD)")

    hook = subparsers.add_parser("install-hook", help="install a staged-scan pre-commit hook")
    hook.add_argument("path", nargs="?", default=".", type=Path)
    hook.add_argument("--force", action="store_true", help="replace an existing hook")
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv or argv[0] not in COMMANDS:
        return ["scan", *argv]
    return argv


def _scan(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    baseline_path = args.baseline
    if baseline_path is None and (root / ".repoready-baseline.json").exists():
        baseline_path = root / ".repoready-baseline.json"
    baseline = read_baseline(baseline_path) if baseline_path else set()
    report = scan_repository(
        root,
        staged=args.staged,
        config_path=args.config,
        baseline=baseline,
        github=args.github,
        gitleaks=args.gitleaks,
    )
    selected_format = "json" if args.json else args.format
    renderer = {"text": render_text, "json": render_json, "sarif": render_sarif}[selected_format]
    rendered = renderer(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.fail_on == "never":
        return 0
    if args.fail_on == "block":
        return 2 if report.result == "BLOCK" else 0
    return SEVERITY_ORDER[report.result]


def _create_baseline(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    report = scan_repository(root, config_path=args.config)
    output = args.output if args.output.is_absolute() else root / args.output
    count = write_baseline(output, report.findings, reason=args.reason, expires=args.expires)
    print(f"Wrote {count} finding fingerprint(s) to {output}")
    return 0


def _install_hook(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--git-dir"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    git_dir_result = result.stdout.strip()
    if result.returncode != 0 or not git_dir_result:
        raise SystemExit("Not a Git repository")
    git_dir = Path(git_dir_result)
    if not git_dir.is_absolute():
        git_dir = root / git_dir
    hook = git_dir / "hooks" / "pre-commit"
    if hook.exists() and not args.force:
        raise SystemExit(f"Hook already exists: {hook} (use --force to replace it)")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\npython -m repoready scan --staged\n", encoding="utf-8")
    try:
        hook.chmod(hook.stat().st_mode | 0o111)
    except OSError:
        pass
    print(f"Installed RepoReady pre-commit hook at {hook}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(_normalize_argv(list(argv if argv is not None else sys.argv[1:])))
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "baseline":
            return _create_baseline(args)
        return _install_hook(args)
    except (OSError, ValueError) as exc:
        print(f"RepoReady error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
