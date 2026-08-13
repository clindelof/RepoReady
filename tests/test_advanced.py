from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repoready.baseline import read_baseline, write_baseline
from repoready.cli import main
from repoready.formats import render_sarif
from repoready.scanner import scan_repository
from test_scanner import git, repository


def test_deleted_secret_content_is_detected_without_value(tmp_path: Path) -> None:
    root = repository(tmp_path)
    value = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    target = root / "config.txt"
    target.write_text(f"token={value}\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "add synthetic credential")
    target.unlink()
    git(root, "add", "-u")
    git(root, "commit", "-qm", "remove synthetic credential")

    report = scan_repository(root)
    assert any(item.check == "history-secrets" and item.severity == "BLOCK" for item in report.findings)
    assert value not in json.dumps(report.to_dict())


def test_staged_mode_scans_only_staged_material(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / ".env").write_text("MODE=synthetic\n", encoding="utf-8")
    git(root, "add", "-f", ".env")
    report = scan_repository(root, staged=True)
    assert report.result == "BLOCK"
    assert any(item.check == "staged-sensitive-paths" for item in report.findings)
    assert not any(item.check == "working-tree" for item in report.findings)


def test_configuration_allows_paths_and_custom_secret_rules(tmp_path: Path) -> None:
    root = repository(tmp_path)
    fixture = root / "fixtures" / ".env"
    fixture.parent.mkdir()
    fixture.write_text("INTERNAL_TOKEN_123456789\n", encoding="utf-8")
    config = root / ".repoready.toml"
    config.write_text(
        '[paths]\nallow = ["fixtures/**"]\n\n[secrets.patterns]\ninternal = "INTERNAL_TOKEN_[0-9]+"\n',
        encoding="utf-8",
    )
    git(root, "add", "-f", ".")
    git(root, "commit", "-qm", "add allowed synthetic fixture")
    assert scan_repository(root).result == "PASS"


def test_custom_secret_rule_blocks_unallowed_content(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / ".repoready.toml").write_text(
        '[secrets.patterns]\ninternal = "INTERNAL_TOKEN_[0-9]+"\n', encoding="utf-8"
    )
    (root / "config.txt").write_text("INTERNAL_TOKEN_123456789\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "add custom synthetic fixture")
    report = scan_repository(root)
    assert report.result == "BLOCK"
    assert any("internal" in item.message for item in report.findings if item.check.endswith("secrets"))


def test_baseline_suppresses_reviewed_findings_and_can_expire(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / ".env").write_text("MODE=synthetic\n", encoding="utf-8")
    git(root, "add", "-f", ".env")
    git(root, "commit", "-qm", "add reviewed fixture")
    report = scan_repository(root)
    baseline_path = root / ".repoready-baseline.json"
    write_baseline(baseline_path, report.findings, reason="Synthetic test fixture", expires="2999-01-01")
    git(root, "add", ".repoready-baseline.json")
    git(root, "commit", "-qm", "add reviewed baseline")
    rescanned = scan_repository(root, baseline=read_baseline(baseline_path))
    assert rescanned.result == "PASS"
    assert rescanned.suppressed >= 1

    write_baseline(baseline_path, report.findings, reason="Expired fixture", expires="2000-01-01")
    assert read_baseline(baseline_path) == set()


def test_sarif_contains_redacted_findings_and_fingerprints(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / ".env").write_text("MODE=synthetic\n", encoding="utf-8")
    git(root, "add", "-f", ".env")
    git(root, "commit", "-qm", "add fixture")
    data = json.loads(render_sarif(scan_repository(root)))
    results = data["runs"][0]["results"]
    assert data["version"] == "2.1.0"
    assert results
    assert all("reporeadyFingerprint" in item["partialFingerprints"] for item in results)


def test_dependency_hygiene_detects_missing_lockfile_and_dependabot(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / "package.json").write_text('{"name":"example"}\n', encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "add manifest")
    report = scan_repository(root)
    assert any(item.check == "javascript-lockfile" and item.severity == "WARN" for item in report.findings)
    assert any(item.check == "dependabot" and item.severity == "WARN" for item in report.findings)


def test_cli_preserves_legacy_invocation_and_writes_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = repository(tmp_path)
    assert main([str(root), "--json", "--fail-on", "never"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"] == "PASS"


def test_pre_commit_hook_installation_is_non_destructive(tmp_path: Path) -> None:
    root = repository(tmp_path)
    assert main(["install-hook", str(root)]) == 0
    hook = root / ".git" / "hooks" / "pre-commit"
    assert "repoready scan --staged" in hook.read_text(encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["install-hook", str(root)])
