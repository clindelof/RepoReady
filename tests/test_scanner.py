from __future__ import annotations

import subprocess
from pathlib import Path

from repoready.scanner import scan_repository


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)


def repository(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Test User")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    for name, content in {
        "README.md": "# Example\n",
        "LICENSE": "Example license\n",
        ".gitignore": ".env\n",
        "tests/test_example.py": "def test_example(): assert True\n",
        ".github/workflows/test.yml": "name: test\n",
    }.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def test_clean_repository_passes(tmp_path: Path) -> None:
    report = scan_repository(repository(tmp_path))
    assert report.result == "PASS"


def test_tracked_env_blocks_publication(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / ".env").write_text("APP_MODE=demo\n", encoding="utf-8")
    git(root, "add", "-f", ".env")
    git(root, "commit", "-qm", "add environment")
    report = scan_repository(root)
    assert report.result == "BLOCK"
    assert any(item.check == "sensitive-paths" and item.severity == "BLOCK" for item in report.findings)


def test_deleted_sensitive_file_is_found_in_history(tmp_path: Path) -> None:
    root = repository(tmp_path)
    secret = root / "private" / "credentials.txt"
    secret.parent.mkdir()
    secret.write_text("synthetic fixture\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "add fixture")
    secret.unlink()
    git(root, "add", "-u")
    git(root, "commit", "-qm", "remove fixture")
    report = scan_repository(root)
    assert any(item.check == "git-history" and item.severity == "BLOCK" for item in report.findings)


def test_secret_value_is_never_in_report(tmp_path: Path) -> None:
    root = repository(tmp_path)
    value = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    (root / "config.txt").write_text(f"token={value}\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "add synthetic token")
    report = scan_repository(root)
    rendered = str(report.to_dict())
    assert report.result == "BLOCK"
    assert value not in rendered

