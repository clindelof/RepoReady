"""Repository publication-safety checks."""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


SEVERITY_ORDER = {"PASS": 0, "WARN": 1, "BLOCK": 2}
SENSITIVE_PATH_PATTERNS = (
    re.compile(r"(^|/)(\.env($|\.)|id_rsa|id_ed25519|credentials?($|\.)|secrets?($|\.))", re.I),
    re.compile(r"\.(pem|key|p12|pfx|jks|sqlite|sqlite3|db|bak)$", re.I),
    re.compile(r"(^|/)(backups?|private|financial|finance|inventory)(/|$)", re.I),
)
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "likely assigned secret": re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[^\s'\"$<{]{8,}"
    ),
}
SKIP_CONTENT_SUFFIXES = {
    ".7z", ".avi", ".bmp", ".db", ".dll", ".doc", ".docx", ".exe", ".gif",
    ".gz", ".ico", ".jar", ".jpeg", ".jpg", ".mov", ".mp3", ".mp4", ".pdf",
    ".png", ".pyc", ".sqlite", ".sqlite3", ".tar", ".webp", ".xlsx", ".zip",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    check: str
    message: str


@dataclass(frozen=True)
class Report:
    repository: str
    findings: list[Finding]

    @property
    def result(self) -> str:
        return max((item.severity for item in self.findings), key=SEVERITY_ORDER.get, default="PASS")

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "result": self.result,
            "findings": [asdict(item) for item in self.findings],
        }


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _tracked_files(root: Path) -> list[str]:
    result = _git(root, "ls-files", "-z")
    return [name for name in result.stdout.split("\0") if name] if result.returncode == 0 else []


def _historical_files(root: Path) -> set[str]:
    result = _git(root, "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=ACMRD")
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def _sensitive_paths(paths: list[str] | set[str]) -> list[str]:
    return sorted(path for path in paths if any(pattern.search(path.replace("\\", "/")) for pattern in SENSITIVE_PATH_PATTERNS))


def _scan_content(root: Path, paths: list[str]) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.suffix.lower() in SKIP_CONTENT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                matches.append((relative, label))
    return matches


def scan_repository(path: str | Path) -> Report:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        return Report(str(root), [Finding("BLOCK", "repository", "Path is not a directory")])
    if _git(root, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return Report(str(root), [Finding("BLOCK", "repository", "Path is not a Git repository")])

    findings: list[Finding] = []
    tracked = _tracked_files(root)
    sensitive_current = _sensitive_paths(tracked)
    if sensitive_current:
        findings.append(Finding("BLOCK", "sensitive-paths", f"{len(sensitive_current)} sensitive-looking tracked path(s) found; paths hidden"))
    else:
        findings.append(Finding("PASS", "sensitive-paths", "No sensitive-looking tracked paths found"))

    history_paths = _sensitive_paths(_historical_files(root))
    current_set = set(sensitive_current)
    historical_only = [path for path in history_paths if path not in current_set]
    if historical_only:
        findings.append(Finding("BLOCK", "git-history", f"{len(historical_only)} sensitive-looking path(s) remain in Git history"))
    else:
        findings.append(Finding("PASS", "git-history", "No deleted sensitive-looking paths found in Git history"))

    content_matches = _scan_content(root, tracked)
    if content_matches:
        labels = ", ".join(sorted({label for _, label in content_matches}))
        findings.append(Finding("BLOCK", "secret-patterns", f"{len(content_matches)} potential secret occurrence(s) detected ({labels}); paths and values hidden"))
    else:
        findings.append(Finding("PASS", "secret-patterns", "No common secret patterns found in tracked text files"))

    status = _git(root, "status", "--porcelain").stdout.strip()
    findings.append(Finding("WARN" if status else "PASS", "working-tree", "Working tree has uncommitted changes" if status else "Working tree is clean"))

    for filename, label in (("README.md", "README"), ("LICENSE", "license"), (".gitignore", ".gitignore")):
        exists = any(Path(item).name.lower() == filename.lower() for item in tracked)
        findings.append(Finding("PASS" if exists else "WARN", label.lower(), f"{label} found" if exists else f"No tracked {label} found"))

    tests = [name for name in tracked if re.search(r"(^|/)(tests?/|test_.*\.py$|.*\.(spec|test)\.[jt]sx?$)", name, re.I)]
    findings.append(Finding("PASS" if tests else "WARN", "tests", f"{len(tests)} test file(s) found" if tests else "No test files found"))

    workflows = [name for name in tracked if name.startswith(".github/workflows/")]
    findings.append(Finding("PASS" if workflows else "WARN", "ci", f"{len(workflows)} CI workflow(s) found" if workflows else "No GitHub Actions workflow found"))

    return Report(str(root), findings)
