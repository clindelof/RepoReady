"""Repository publication-safety checks."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .config import Config, load_config


SEVERITY_ORDER = {"PASS": 0, "WARN": 1, "BLOCK": 2}
SENSITIVE_PATH_PATTERNS = (
    re.compile(r"(^|/)(\.env($|\.)|id_rsa|id_ed25519|credentials?($|\.)|secrets?($|\.))", re.I),
    re.compile(r"\.(pem|key|p12|pfx|jks|sqlite|sqlite3|db|bak)$", re.I),
    re.compile(r"(^|/)(backups?|private|financial|finance|inventory)(/|$)", re.I),
)
SECRET_EXPRESSIONS = {
    "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "github-token": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
    "aws-access-key": r"\bAKIA[0-9A-Z]{16}\b",
    "assigned-secret": r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[^\s'\"$<{]{8,}",
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
    remediation: str = ""
    location: str = ""
    evidence: str = ""

    @property
    def fingerprint(self) -> str:
        source = "\0".join((self.check, self.location, self.evidence or self.message))
        return hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, str]:
        result = asdict(self)
        result.pop("evidence", None)
        result["fingerprint"] = self.fingerprint
        return result


@dataclass(frozen=True)
class Report:
    repository: str
    findings: list[Finding]
    suppressed: int = 0

    @property
    def result(self) -> str:
        return max((item.severity for item in self.findings), key=SEVERITY_ORDER.get, default="PASS")

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "result": self.result,
            "suppressed": self.suppressed,
            "findings": [item.to_dict() for item in self.findings],
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


def _command(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), cwd=root, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )


def _tracked_files(root: Path) -> list[str]:
    result = _git(root, "ls-files", "-z")
    return [name for name in result.stdout.split("\0") if name] if result.returncode == 0 else []


def _staged_files(root: Path) -> list[str]:
    result = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [name for name in result.stdout.split("\0") if name] if result.returncode == 0 else []


def _historical_files(root: Path) -> set[str]:
    result = _git(root, "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=ACMRD")
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def _patterns(config: Config) -> dict[str, re.Pattern[str]]:
    built_in = {name: re.compile(expression) for name, expression in SECRET_EXPRESSIONS.items()}
    built_in.update(config.compiled_secret_patterns())
    return {name: pattern for name, pattern in built_in.items() if name not in config.allowed_secret_rules}


def _allowed(path: str, config: Config) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in config.allowed_paths)


def _sensitive_paths(paths: Iterable[str], config: Config) -> list[str]:
    result = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if _allowed(normalized, config):
            continue
        built_in = any(pattern.search(normalized) for pattern in SENSITIVE_PATH_PATTERNS)
        configured = any(fnmatch.fnmatch(normalized, pattern) for pattern in config.blocked_paths)
        if built_in or configured:
            result.append(normalized)
    return sorted(result)


def _scan_text(content: str, patterns: dict[str, re.Pattern[str]]) -> dict[str, int]:
    content = "\n".join(line for line in content.splitlines() if "repoready:allow" not in line)
    return {name: len(pattern.findall(content)) for name, pattern in patterns.items() if pattern.search(content)}


def _filter_diff(content: str, config: Config) -> str:
    """Remove allowed-path sections from a Git patch before content scanning."""

    kept: list[str] = []
    include_section = True
    for line in content.splitlines():
        if line.startswith("diff --git a/") and " b/" in line:
            path = line.split(" b/", 1)[1]
            include_section = not _allowed(path, config)
        if include_section:
            kept.append(line)
    return "\n".join(kept)


def _scan_worktree_content(root: Path, paths: list[str], config: Config) -> dict[str, int]:
    totals: dict[str, int] = {}
    patterns = _patterns(config)
    for relative in paths:
        if _allowed(relative, config):
            continue
        path = root / relative
        if not path.is_file() or path.suffix.lower() in SKIP_CONTENT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            matches = _scan_text(path.read_text(encoding="utf-8", errors="ignore"), patterns)
        except OSError:
            continue
        for name, count in matches.items():
            totals[name] = totals.get(name, 0) + count
    return totals


def _scan_staged_content(root: Path, config: Config) -> dict[str, int]:
    diff = _git(root, "diff", "--cached", "--no-ext-diff", "--unified=0", "--no-color")
    return _scan_text(_filter_diff(diff.stdout, config), _patterns(config)) if diff.returncode == 0 else {}


def _scan_history_content(root: Path, config: Config) -> dict[str, int]:
    history = _git(
        root, "log", "--all", "-p", "--no-ext-diff", "--unified=0", "--no-color",
        "--format=commit:%H",
    )
    return _scan_text(_filter_diff(history.stdout, config), _patterns(config)) if history.returncode == 0 else {}


def _secret_finding(check: str, matches: dict[str, int], scope: str) -> Finding:
    rules = ", ".join(sorted(matches))
    return Finding(
        "BLOCK", check,
        f"Potential secret material detected in {scope} ({rules}); paths and values hidden",
        "Remove the material, rotate any real credentials, and sanitize Git history when applicable.",
        evidence=rules,
    )


def _presence(paths: list[str], candidates: tuple[str, ...]) -> bool:
    lowered = {path.lower() for path in paths}
    return any(candidate.lower() in lowered for candidate in candidates)


def _community_findings(paths: list[str], config: Config) -> list[Finding]:
    checks = [
        ("readme", True, ("README.md", "README.rst", "README.txt"), "README"),
        ("license", config.policy.require_license, ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"), "license"),
        ("contributing", config.policy.require_contributing, ("CONTRIBUTING.md", ".github/CONTRIBUTING.md"), "contribution guide"),
        ("security-policy", config.policy.require_security_policy, ("SECURITY.md", ".github/SECURITY.md"), "security policy"),
        ("code-of-conduct", config.policy.require_code_of_conduct, ("CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md"), "code of conduct"),
        ("issue-templates", config.policy.require_issue_templates, (".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/bug_report.md"), "issue template"),
        ("pull-request-template", config.policy.require_pull_request_template, (".github/PULL_REQUEST_TEMPLATE.md", "PULL_REQUEST_TEMPLATE.md"), "pull request template"),
        ("changelog", config.policy.require_changelog, ("CHANGELOG.md", "HISTORY.md"), "changelog"),
    ]
    findings = []
    for check, required, candidates, label in checks:
        if not required:
            continue
        found = _presence(paths, candidates)
        findings.append(Finding(
            "PASS" if found else "WARN", check,
            f"{label.capitalize()} found" if found else f"No tracked {label} found",
            "Add the file in the repository root or supported .github directory." if not found else "",
            location=candidates[0] if not found else "",
        ))

    tests = [name for name in paths if re.search(r"(^|/)(tests?/|test_.*\.py$|.*\.(spec|test)\.[jt]sx?$)", name, re.I)]
    if config.policy.require_tests:
        findings.append(Finding(
            "PASS" if tests else "WARN", "tests",
            f"{len(tests)} test file(s) found" if tests else "No test files found",
            "Add an automated test suite with synthetic fixtures." if not tests else "",
        ))
    workflows = [name for name in paths if name.startswith(".github/workflows/")]
    if config.policy.require_ci:
        findings.append(Finding(
            "PASS" if workflows else "WARN", "ci",
            f"{len(workflows)} CI workflow(s) found" if workflows else "No GitHub Actions workflow found",
            "Add a workflow that runs tests and repository safety checks." if not workflows else "",
            location=".github/workflows" if not workflows else "",
        ))
    return findings


def _dependency_findings(root: Path, paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    dependency_dirs = [
        path for path in paths
        if re.search(r"(^|/)(node_modules|\.venv|venv|vendor)/", path)
    ]
    findings.append(Finding(
        "BLOCK" if dependency_dirs else "PASS", "tracked-dependencies",
        f"{len(dependency_dirs)} vendored dependency path(s) are tracked; paths hidden" if dependency_dirs else "No common dependency directories are tracked",
        "Remove generated dependency directories from Git and add them to .gitignore." if dependency_dirs else "",
        evidence=str(len(dependency_dirs)),
    ))

    path_set = set(paths)
    if "package.json" in path_set:
        locks = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}
        present = bool(path_set & locks)
        findings.append(Finding(
            "PASS" if present else "WARN", "javascript-lockfile",
            "JavaScript lockfile found" if present else "package.json is tracked without a lockfile",
            "Commit the lockfile generated by the project's package manager." if not present else "",
            location="package.json",
        ))

    requirement_files = [path for path in paths if re.search(r"(^|/)requirements[^/]*\.txt$", path, re.I)]
    unpinned = 0
    for relative in requirement_files:
        try:
            lines = (root / relative).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            value = line.strip()
            if value and not value.startswith(("#", "-", "git+")) and "==" not in value:
                unpinned += 1
    if requirement_files:
        findings.append(Finding(
            "WARN" if unpinned else "PASS", "python-pins",
            f"{unpinned} unpinned Python requirement(s) found" if unpinned else "Python requirements are pinned",
            "Pin deployable application requirements or document the deliberate version policy." if unpinned else "",
        ))

    audit_tools = []
    if "package.json" in path_set:
        audit_tools.append("npm audit")
    if "pyproject.toml" in path_set or requirement_files:
        audit_tools.append("pip-audit")
    if audit_tools:
        findings.append(Finding(
            "PASS", "dependency-audit",
            f"Run ecosystem vulnerability checks: {', '.join(audit_tools)}",
            evidence=",".join(audit_tools),
        ))
        dependabot = ".github/dependabot.yml" in path_set or ".github/dependabot.yaml" in path_set
        findings.append(Finding(
            "PASS" if dependabot else "WARN", "dependabot",
            "Dependabot configuration found" if dependabot else "No Dependabot configuration found",
            "Add .github/dependabot.yml for the detected package ecosystems." if not dependabot else "",
            location=".github/dependabot.yml" if not dependabot else "",
        ))
    return findings


def _github_findings(root: Path) -> list[Finding]:
    if shutil.which("gh") is None:
        return [Finding("WARN", "github-metadata", "GitHub CLI is unavailable", "Install and authenticate GitHub CLI, or omit --github.")]
    view = _command(
        root, "gh", "repo", "view", "--json",
        "description,homepageUrl,repositoryTopics,visibility,defaultBranchRef,isSecurityPolicyEnabled",
    )
    if view.returncode != 0:
        return [Finding("WARN", "github-metadata", "GitHub metadata could not be read", "Run `gh auth login` and verify the repository remote." )]
    data = json.loads(view.stdout)
    topics = data.get("repositoryTopics") or []
    findings = [
        Finding("PASS" if data.get("description") else "WARN", "github-description", "Repository description found" if data.get("description") else "Repository description is empty", "Set it with `gh repo edit --description ...`." if not data.get("description") else ""),
        Finding("PASS" if topics else "WARN", "github-topics", f"{len(topics)} repository topic(s) found" if topics else "No repository topics found", "Add focused topics with `gh repo edit --add-topic ...`." if not topics else ""),
        Finding("PASS" if data.get("defaultBranchRef") else "WARN", "github-default-branch", "Default branch is configured" if data.get("defaultBranchRef") else "Default branch could not be verified"),
    ]
    api = _command(root, "gh", "api", "repos/{owner}/{repo}")
    if api.returncode == 0:
        security = (json.loads(api.stdout).get("security_and_analysis") or {})
        push = (security.get("secret_scanning_push_protection") or {}).get("status")
        findings.append(Finding(
            "PASS" if push == "enabled" else "WARN", "push-protection",
            "Secret-scanning push protection is enabled" if push == "enabled" else "Secret-scanning push protection is not enabled or could not be verified",
            "Enable push protection in repository security settings." if push != "enabled" else "",
        ))
    return findings


def _gitleaks_findings(root: Path) -> list[Finding]:
    if shutil.which("gitleaks") is None:
        return [Finding(
            "WARN", "gitleaks", "Gitleaks is unavailable",
            "Install Gitleaks or omit --gitleaks; RepoReady's built-in redacted checks still ran.",
        )]
    with tempfile.TemporaryDirectory() as temporary:
        report_path = Path(temporary) / "gitleaks.json"
        result = _command(
            root, "gitleaks", "git", "--redact", "--report-format", "json",
            "--report-path", str(report_path), str(root),
        )
        findings = []
        if report_path.exists():
            try:
                findings = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                findings = []
        if findings:
            return [Finding(
                "BLOCK", "gitleaks", f"Gitleaks detected {len(findings)} potential secret(s); paths and values hidden",
                "Review with a local redacted Gitleaks report, rotate real credentials, and sanitize history.",
                evidence=str(len(findings)),
            )]
        if result.returncode not in (0, 1):
            return [Finding("WARN", "gitleaks", "Gitleaks could not complete", "Run `gitleaks git --redact` locally for diagnostics.")]
        return [Finding("PASS", "gitleaks", "Gitleaks found no potential secrets")]


def _apply_baseline(findings: list[Finding], baseline: set[str]) -> tuple[list[Finding], int]:
    if not baseline:
        return findings, 0
    kept = []
    suppressed = 0
    for finding in findings:
        if finding.severity != "PASS" and finding.fingerprint in baseline:
            suppressed += 1
        else:
            kept.append(finding)
    if suppressed:
        kept.append(Finding("PASS", "baseline", f"{suppressed} reviewed finding(s) suppressed by baseline"))
    return kept, suppressed


def scan_repository(
    path: str | Path,
    *,
    staged: bool = False,
    config_path: str | Path | None = None,
    baseline: set[str] | None = None,
    github: bool = False,
    gitleaks: bool = False,
) -> Report:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        return Report(str(root), [Finding("BLOCK", "repository", "Path is not a directory", "Provide an existing repository directory.")])
    if _git(root, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return Report(str(root), [Finding("BLOCK", "repository", "Path is not a Git repository", "Initialize it with `git init`.")])
    try:
        config = load_config(root, Path(config_path) if config_path else None)
    except (OSError, ValueError) as exc:
        return Report(str(root), [Finding("BLOCK", "configuration", f"Configuration is invalid: {exc}", "Correct .repoready.toml and scan again.")])

    findings: list[Finding] = []
    paths = _staged_files(root) if staged else _tracked_files(root)
    sensitive = _sensitive_paths(paths, config)
    scope = "staged" if staged else "tracked"
    findings.append(Finding(
        "BLOCK" if sensitive else "PASS", f"{scope}-sensitive-paths",
        f"{len(sensitive)} sensitive-looking {scope} path(s) found; paths hidden" if sensitive else f"No sensitive-looking {scope} paths found",
        "Unstage and remove private data, then add an appropriate ignore rule." if sensitive else "",
        evidence=str(len(sensitive)),
    ))

    secrets = _scan_staged_content(root, config) if staged else _scan_worktree_content(root, paths, config)
    findings.append(
        _secret_finding(f"{scope}-secrets", secrets, f"{scope} content")
        if secrets else Finding("PASS", f"{scope}-secrets", f"No common secret patterns found in {scope} content")
    )

    if staged:
        findings.append(Finding("PASS" if paths else "WARN", "staged-changes", f"{len(paths)} staged file(s) inspected" if paths else "No staged files found", "Stage files before using --staged." if not paths else ""))
    else:
        history_paths = _sensitive_paths(_historical_files(root), config)
        historical_only = [value for value in history_paths if value not in set(sensitive)]
        findings.append(Finding(
            "BLOCK" if historical_only else "PASS", "history-sensitive-paths",
            f"{len(historical_only)} sensitive-looking path(s) remain in Git history; paths hidden" if historical_only else "No deleted sensitive-looking paths found in Git history",
            "Create clean history or use git-filter-repo, then rotate exposed credentials." if historical_only else "",
            evidence=str(len(historical_only)),
        ))
        history_secrets = _scan_history_content(root, config)
        findings.append(
            _secret_finding("history-secrets", history_secrets, "Git history")
            if history_secrets else Finding("PASS", "history-secrets", "No common secret patterns found in Git history")
        )
        status = _git(root, "status", "--porcelain").stdout.strip()
        findings.append(Finding("WARN" if status else "PASS", "working-tree", "Working tree has uncommitted changes" if status else "Working tree is clean", "Commit, stash, or deliberately review local changes." if status else ""))
        findings.extend(_community_findings(paths, config))
        findings.extend(_dependency_findings(root, paths))
        if gitleaks:
            findings.extend(_gitleaks_findings(root))
        if github:
            findings.extend(_github_findings(root))

    filtered, suppressed = _apply_baseline(findings, baseline or set())
    return Report(str(root), filtered, suppressed)
