"""RepoReady project configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib


@dataclass(frozen=True)
class Policy:
    require_license: bool = True
    require_tests: bool = True
    require_ci: bool = True
    require_contributing: bool = True
    require_security_policy: bool = True
    require_code_of_conduct: bool = True
    require_issue_templates: bool = True
    require_pull_request_template: bool = True
    require_changelog: bool = True


@dataclass(frozen=True)
class Config:
    policy: Policy = field(default_factory=Policy)
    blocked_paths: tuple[str, ...] = ()
    allowed_paths: tuple[str, ...] = ()
    allowed_secret_rules: frozenset[str] = field(default_factory=frozenset)
    custom_secret_patterns: tuple[tuple[str, str], ...] = ()

    def compiled_secret_patterns(self) -> dict[str, re.Pattern[str]]:
        result: dict[str, re.Pattern[str]] = {}
        for name, expression in self.custom_secret_patterns:
            try:
                result[name] = re.compile(expression)
            except re.error as exc:
                raise ValueError(f"invalid custom secret pattern {name!r}: {exc}") from exc
        return result


def load_config(root: Path, explicit: Path | None = None) -> Config:
    path = explicit or (root / ".repoready.toml")
    if not path.exists():
        return Config()
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return parse_config(data)


def parse_config(data: dict[str, Any]) -> Config:
    policy_data = data.get("policy", {})
    policy = Policy(
        require_license=_boolean(policy_data, "require_license", True),
        require_tests=_boolean(policy_data, "require_tests", True),
        require_ci=_boolean(policy_data, "require_ci", True),
        require_contributing=_boolean(policy_data, "require_contributing", True),
        require_security_policy=_boolean(policy_data, "require_security_policy", True),
        require_code_of_conduct=_boolean(policy_data, "require_code_of_conduct", True),
        require_issue_templates=_boolean(policy_data, "require_issue_templates", True),
        require_pull_request_template=_boolean(policy_data, "require_pull_request_template", True),
        require_changelog=_boolean(policy_data, "require_changelog", True),
    )
    paths = data.get("paths", {})
    secrets = data.get("secrets", {})
    custom = secrets.get("patterns", {})
    if not isinstance(custom, dict):
        raise ValueError("secrets.patterns must be a table")
    return Config(
        policy=policy,
        blocked_paths=_strings(paths.get("block", ()), "paths.block"),
        allowed_paths=_strings(paths.get("allow", ()), "paths.allow"),
        allowed_secret_rules=frozenset(_strings(secrets.get("allow_rules", ()), "secrets.allow_rules")),
        custom_secret_patterns=tuple((str(name), str(expression)) for name, expression in custom.items()),
    )


def _boolean(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"policy.{key} must be true or false")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(value)
