"""Text, JSON, and SARIF report rendering."""

from __future__ import annotations

import json
from typing import Any

from .scanner import Report


def render_text(report: Report) -> str:
    lines = [f"RepoReady: {report.repository}", ""]
    for finding in report.findings:
        lines.append(f"{finding.severity:<5}  {finding.check:<20} {finding.message}")
        if finding.severity != "PASS" and finding.remediation:
            lines.append(f"       {'Fix:':<20} {finding.remediation}")
    lines.extend(["", f"Result: {report.result}"])
    if report.suppressed:
        lines.append(f"Baseline: {report.suppressed} finding(s) suppressed")
    if report.result == "BLOCK":
        lines.append("Do not publish until blocking findings are resolved.")
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_sarif(report: Report) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.severity == "PASS":
            continue
        rules.setdefault(
            finding.check,
            {
                "id": finding.check,
                "shortDescription": {"text": finding.check.replace("-", " ").title()},
                "help": {"text": finding.remediation or finding.message},
            },
        )
        result: dict[str, Any] = {
            "ruleId": finding.check,
            "level": "error" if finding.severity == "BLOCK" else "warning",
            "message": {"text": finding.message},
            "partialFingerprints": {"reporeadyFingerprint": finding.fingerprint},
        }
        if finding.location:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": finding.location}}}
            ]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoReady",
                        "informationUri": "https://github.com/clindelof/RepoReady",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
