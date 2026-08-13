"""Finding baseline support."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Iterable

from .scanner import Finding


def write_baseline(
    path: Path,
    findings: Iterable[Finding],
    *,
    reason: str = "Reviewed RepoReady finding",
    expires: str | None = None,
) -> int:
    if expires is not None:
        date.fromisoformat(expires)
    fingerprints = sorted({item.fingerprint for item in findings if item.severity != "PASS"})
    entries = [
        {"fingerprint": value, "reason": reason, "expires": expires}
        for value in fingerprints
    ]
    path.write_text(
        json.dumps({"version": 1, "entries": entries}, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(fingerprints)


def read_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError("unsupported RepoReady baseline format")
    if isinstance(data.get("fingerprints"), list):  # compatibility with early baseline files
        return {str(value) for value in data["fingerprints"]}
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("unsupported RepoReady baseline format")
    today = date.today()
    result = set()
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("fingerprint") or not entry.get("reason"):
            raise ValueError("baseline entries require fingerprint and reason")
        expires = date.fromisoformat(entry["expires"]) if entry.get("expires") else None
        if expires is None or expires >= today:
            result.add(str(entry["fingerprint"]))
    return result
