# RepoReady

RepoReady is a privacy-first publication gate for Git repositories. It looks for disclosure risks, history leaks, dependency hygiene, community-health gaps, and optional GitHub configuration problems without printing suspected secret values or sensitive-looking paths.

> **Status:** Early alpha. RepoReady is a useful second set of eyes, not a replacement for a dedicated secret scanner or a careful human review.

## What it checks

- Sensitive-looking tracked paths such as `.env`, private keys, databases, backups, and financial-data directories
- Sensitive-looking paths deleted from the working tree but retained in Git history
- Common private-key, access-token, assigned-secret, and custom patterns in current content and Git patches
- Staged changes for use as a pre-commit publication gate
- Uncommitted working-tree changes
- README, license, contribution, security, conduct, issue, pull-request, changelog, test, and CI assets
- Tracked dependency directories, missing JavaScript lockfiles, and unpinned Python requirements
- Optional Gitleaks history results
- Optional GitHub description, topics, default branch, and push-protection status

RepoReady reports each check as `PASS`, `WARN`, or `BLOCK`. Sensitive-looking paths and suspected values are never included in its report, making the default output safer for CI logs.

## Install for development

```bash
git clone https://github.com/clindelof/repoready.git
cd repoready
python -m venv .venv
```

Activate the environment and install the project:

```bash
python -m pip install -e .
```

## Usage

Scan the current repository (the original `repoready` shorthand remains supported):

```bash
repoready scan .
# or: repoready
```

Scan another repository:

```bash
repoready /path/to/repository
```

Produce JSON or SARIF for automation:

```bash
repoready scan . --format json
repoready scan . --format sarif --output repoready.sarif
```

Scan staged changes or install a pre-commit hook:

```bash
repoready scan --staged
repoready install-hook
```

Inspect GitHub metadata or delegate a second redacted history scan to Gitleaks:

```bash
repoready scan --github
repoready scan --gitleaks
```

These integrations are opt-in. `--github` requires an authenticated GitHub CLI, and `--gitleaks` requires Gitleaks on `PATH`.

Example output:

```text
BLOCK  sensitive-paths  1 sensitive-looking tracked path(s) found; paths hidden
PASS   readme           README found
WARN   license          No tracked license found

Result: BLOCK
Do not publish until blocking findings are resolved.
```

Exit codes are `0` for pass, `1` when warnings are present, and `2` when publication is blocked. Use `--fail-on block` in CI when warnings should remain advisory, or `--fail-on never` while adopting RepoReady.

## Project policy

Create `.repoready.toml` to customize expectations:

```toml
[policy]
require_license = true
require_tests = true
require_ci = true
require_contributing = true
require_security_policy = true

[paths]
block = ["private/**", "*.sqlite"]
allow = ["tests/fixtures/**"]

[secrets]
allow_rules = ["synthetic-token"]

[secrets.patterns]
internal-token = "INTERNAL_TOKEN_[A-Z0-9]{20}"
```

An individual source line containing `repoready:allow` is omitted from content-pattern matching. Prefer narrow path or rule configuration when possible, and use only for reviewed synthetic examples.

## Reviewed baselines

Create a baseline for findings that have been explicitly reviewed:

```bash
repoready baseline create \
  --reason "Reviewed synthetic fixtures" \
  --expires 2027-01-01
```

The resulting `.repoready-baseline.json` contains stable finding fingerprints, reasons, and optional expiration dates—not secret values. Commit the baseline so working-tree checks remain clean. Expired entries stop suppressing findings automatically.

## GitHub Action

Use RepoReady directly from this repository:

```yaml
- uses: clindelof/RepoReady@v0.2.0
  with:
    fail-on: block
```

For SARIF code-scanning integration, run RepoReady in a workflow, write a SARIF file, and upload it with GitHub's `github/codeql-action/upload-sarif` action.

## Development

```bash
python -m pip install -e . pytest
pytest
```

All tests construct temporary Git repositories with synthetic data. No personal repository contents are included.

## Limitations

- Built-in history scanning inspects Git patches, so a secret that exists only in a binary blob or outside a diff addition may not be detected.
- Pattern matching can produce false positives and cannot identify every kind of private information.
- GitHub metadata checks require network access and an authenticated `gh` session.
- RepoReady recommends ecosystem audit tools rather than maintaining its own vulnerability database.
- A clean result does not guarantee that a repository is safe to publish.

## License

[MIT](LICENSE)
