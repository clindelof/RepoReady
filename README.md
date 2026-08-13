# RepoReady

RepoReady is a privacy-first preflight check for publishing a Git repository. It looks for common disclosure risks and project-readiness gaps without printing suspected secret values.

> **Status:** Early alpha. RepoReady is a useful second set of eyes, not a replacement for a dedicated secret scanner or a careful human review.

## What it checks

- Sensitive-looking tracked paths such as `.env`, private keys, databases, backups, and financial-data directories
- Sensitive-looking paths deleted from the working tree but retained in Git history
- Common private-key, access-token, and assigned-secret patterns in tracked text files
- Uncommitted working-tree changes
- A README, license, `.gitignore`, tests, and GitHub Actions configuration

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

Scan the current repository:

```bash
repoready
```

Scan another repository:

```bash
repoready /path/to/repository
```

Produce a JSON report for automation:

```bash
repoready --json
```

Example output:

```text
BLOCK  sensitive-paths  1 sensitive-looking tracked path(s) found; paths hidden
PASS   readme           README found
WARN   license          No tracked license found

Result: BLOCK
Do not publish until blocking findings are resolved.
```

Exit codes are `0` for pass, `1` when warnings are present, and `2` when publication is blocked.

## Development

```bash
python -m pip install -e . pytest
pytest
```

All tests construct temporary Git repositories with synthetic data. No personal repository contents are included.

## Limitations

- History inspection currently detects sensitive filenames, not secret content inside deleted historical blobs.
- Pattern matching can produce false positives and cannot identify every kind of private information.
- RepoReady does not determine whether a remote repository is public or private.
- A clean result does not guarantee that a repository is safe to publish.

## License

[MIT](LICENSE)
