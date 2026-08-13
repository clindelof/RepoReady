# Contributing

Thank you for considering a contribution to RepoReady.

1. Open an issue for substantial behavioral changes.
2. Create a focused branch and include synthetic tests.
3. Run `pytest` and `repoready scan .` locally.
4. Submit a pull request describing the risk or readiness problem being solved.

Never include real credentials, private repository contents, or personal datasets in tests or reports. Synthetic secret fixtures must live under `tests/`, which is explicitly allowed by the project policy.

