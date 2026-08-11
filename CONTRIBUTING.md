# Contributing

Thank you for contributing to `poker-xai`. Keep changes small and focused so they are
easy to review and verify.

## Project scope

This repository is for simulation-only poker research. Contributions must not add
real-time poker operation, screen scraping, poker-site APIs, or automation of external
sites or real-money play.

Release artifacts are distributed only through GitHub Releases. Do not add publishing
to PyPI or any other package index.

## Development setup

Use Python 3.12.x. CI currently runs Python 3.12.10.

Create the existing editable development environment from the repository root:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or activate it on a POSIX shell:

```bash
. .venv/bin/activate
```

Then install the project and pinned development tools:

```bash
python -m pip install -e ".[dev]"
```

## Make and verify a change

Before opening a pull request, run the same core checks as CI:

```bash
python -m ruff check . --no-cache
python -m ruff format --check --diff .
python -m pytest -p no:cacheprovider
```

If the change affects packaging, entry points, or release verification, also run:

```bash
python -m pytest -p no:cacheprovider tests/test_release_artifacts.py tests/phase6/test_gate_b_v2_packaging.py
```

## Maintainer releases

Maintainers publishing a GitHub prerelease must follow the complete
[release checklist](docs/releasing.md), including the required CI and review
gates, the unchanged four-asset workflow bundle, and the post-publication flat
download verification.

Open an issue when the problem or proposed direction needs discussion. For a pull
request, explain the motivation, summarize the focused change, and list the checks you
ran. Update documentation and tests when behavior changes.
