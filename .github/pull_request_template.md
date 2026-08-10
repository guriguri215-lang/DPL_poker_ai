## Summary

<!-- Explain the motivation and the small, focused change. -->

## Verification

<!-- List the exact commands you ran and their results. Explain any check not run. -->

- [ ] `python -m ruff check . --no-cache`
- [ ] `python -m ruff format --check --diff .`
- [ ] Relevant pytest checks, including the packaging tests when applicable

## Scope checklist

- [ ] The pull request is small and focused.
- [ ] Documentation and tests are updated when behavior changes.
- [ ] The change remains simulation-only and does not add real-time poker operation, screen scraping, poker-site APIs, external-site automation, or real-money play.
- [ ] The change does not publish to PyPI or another package index; release artifacts remain GitHub Releases-only.
