"""Publication-safety checks that never disclose a matched candidate value."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "private-key-material",
        re.compile(rb"-----BEGIN (?:ENCRYPTED |RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "private-key-material",
        re.compile(b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"),
    ),
    ("private-key-material", re.compile(rb"PuTTY-User-Key-File-[0-9]+:")),
    ("github-token", re.compile(rb"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}")),
    ("gitlab-token", re.compile(rb"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(rb"npm_[A-Za-z0-9]{20,}")),
    ("api-token", re.compile(rb"sk-proj-[A-Za-z0-9_-]{20,}")),
    ("google-api-key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("stripe-live-key", re.compile(rb"sk_live_[A-Za-z0-9]{16,}")),
    ("aws-access-key", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}")),
    (
        "credentialed-url",
        re.compile(rb"https?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    ),
    (
        "personal-absolute-path",
        re.compile(
            rb"(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\\/\s]+|"
            rb"/(?:home|Users)/[^/\s]+/)",
            re.IGNORECASE,
        ),
    ),
)

_UNSAFE_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "secrets",
}
_UNSAFE_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".tmp",
    ".bak",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
)


def path_issue(path: str) -> str | None:
    """Return a redacted issue category for a publication path, if unsafe."""
    normalized = path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    lower_parts = tuple(part.lower() for part in pure.parts)
    lower_name = pure.name.lower()
    if not normalized or pure.is_absolute() or ".." in pure.parts or "\\" in path:
        return "unsafe-path-topology"
    if any(part in _UNSAFE_PARTS for part in lower_parts):
        return "local-or-build-path"
    if any(part.endswith(".egg-info") for part in lower_parts):
        return "unexpected-egg-info"
    if lower_name == ".env" or lower_name.startswith(".env."):
        return "environment-file"
    if lower_name.endswith(_UNSAFE_SUFFIXES) or lower_name.startswith("~$"):
        return "temporary-or-sensitive-file"
    return None


def content_issues(data: bytes) -> tuple[str, ...]:
    """Return issue categories only; never return the matching bytes."""
    return tuple(category for category, pattern in _CONTENT_PATTERNS if pattern.search(data))
