"""Resolve runtime package and Git provenance without guessing.

Source-tree provenance is accepted only when this module is loaded from the
project's exact ``src/poker_ai`` directory.  Installed or unpacked wheel code is
matched to the distribution metadata that locates this exact module.  Git state
is never inferred from the process working directory.
"""

from __future__ import annotations

import importlib.metadata
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from poker_core.run_manifest import UNKNOWN_COMMIT

DIST_NAME = "poker-xai"
UNKNOWN_PACKAGE_VERSION = "unknown"
_MODULE_RELATIVE_PATH = Path("poker_ai/runtime_provenance.py")


@dataclass(frozen=True)
class RuntimeProvenance:
    """Code identity available for the module that is actually executing."""

    package_version: str
    git_commit: str
    git_dirty: bool | None


def _source_project_root(module_file: Path) -> Path | None:
    """Return the exact src-layout project root for *module_file*, if present."""
    try:
        module_path = module_file.resolve(strict=True)
        root = module_path.parents[2]
    except (IndexError, OSError):
        return None
    if module_path != (root / "src" / _MODULE_RELATIVE_PATH).resolve():
        return None
    pyproject_path = root / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
    except (KeyError, OSError, tomllib.TOMLDecodeError):
        return None
    if project.get("name") != DIST_NAME:
        return None
    return root


def _source_version(root: Path) -> str | None:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    except (KeyError, OSError, tomllib.TOMLDecodeError):
        return None
    version = project.get("version")
    return version if isinstance(version, str) and version else None


def _matching_distribution_version(module_file: Path) -> str | None:
    try:
        module_path = module_file.resolve(strict=True)
        distributions = importlib.metadata.distributions(name=DIST_NAME)
    except (OSError, TypeError):
        return None
    matches: list[str] = []
    for distribution in distributions:
        try:
            located = Path(distribution.locate_file(_MODULE_RELATIVE_PATH)).resolve(strict=True)
        except (OSError, TypeError):
            continue
        if located == module_path and distribution.version:
            matches.append(distribution.version)
    return matches[0] if len(matches) == 1 else None


def resolve_package_version(module_file: Path | None = None) -> str:
    """Return an authoritative source/artifact version or ``"unknown"``."""
    resolved_module = Path(__file__) if module_file is None else module_file
    source_root = _source_project_root(resolved_module)
    if source_root is not None:
        return _source_version(source_root) or UNKNOWN_PACKAGE_VERSION
    return _matching_distribution_version(resolved_module) or UNKNOWN_PACKAGE_VERSION


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None


def resolve_git_provenance(module_file: Path | None = None) -> tuple[str, bool | None]:
    """Return the anchored source commit/dirty state or explicit unknowns."""
    resolved_module = Path(__file__) if module_file is None else module_file
    source_root = _source_project_root(resolved_module)
    if source_root is None or not (
        (source_root / ".git").is_dir() or (source_root / ".git").is_file()
    ):
        return UNKNOWN_COMMIT, None

    top_level = _run_git(source_root, "rev-parse", "--show-toplevel")
    if top_level is None or top_level.returncode != 0:
        return UNKNOWN_COMMIT, None
    try:
        actual_root = Path(top_level.stdout.decode("utf-8", "surrogateescape").strip()).resolve()
    except OSError:
        return UNKNOWN_COMMIT, None
    if actual_root != source_root.resolve():
        return UNKNOWN_COMMIT, None

    commit_result = _run_git(source_root, "rev-parse", "--verify", "HEAD^{commit}")
    if commit_result is None or commit_result.returncode != 0:
        commit = UNKNOWN_COMMIT
    else:
        candidate = commit_result.stdout.decode("ascii", "ignore").strip().lower()
        commit = candidate if re.fullmatch(r"[0-9a-f]{40}", candidate) else UNKNOWN_COMMIT

    dirty_result = _run_git(
        source_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    dirty = (
        None if dirty_result is None or dirty_result.returncode != 0 else bool(dirty_result.stdout)
    )
    return commit, dirty


def collect_runtime_provenance(module_file: Path | None = None) -> RuntimeProvenance:
    """Collect the exact version and anchored Git state for the executing code."""
    resolved_module = Path(__file__) if module_file is None else module_file
    commit, dirty = resolve_git_provenance(resolved_module)
    return RuntimeProvenance(
        package_version=resolve_package_version(resolved_module),
        git_commit=commit,
        git_dirty=dirty,
    )
