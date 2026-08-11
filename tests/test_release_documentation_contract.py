from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALPHA_VERSION = re.compile(r"\b0\.1\.0a\d+\b")
VERSIONED_ASSET = re.compile(r"poker_xai-0\.1\.0a\d+(?:-py3-none-any\.whl|\.tar\.gz)")


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _current_version() -> str:
    project = tomllib.loads(_text("pyproject.toml"))
    return project["project"]["version"]


def test_current_release_version_references_move_together() -> None:
    version = _current_version()
    assert re.fullmatch(r"0\.1\.0a\d+", version)
    current_version_files = (
        ".github/workflows/release-artifacts.yml",
        "docs/release_verification.md",
        "docs/releasing.md",
        "tests/test_release_artifacts.py",
        "tests/poker_ai/test_runtime_provenance.py",
        "tests/poker_ai/test_session.py",
    )
    for relative in current_version_files:
        assert set(ALPHA_VERSION.findall(_text(relative))) == {version}, relative

    workflow = _text(".github/workflows/release-artifacts.yml")
    assert workflow.count(f'default: "{version}"') == 2
    assert workflow.count(f"|| '{version}'") == 1


def test_release_documents_name_the_exact_current_four_assets() -> None:
    version = _current_version()
    wheel = f"poker_xai-{version}-py3-none-any.whl"
    sdist = f"poker_xai-{version}.tar.gz"
    expected_versioned_assets = {wheel, sdist}
    expected_assets = expected_versioned_assets | {
        "artifact-manifest.json",
        "SHA256SUMS",
    }

    for relative in ("docs/release_verification.md", "docs/releasing.md"):
        document = _text(relative)
        assert set(VERSIONED_ASSET.findall(document)) == expected_versioned_assets, relative
        for asset in expected_assets:
            assert asset in document, f"{relative}: {asset}"
        assert "--layout flat" in document
        assert "exact four" in document.lower() or "four-asset" in document.lower()


def test_release_runbook_is_linked_and_preserves_alpha_limitations() -> None:
    assert "](docs/releasing.md)" in _text("CONTRIBUTING.md")
    assert "](docs/releasing.md)" in _text("README.md")
    assert "](releasing.md)" in _text("docs/README.md")

    runbook = _text("docs/releasing.md")
    assert "facing-all-in" in runbook
    assert "40 CFR+ iterations" in runbook
    assert "not a convergence" in runbook
    assert "runtime CLI" in runbook
    assert "RunManifest" in runbook

    # This is historical scope, not a current-version reference.
    assert "Starting with `0.1.0a4`" in _text("README.md")
