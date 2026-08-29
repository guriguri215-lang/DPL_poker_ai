from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALPHA_VERSION = re.compile(r"\b0\.1\.0a\d+\b")
VERSIONED_ASSET = re.compile(r"poker_xai-0\.1\.0a\d+(?:-py3-none-any\.whl|\.tar\.gz)")


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _normalized(relative: str) -> str:
    return " ".join(_text(relative).split())


def _current_version() -> str:
    project = tomllib.loads(_text("pyproject.toml"))
    return project["project"]["version"]


def test_current_release_version_references_move_together() -> None:
    version = _current_version()
    assert re.fullmatch(r"0\.1\.0a\d+", version)
    current_version_files = (
        ".github/workflows/release-artifacts.yml",
        ".github/workflows/verify-published-release.yml",
        "docs/release_verification.md",
        "docs/releasing.md",
        "tests/test_release_artifacts.py",
        "tests/poker_ai/test_runtime_provenance.py",
        "tests/poker_ai/test_session.py",
    )
    for relative in current_version_files:
        assert set(ALPHA_VERSION.findall(_text(relative))) == {version}, relative

    bundle_verifier_test = _text("tests/poker_ai/test_explanation_bundle_verification.py")
    assert set(ALPHA_VERSION.findall(bundle_verifier_test)) == {"0.1.0a8", version}
    assert f"poker-xai-verify-explanation-bundle {version}" in bundle_verifier_test

    for relative in (
        ".github/workflows/release-artifacts.yml",
        ".github/workflows/verify-published-release.yml",
    ):
        workflow = _text(relative)
        assert workflow.count(f'default: "{version}"') == 2, relative
        assert workflow.count(f"|| '{version}'") == 1, relative


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

    runbook = _normalized("docs/releasing.md")
    assert "facing-all-in" in runbook
    assert "40 CFR+ iterations" in runbook
    assert "not a convergence" in runbook
    assert "runtime CLI" in runbook
    assert "RunManifest" in runbook

    readme = _text("README.md")
    assert "facing-all-in" in readme
    assert "40 iterations" in readme
    assert "not a convergence guarantee" in readme

    # This is historical scope, not a current-version reference.
    assert "Starting with `0.1.0a4`" in readme


def test_manual_and_automated_post_publication_checks_are_documented() -> None:
    for relative in ("docs/releasing.md", "docs/release_verification.md"):
        document = _normalized(relative)
        for required in (
            "Verify published release assets",
            "published",
            "workflow_dispatch",
            "contents: read",
            "uploaded assets",
            "source archives",
            "new, empty directory",
            "network-free",
            "read-only",
            "no-install",
            "category",
            "target filename",
        ):
            assert required in document, f"{relative}: {required}"
        assert "does not replace or permit skipping" in document
        assert "cannot undo a publication" in document


def test_release_notes_contract_covers_verified_evaluation_display_and_limits() -> None:
    runbook = _normalized("docs/releasing.md")
    for required in (
        "explicit `--show-evaluation` opt-in",
        "exact two-line default output",
        "exit codes, public Python API, read-only behavior",
        "all pass on one captured snapshot",
        "must not reread the post-session artifact after verification",
        "six existing evaluation metrics",
        "exact exploit-EV gain",
        "over/under-adjustment counts",
        "explanation validity",
        "every existing next-session setting",
        "without hashes, local paths, answer-key data, diagnostic notes",
        "older bundle without a post-session artifact remains verifiable without the flag",
        "Tamper, missing or duplicate artifacts",
        "fail before stdout and leave the bundle unchanged",
        "legacy bundle without post-session data still verifies with no flag",
        "produce no partial success output and do not change the bundle",
        "same captured snapshot; the artifact is not reread after verification",
        "source checkout, unpacked wheel, and unpacked sdist",
        "source bundle byte-for-byte unchanged",
        "does not rerun a session, solver, or answer-key evaluator",
        "independent recomputation",
        "no new dependency, entry point, schema, artifact, registry, file discovery",
        "automatic handoff",
        "automatic session loop",
        "workflow topology, release mechanism",
        "published-release four-asset verification workflow",
        "continued required manual verification",
        "release documentation contract test",
        "exact four-asset contract",
        "simulation-only",
        "Phase 6",
        "Gate B",
        "facing-all-in",
        "40 CFR+ iterations",
        "not a convergence guarantee",
        "make no convergence, GTO, strategy-safety, profitability, or real-world performance claim",
    ):
        assert required in runbook, required

    release_verification = _normalized("docs/release_verification.md")
    for required in (
        "`--show-evaluation` output",
        "all six stored evaluation metrics",
        "exact-EV gain and over/under-adjustment counts",
        "every existing next-session setting",
        "same fixed order",
        "byte-for-byte unchanged",
    ):
        assert required in release_verification, required
