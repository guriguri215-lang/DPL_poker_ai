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


def test_release_notes_contract_covers_r001_r002_parity_and_alpha_limitations() -> None:
    runbook = _normalized("docs/releasing.md")
    for required in (
        "`--leaky-fixture-reason LEAK_R001`",
        "`--leaky-fixture-reason LEAK_R002`",
        "explicit `--leaky-fixture` opt-in",
        "ordinary session, bare `--leaky-fixture`, R007, and R008 defaults",
        "OOP `CHECK` and fixed `BET_75`",
        "0.75-pot equilibrium-artifact provenance",
        "records FOLD/CALL only after Hero actually chose `BET_75`",
        "zero opportunity after `CHECK`",
        "available only to later hands rather than the same decision",
        "complementary CALL baseline",
        "content-hashed noncatalog",
        "HARD/fix-to-baseline opponent/IP/vs_bet/CALL",
        "exact current-node CHECK/BET_75 action EV",
        "strictly improves by more than the existing `1e-12 bb` tolerance",
        "DPL v3",
        "saved-bundle verification",
        "Invalid CLI combinations fail before an output directory is created",
        "release smoke adds R001/R002 release-surface parity",
        "verified R002 two-session handoff",
        "source checkout, unpacked wheel, and unpacked sdist",
        "leaves the source bundle unchanged",
        "restores only the existing settings",
        "reselects R002",
        "saved explanation-bundle checks",
        "R007/R008 smoke",
        "no copied JSON",
        "no new dependency, entry point, schema, default, solver public API",
        "arbitrary bet-size parameter",
        "automatic session loop",
        "registry",
        "workflow topology",
        "release mechanism",
        "published-release four-asset verification workflow",
        "continued required manual verification",
        "release documentation contract test",
        "exact four-asset contract",
        "simulation-only",
        "two consecutive Hero sessions",
        "--previous-session-manifest",
        "Phase 6",
        "Gate B",
        "facing-all-in",
        "40 CFR+ iterations",
        "not a convergence guarantee",
        "make no convergence, GTO, strategy-safety, profitability, or real-world performance claim",
    ):
        assert required in runbook, required
