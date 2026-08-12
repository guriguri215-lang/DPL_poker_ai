from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "verify-published-release.yml"


def _workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _current_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return project["project"]["version"]


def test_published_release_workflow_triggers_and_permissions_are_read_only() -> None:
    workflow = _workflow()
    parsed = yaml.load(workflow, Loader=yaml.BaseLoader)
    assert parsed["on"]["release"]["types"] == ["published"]
    assert "workflow_dispatch" in parsed["on"]
    assert re.search(
        r"(?m)^on:\n  release:\n    types: \[published\]\n  workflow_dispatch:\n",
        workflow,
    )
    assert '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow
    assert workflow.count('python-version: "3.12.10"') == 1

    permissions = re.search(r"(?m)^permissions:\n(?P<body>(?:  [^\n]+\n)+)", workflow)
    assert permissions is not None
    assert permissions.group("body") == "  contents: read\n"
    for forbidden in (
        "contents: write",
        "issues: write",
        "pull-requests: write",
        "actions: write",
        "releases: write",
        "gh release create",
        "gh release upload",
        "gh release edit",
        "gh release delete",
        "gh issue",
        "gh pr",
        "git push",
        "--method POST",
        "--method PATCH",
        "--method DELETE",
    ):
        assert forbidden not in workflow


def test_published_release_identity_and_current_version_must_all_match() -> None:
    workflow = _workflow()
    version = _current_version()
    assert workflow.count(f'default: "{version}"') == 2
    assert workflow.count(f"|| '{version}'") == 1
    assert "github.event.release.tag_name" in workflow
    assert '[[ "$RELEASE_TAG" == "$EXPECTED_VERSION" ]]' in workflow
    assert "ref: refs/tags/${{ env.RELEASE_TAG }}" in workflow
    assert 'git -C source rev-list -n 1 "refs/tags/$RELEASE_TAG"' in workflow
    assert 'project["project"]["version"]' in workflow
    assert 'payload.get("tag_name") != release_tag' in workflow
    assert 'payload.get("prerelease") is not True' in workflow
    assert 'payload.get("draft") is not False' in workflow


def test_uploaded_assets_are_the_exact_flat_four_file_set() -> None:
    workflow = _workflow()
    expected_names = (
        'f"poker_xai-{version}-py3-none-any.whl"',
        'f"poker_xai-{version}.tar.gz"',
        '"artifact-manifest.json"',
        '"SHA256SUMS"',
    )
    for name in expected_names:
        assert workflow.count(name) >= 2, name
    assert 'assets = payload.get("assets")' in workflow
    assert 'asset.get("state") != "uploaded"' in workflow
    assert "duplicate-uploaded-asset" in workflow
    assert "missing-uploaded-asset" in workflow
    assert "unexpected-uploaded-asset" in workflow
    assert "zipball_url" not in workflow
    assert "tarball_url" not in workflow
    assert "--archive" not in workflow


def test_asset_retrieval_is_separate_from_tag_source_flat_verification() -> None:
    workflow = _workflow()
    metadata = workflow.index("Retrieve published release metadata")
    download = workflow.index("Download all uploaded release assets")
    local_verification = workflow.index("Verify the flat bundle with the tagged source")
    assert metadata < download < local_verification
    assert 'mktemp -d "$RUNNER_TEMP/published-release-assets.XXXXXX"' in workflow
    assert 'gh release download "$RELEASE_TAG"' in workflow
    assert "python source/scripts/verify_release_bundle.py" in workflow
    assert "--layout flat" in workflow
    assert '--expected-version "$EXPECTED_VERSION"' in workflow
    assert workflow.count("GH_TOKEN: ${{ github.token }}") == 2
    assert "GH_TOKEN" not in workflow[local_verification:]

    for forbidden in (
        "pip install",
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "zipfile",
        "tarfile",
    ):
        assert forbidden not in workflow
    assert 'PIP_NO_INDEX: "1"' in workflow[local_verification:]
    assert 'PYTHONDONTWRITEBYTECODE: "1"' in workflow[local_verification:]


def test_workflow_failures_are_redacted_to_category_and_filename() -> None:
    workflow = _workflow()
    assert "category=%s filename=%s" in workflow
    assert "category={category} filename={filename}" in workflow
    assert "gh api --method GET" in workflow
    assert workflow.count("2>/dev/null") >= 4
    assert "automatic repair" not in workflow.lower()
