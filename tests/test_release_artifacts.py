from __future__ import annotations

import importlib.util
import io
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _module(name: str):
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


publication_policy = _module("publication_policy")
normalizer = _module("normalize_sdist")
release = _module("verify_release_artifacts")


def _requirements(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.partition("#")[0].strip()
        if not line:
            continue
        requirement, _, marker = line.partition(";")
        match = re.fullmatch(r"([A-Za-z0-9_-]+)==([^\s]+)", requirement.strip())
        assert match is not None, f"release requirement is not exactly pinned: {requirement}"
        result[match.group(1).lower()] = match.group(2)
        if marker:
            assert marker.strip() == 'sys_platform == "win32"'
    return result


def test_release_toolchains_are_fully_pinned_and_match_project_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    build = _requirements(ROOT / "requirements" / "release-build.txt")
    smoke = _requirements(ROOT / "requirements" / "release-smoke.txt")
    assert build == {
        "build": "1.3.0",
        "colorama": "0.4.6",
        "packaging": "25.0",
        "pip": "25.2",
        "pyproject-hooks": "1.2.0",
        "setuptools": "83.0.0",
        "wheel": "0.45.1",
    }
    assert project["build-system"]["requires"] == [f"setuptools=={build['setuptools']}"]
    assert project["project"]["version"] == "0.1.0a1"
    direct = {value.lower() for value in project["project"]["dependencies"]}
    assert "pydantic==2.11.7" in direct
    assert "pyyaml==6.0.2" in direct
    assert smoke["pydantic"] == "2.11.7"
    assert smoke["pyyaml"] == "6.0.2"
    assert smoke["pydantic-core"] == "2.33.2"


def test_release_workflow_keeps_exact_python_and_offline_cross_platform_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-artifacts.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count('python-version: "3.12.10"') == 2
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in workflow
    assert "needs.build-ubuntu.outputs.control_sha" in workflow
    assert "refs/tags/{0}" in workflow
    assert "Build twice from independent clean checkouts" in workflow
    assert workflow.count("control/scripts/normalize_sdist.py") == 2
    assert "--compare-dist build-b" in workflow
    assert workflow.count('PIP_NO_INDEX: "1"') == 2
    assert "--wheelhouse wheelhouse" in workflow
    assert "ubuntu-24.04" in workflow
    assert "windows-2022" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in workflow
    assert "gh release" not in workflow
    verifier = (SCRIPTS / "verify_release_artifacts.py").read_text(encoding="utf-8")
    assert verifier.count('"--isolated"') == 2
    assert "poker-xai-gate-b-v2" in verifier


@pytest.mark.parametrize(
    ("path", "category"),
    [
        ("pkg/__pycache__/module.pyc", "local-or-build-path"),
        ("pkg/module.pyc", "temporary-or-sensitive-file"),
        ("../outside", "unsafe-path-topology"),
        ("src/project.egg-info/PKG-INFO", "unexpected-egg-info"),
        ("keys/release.pfx", "temporary-or-sensitive-file"),
    ],
)
def test_publication_path_policy_rejects_non_release_material(path: str, category: str) -> None:
    assert publication_policy.path_issue(path) == category


def test_publication_content_policy_reports_only_redacted_categories() -> None:
    candidate = b"github_pat_" + b"A" * 32
    issues = publication_policy.content_issues(candidate)
    assert issues == ("github-token",)
    assert candidate.decode() not in repr(issues)


@pytest.mark.parametrize(
    ("candidate", "category"),
    [
        (b"-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----", "private-key-material"),
        (b"glpat-" + b"A" * 24, "gitlab-token"),
        (b"npm_" + b"A" * 24, "npm-token"),
        (b"sk-proj-" + b"A" * 24, "api-token"),
        (b"AIza" + b"A" * 35, "google-api-key"),
        (b"sk_live_" + b"A" * 20, "stripe-live-key"),
    ],
)
def test_publication_content_policy_covers_high_confidence_credentials(
    candidate: bytes, category: str
) -> None:
    issues = publication_policy.content_issues(candidate)
    assert category in issues
    assert candidate.decode() not in repr(issues)


def test_distribution_directory_must_contain_only_wheel_and_sdist(tmp_path: Path) -> None:
    wheel = tmp_path / "poker_xai-0.1.0a1-py3-none-any.whl"
    sdist = tmp_path / "poker_xai-0.1.0a1.tar.gz"
    wheel.touch()
    sdist.touch()
    assert release._distribution_files(tmp_path, "0.1.0a1") == (wheel, sdist)
    (tmp_path / "temporary.tmp").touch()
    with pytest.raises(release.VerificationError, match="exactly one expected wheel"):
        release._distribution_files(tmp_path, "0.1.0a1")


def test_sdist_normalization_is_byte_reproducible(tmp_path: Path) -> None:
    outputs = []
    for index in range(2):
        path = tmp_path / f"input-{index}.tar.gz"
        with tarfile.open(path, mode="w:gz") as archive:
            info = tarfile.TarInfo("poker_xai-0.1.0a1/module.py")
            data = b"VALUE = 1\n"
            info.size = len(data)
            info.mtime = 100 + index
            archive.addfile(info, io.BytesIO(data))
        normalizer.normalize(path, 1_700_000_000)
        outputs.append(path.read_bytes())
    assert outputs[0] == outputs[1]


def test_wheel_rejects_unsafe_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: set())
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("pkg/__pycache__/", b"")
    with pytest.raises(release.VerificationError, match="local-or-build-path"):
        release.verify_wheel(wheel, ROOT, "0.1.0a1")


def test_sdist_rejects_unsafe_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: set())
    sdist = tmp_path / "unsafe.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        root = tarfile.TarInfo("poker_xai-0.1.0a1")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        unsafe = tarfile.TarInfo("poker_xai-0.1.0a1/build")
        unsafe.type = tarfile.DIRTYPE
        archive.addfile(unsafe)
    with pytest.raises(release.VerificationError, match="local-or-build-path"):
        release.verify_sdist(sdist, ROOT, "0.1.0a1")


def test_wheel_payload_must_equal_the_tracked_git_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: {"module.py"})
    monkeypatch.setattr(release, "_git_blob", lambda _source, _path: b"tracked\n")
    wheel = tmp_path / "mismatch.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("module.py", b"transformed\n")
    with pytest.raises(release.VerificationError, match="tracked-payload-byte-mismatch"):
        release.verify_wheel(wheel, ROOT, "0.1.0a1")
