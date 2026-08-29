from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CURRENT_VERSION = "0.1.0a16"
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
bundle = _module("verify_release_bundle")
checksums = _module("write_release_checksums")


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
    assert project["project"]["version"] == CURRENT_VERSION
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
    assert "--wheelhouse" not in workflow
    assert "ubuntu-24.04" in workflow
    assert "windows-2022" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in workflow
    assert "gh release" not in workflow
    verifier = (SCRIPTS / "verify_release_artifacts.py").read_text(encoding="utf-8")
    assert '"pip"' not in verifier
    assert "venv.EnvBuilder" not in verifier
    assert "archive.extractall" in verifier
    assert "poker-xai-gate-b-v2" in verifier
    assert "poker-xai-run-session" in verifier
    assert "poker-xai-verify-explanation-bundle" in verifier
    assert "manifest.code.package_version" in verifier
    assert "loaded['poker-xai-run-session'](['--version'])" in verifier
    assert "loaded['poker-xai-verify-explanation-bundle'](['--version'])" in verifier
    assert "loaded['poker-xai-run-session'](first_argv)" in verifier
    assert "loaded['poker-xai-run-session'](second_argv)" in verifier
    assert "'--previous-session-manifest'" in verifier
    assert "positive_argv = [" in verifier
    assert "'--leaky-fixture'" in verifier
    assert "if dpl.exploit_source == 'nodelock_solver'" in verifier
    assert "dpl.ev_estimate.exploit_ev > dpl.ev_estimate.base_ev" in verifier
    assert "dpl.solver_result_id in explanation.rendered_text" in verifier
    assert "verify_explanation(explanation, dpl)" in verifier
    assert "positive_bundle_output" in verifier
    assert "r007_argv = [" in verifier
    assert "'--leaky-fixture-reason'" in verifier
    assert "'LEAK_R007'" in verifier
    assert "r007_pairs[0][0].detected_leaks == []" in verifier
    assert "r007_manifest.code.entrypoint" in verifier
    assert "r007_manifest.code.argv == r007_argv" in verifier
    assert "r007_bundle_output" in verifier
    assert "source-checkout" in verifier
    assert "verify_documentation_links(documentation_root)" in verifier
    assert workflow.count("verify_release_bundle.py") == 3
    assert "control/scripts/write_release_checksums.py" in workflow
    assert workflow.index("Verify final four-file release bundle") < workflow.index(
        "Upload final four-file release bundle"
    )
    assert "Get-FileHash" not in workflow
    final_verifier = (SCRIPTS / "verify_release_bundle.py").read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "zipfile",
        "tarfile",
        "pip",
    ):
        assert forbidden not in final_verifier


def test_sdist_document_and_runtime_data_contracts_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracked = {
        "CONTRIBUTING.md",
        "docs/README.md",
        "docs/releasing.md",
        "docs/release_verification.md",
        "docs/not-public.txt",
        "src/experiments/README.md",
        "src/poker_ai/README.md",
        "src/poker_ai/notes.md",
    }
    stdout = b"\0".join(path.encode() for path in sorted(tracked)) + b"\0"
    monkeypatch.setattr(
        release.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=stdout),
    )

    assert release._tracked_sdist_documents(ROOT) == {
        "CONTRIBUTING.md",
        "docs/README.md",
        "docs/releasing.md",
        "docs/release_verification.md",
        "src/experiments/README.md",
        "src/poker_ai/README.md",
    }
    assert (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines() == [
        "include CONTRIBUTING.md",
        "recursive-include configs/opponents/equilibria *.equilibrium.json",
        "recursive-include configs/opponents/training *.opponent.json",
        "recursive-include configs/opponents/validation *.opponent.json",
        "recursive-include docs *.md",
        "recursive-include src README.md",
    ]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["setuptools"]["include-package-data"] is False
    assert project["tool"]["setuptools"]["data-files"] == {
        "configs/opponents/equilibria": ["configs/opponents/equilibria/*.equilibrium.json"],
        "configs/opponents/training": ["configs/opponents/training/*.opponent.json"],
        "configs/opponents/validation": ["configs/opponents/validation/*.opponent.json"],
    }


def test_wheel_runtime_data_maps_to_the_existing_tracked_catalog_and_equilibrium() -> None:
    tracked = release._tracked_opponent_data(ROOT)
    training = {path for path in tracked if "/training/" in path}
    validation = {path for path in tracked if "/validation/" in path}
    equilibrium = {path for path in tracked if "/equilibria/" in path}
    assert len(training) == len(validation) == 9
    assert equilibrium == {
        "configs/opponents/equilibria/river-large-bet-equilibrium-v1.equilibrium.json"
    }
    sources = release._wheel_payload_sources(ROOT, CURRENT_VERSION)
    prefix = f"poker_xai-{CURRENT_VERSION}.data/data/"
    assert {
        member.removeprefix(prefix) for member in sources if member.startswith(prefix)
    } == tracked
    assert {sources[f"{prefix}{path}"] for path in tracked} == tracked


def test_release_verifier_checks_unpacked_documentation_links(tmp_path: Path) -> None:
    project = tmp_path / f"poker_xai-{CURRENT_VERSION}"
    docs = project / "docs"
    component = project / "src" / "poker_core"
    docs.mkdir(parents=True)
    component.mkdir(parents=True)
    (project / "README.md").write_text("[Docs](docs/README.md)\n", encoding="utf-8")
    (project / "CONTRIBUTING.md").write_text("[Docs](docs/README.md)\n", encoding="utf-8")
    (docs / "README.md").write_text("[Component](../src/poker_core/README.md)\n", encoding="utf-8")
    component_readme = component / "README.md"
    component_readme.write_text("# Component\n", encoding="utf-8")

    release.verify_documentation_links(project)

    component_readme.unlink()
    with pytest.raises(release.VerificationError, match="documentation-link-missing"):
        release.verify_documentation_links(project)


def test_sdist_document_bytes_must_equal_the_tracked_git_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_opponent_data", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_top_level_sdist_tests", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_sdist_documents", lambda _source: {"docs/README.md"})
    monkeypatch.setattr(release, "_git_blob", lambda _source, _path: b"tracked\n")
    sdist = tmp_path / f"poker_xai-{CURRENT_VERSION}.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        info = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}/docs/README.md")
        data = b"changed\n"
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    with pytest.raises(release.VerificationError, match="tracked-payload-byte-mismatch"):
        release.verify_sdist(sdist, ROOT, CURRENT_VERSION)


def test_sdist_rejects_generated_metadata_outside_the_exact_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_opponent_data", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_top_level_sdist_tests", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_sdist_documents", lambda _source: set())
    monkeypatch.setattr(release, "_git_blob", lambda _source, _path: b"tracked\n")
    sdist = tmp_path / f"poker_xai-{CURRENT_VERSION}.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        for relative in ("LICENSE", "MANIFEST.in", "README.md", "pyproject.toml"):
            info = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}/{relative}")
            data = b"tracked\n"
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}/src/poker_xai.egg-info/unexpected.txt")
        data = b"generated\n"
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    with pytest.raises(release.VerificationError, match="generated metadata allowlist"):
        release.verify_sdist(sdist, ROOT, CURRENT_VERSION)


def _release_bundle(tmp_path: Path, layout: str) -> tuple[Path, Path, Path, Path, Path]:
    staging = tmp_path / "fixture-staging"
    dist = staging / "dist"
    evidence = staging / "evidence"
    dist.mkdir(parents=True)
    evidence.mkdir()
    wheel = dist / f"poker_xai-{CURRENT_VERSION}-py3-none-any.whl"
    sdist = dist / f"poker_xai-{CURRENT_VERSION}.tar.gz"
    wheel.write_bytes(b"wheel\n")
    sdist.write_bytes(b"sdist\n")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = evidence / "artifact-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "distribution": "poker-xai",
                "version": CURRENT_VERSION,
                "source_commit": "a" * 40,
                "artifacts": {wheel.name: digest(wheel), sdist.name: digest(sdist)},
                "reproducible": True,
                "offline_smoke": True,
                "smoke_mode": "source-and-archive-extraction-existing-python",
                "smoke_surfaces": [
                    "source-checkout",
                    "unpacked-wheel",
                    "unpacked-sdist",
                ],
                "smoke_checks": [
                    "--version",
                    "--help",
                    "two-consecutive-hero-sessions",
                    "explicit-previous-session-manifest",
                    "manifest-round-trip",
                    "saved-explanation-bundle-verification",
                    "solver-backed-explanation-provenance",
                    "r007-solver-backed-no-facing-explanation-provenance",
                    "r001-r002-release-surface-parity",
                    "r002-verified-two-session-handoff",
                    "entry-point-metadata",
                    "documentation-relative-links",
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    checksum = evidence / "SHA256SUMS"
    checksums.write_checksums(dist, manifest, checksum, CURRENT_VERSION)

    if layout == bundle.INTERNAL_LAYOUT:
        return staging, wheel, sdist, manifest, checksum
    if layout != bundle.FLAT_LAYOUT:
        raise AssertionError(f"unsupported test layout: {layout}")

    release_bundle = tmp_path / "release-bundle"
    release_bundle.mkdir()
    flattened = []
    for path in (wheel, sdist, manifest, checksum):
        flattened.append(path.replace(release_bundle / path.name))
    evidence.rmdir()
    dist.rmdir()
    staging.rmdir()
    return release_bundle, *flattened


def _rewrite_checksums(wheel: Path, sdist: Path, manifest: Path, checksum: Path) -> None:
    candidates = sorted((wheel, sdist, manifest), key=lambda path: path.name)
    checksum.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in candidates
        ),
        encoding="ascii",
        newline="\n",
    )


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_final_release_bundle_is_exact_self_verifying_four_file_set(
    tmp_path: Path, layout: str
) -> None:
    release_bundle, wheel, sdist, manifest, checksum = _release_bundle(tmp_path, layout)
    before = _file_bytes(release_bundle)

    result = bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)

    assert _file_bytes(release_bundle) == before
    assert result["version"] == CURRENT_VERSION
    checksum_names = {line.split("  ", 1)[1] for line in checksum.read_text().splitlines()}
    assert checksum_names == {wheel.name, sdist.name, manifest.name}
    assert all("/" not in name and "\\" not in name for name in checksum_names)


def test_internal_checksum_writer_does_not_replace_final_evidence(tmp_path: Path) -> None:
    release_bundle, _, _, manifest, checksum = _release_bundle(tmp_path, bundle.INTERNAL_LAYOUT)
    with pytest.raises(checksums.ChecksumError, match="already exists"):
        checksums.write_checksums(release_bundle / "dist", manifest, checksum, CURRENT_VERSION)


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_release_bundle_rejects_missing_asset(tmp_path: Path, layout: str) -> None:
    release_bundle, _, _, manifest, _ = _release_bundle(tmp_path, layout)
    manifest.unlink()
    with pytest.raises(bundle.BundleVerificationError, match="exact-four-file-allowlist"):
        bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_release_bundle_rejects_extra_asset(tmp_path: Path, layout: str) -> None:
    release_bundle, *_ = _release_bundle(tmp_path, layout)
    extra = release_bundle / "extra.txt"
    extra.write_text("extra\n", encoding="utf-8")
    with pytest.raises(bundle.BundleVerificationError, match="exact-four-file-allowlist"):
        bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_release_bundle_rejects_checksum_mismatch(tmp_path: Path, layout: str) -> None:
    release_bundle, wheel, *_ = _release_bundle(tmp_path, layout)
    wheel.write_bytes(b"changed\n")
    with pytest.raises(bundle.BundleVerificationError, match="checksum-mismatch"):
        bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_release_bundle_rejects_manifest_mismatch(tmp_path: Path, layout: str) -> None:
    release_bundle, wheel, sdist, manifest, checksum = _release_bundle(tmp_path, layout)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["offline_smoke"] = False
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _rewrite_checksums(wheel, sdist, manifest, checksum)
    with pytest.raises(bundle.BundleVerificationError, match="manifest-offline-smoke"):
        bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)


@pytest.mark.parametrize("layout", [bundle.INTERNAL_LAYOUT, bundle.FLAT_LAYOUT])
def test_release_bundle_rejects_checksum_self_target(tmp_path: Path, layout: str) -> None:
    release_bundle, _, _, manifest, checksum = _release_bundle(tmp_path, layout)
    lines = checksum.read_text(encoding="ascii").splitlines()
    manifest_index = next(
        index for index, line in enumerate(lines) if line.endswith(f"  {manifest.name}")
    )
    digest = lines[manifest_index].split("  ", 1)[0]
    lines[manifest_index] = f"{digest}  {checksum.name}"
    checksum.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    with pytest.raises(bundle.BundleVerificationError, match="checksum-asset-allowlist"):
        bundle.verify_bundle(release_bundle, CURRENT_VERSION, layout=layout)


def test_flat_release_bundle_cli_uses_the_same_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    release_bundle, *_ = _release_bundle(tmp_path, bundle.FLAT_LAYOUT)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_release_bundle.py",
            "--bundle",
            str(release_bundle),
            "--layout",
            bundle.FLAT_LAYOUT,
            "--expected-version",
            CURRENT_VERSION,
        ],
    )
    assert bundle.main() == 0
    assert capsys.readouterr().out == "release bundle verification: passed\n"


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
    wheel = tmp_path / f"poker_xai-{CURRENT_VERSION}-py3-none-any.whl"
    sdist = tmp_path / f"poker_xai-{CURRENT_VERSION}.tar.gz"
    wheel.touch()
    sdist.touch()
    assert release._distribution_files(tmp_path, CURRENT_VERSION) == (wheel, sdist)
    (tmp_path / "temporary.tmp").touch()
    with pytest.raises(release.VerificationError, match="exactly one expected wheel"):
        release._distribution_files(tmp_path, CURRENT_VERSION)


def test_sdist_normalization_is_byte_reproducible(tmp_path: Path) -> None:
    outputs = []
    for index in range(2):
        path = tmp_path / f"input-{index}.tar.gz"
        with tarfile.open(path, mode="w:gz") as archive:
            info = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}/module.py")
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
    monkeypatch.setattr(release, "_tracked_opponent_data", lambda _source: set())
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("pkg/__pycache__/", b"")
    with pytest.raises(release.VerificationError, match="local-or-build-path"):
        release.verify_wheel(wheel, ROOT, CURRENT_VERSION)


def test_sdist_rejects_unsafe_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: set())
    monkeypatch.setattr(release, "_tracked_opponent_data", lambda _source: set())
    sdist = tmp_path / "unsafe.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        unsafe = tarfile.TarInfo(f"poker_xai-{CURRENT_VERSION}/build")
        unsafe.type = tarfile.DIRTYPE
        archive.addfile(unsafe)
    with pytest.raises(release.VerificationError, match="local-or-build-path"):
        release.verify_sdist(sdist, ROOT, CURRENT_VERSION)


def test_wheel_payload_must_equal_the_tracked_git_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "_tracked_payload", lambda _source: {"module.py"})
    monkeypatch.setattr(release, "_tracked_opponent_data", lambda _source: set())
    monkeypatch.setattr(release, "_git_blob", lambda _source, _path: b"tracked\n")
    wheel = tmp_path / "mismatch.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("module.py", b"transformed\n")
    with pytest.raises(release.VerificationError, match="tracked-payload-byte-mismatch"):
        release.verify_wheel(wheel, ROOT, CURRENT_VERSION)
