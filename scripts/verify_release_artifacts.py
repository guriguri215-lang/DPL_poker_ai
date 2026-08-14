"""Verify reproducible poker-xai wheel/sdist artifacts without installing them."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email.policy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urlsplit

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from publication_policy import content_issues, path_issue

DIST_NAME = "poker-xai"
NORMALIZED_NAME = "poker_xai"
EXPECTED_ENTRY_POINTS = {
    "poker-xai-export-schemas": "poker_core.schema_export:main",
    "poker-xai-gate-b-v2": "gate_b_v2_launcher:main",
    "poker-xai-run-session": "poker_ai.run_session_cli:main",
    "poker-xai-verify-explanation-bundle": "poker_ai.explanation_bundle_cli:main",
}
_WHEEL_METADATA_FILES = {
    "METADATA",
    "RECORD",
    "WHEEL",
    "entry_points.txt",
    "licenses/LICENSE",
    "top_level.txt",
}
_SDIST_EGG_INFO_FILES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}
_INLINE_DOCUMENTATION_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^\s)]+)")
_REFERENCE_DOCUMENTATION_LINK = re.compile(
    r"^\s*\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)",
    flags=re.MULTILINE,
)


class VerificationError(RuntimeError):
    """An artifact failed the publication policy."""


def _fail(location: str, category: str) -> None:
    raise VerificationError(f"artifact issue: location={location} category={category}")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _distribution_files(dist: Path, version: str) -> tuple[Path, Path]:
    files = tuple(sorted(path for path in dist.iterdir() if path.is_file()))
    wheel = dist / f"{NORMALIZED_NAME}-{version}-py3-none-any.whl"
    sdist = dist / f"{NORMALIZED_NAME}-{version}.tar.gz"
    if files != (sdist, wheel) and files != (wheel, sdist):
        raise VerificationError("dist must contain exactly one expected wheel and one sdist")
    return wheel, sdist


def _tracked_payload(source: Path) -> set[str]:
    completed = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--", "src"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise VerificationError("unable to resolve tracked release payload")
    tracked = {
        raw.decode("utf-8", "surrogateescape") for raw in completed.stdout.split(b"\0") if raw
    }
    return {
        path.removeprefix("src/")
        for path in tracked
        if Path(path).suffix.lower() in {".py", ".yaml"}
    }


def _git_blob(source: Path, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(source), "cat-file", "blob", f"HEAD:{path}"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise VerificationError(f"tracked artifact source is unavailable: {path}")
    return completed.stdout


def _tracked_top_level_sdist_tests(source: Path) -> set[str]:
    completed = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--", "tests"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise VerificationError("unable to resolve tracked sdist tests")
    result = set()
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        candidate = Path(path)
        if candidate.parent.as_posix() == "tests" and candidate.match("test*.py"):
            result.add(candidate.as_posix())
    return result


def _tracked_sdist_documents(source: Path) -> set[str]:
    completed = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--", "CONTRIBUTING.md", "docs", "src"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise VerificationError("unable to resolve tracked sdist documentation")
    tracked = {
        raw.decode("utf-8", "surrogateescape") for raw in completed.stdout.split(b"\0") if raw
    }
    documents = {
        path
        for path in tracked
        if path == "CONTRIBUTING.md"
        or (path.startswith("docs/") and Path(path).suffix.lower() == ".md")
        or (path.startswith("src/") and Path(path).name == "README.md")
    }
    if not {"CONTRIBUTING.md", "docs/README.md"}.issubset(documents):
        raise VerificationError("required tracked sdist documentation is unavailable")
    return documents


def _relative_documentation_targets(markdown: str) -> tuple[str, ...]:
    matches = (
        *_INLINE_DOCUMENTATION_LINK.finditer(markdown),
        *_REFERENCE_DOCUMENTATION_LINK.finditer(markdown),
    )
    targets = []
    for match in matches:
        target = match.group("target").strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("#") or not parsed.path:
            continue
        targets.append(unquote(parsed.path))
    return tuple(targets)


def verify_documentation_links(project: Path) -> None:
    root = project.resolve()
    documents = (
        root / "README.md",
        root / "CONTRIBUTING.md",
        *sorted((root / "docs").rglob("*.md")),
    )
    if not documents or any(not document.is_file() for document in documents):
        _fail("documentation", "documentation-file-missing")
    for document in documents:
        try:
            markdown = document.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            _fail(document.relative_to(root).as_posix(), "documentation-unreadable")
        for target in _relative_documentation_targets(markdown):
            resolved = (document.parent / target).resolve()
            location = document.relative_to(root).as_posix()
            if resolved != root and root not in resolved.parents:
                _fail(location, "documentation-link-escape")
            if not resolved.exists():
                _fail(location, "documentation-link-missing")


def _check_member(location: str, member: str, data: bytes, *, allow_egg_info: bool = False) -> None:
    category = path_issue(member)
    if category == "unexpected-egg-info" and allow_egg_info:
        category = None
    if category is not None:
        _fail(location, category)
    issues = content_issues(data)
    if issues:
        _fail(location, issues[0])


def _requirement_key(value: str) -> tuple[str, tuple[str, ...], str, str | None, str | None]:
    requirement = Requirement(value)
    return (
        canonicalize_name(requirement.name),
        tuple(sorted(requirement.extras)),
        str(requirement.specifier),
        requirement.url,
        str(requirement.marker) if requirement.marker else None,
    )


def _expected_requirements(source: Path) -> tuple[set[tuple[object, ...]], set[str]]:
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    requirements = {_requirement_key(value) for value in project.get("dependencies", ())}
    optional = project.get("optional-dependencies", {})
    for extra, values in optional.items():
        for value in values:
            requirement, separator, marker = value.partition(";")
            combined_marker = (
                f"({marker}) and extra == '{extra}'" if separator else f"extra == '{extra}'"
            )
            requirements.add(_requirement_key(f"{requirement}; {combined_marker}"))
    return requirements, set(optional)


def _metadata(data: bytes, version: str, source: Path, location: str) -> Message:
    message = email.message_from_bytes(data, policy=email.policy.default)
    if message["Name"] != DIST_NAME:
        _fail(location, "distribution-name-mismatch")
    if message["Version"] != version:
        _fail(location, "distribution-version-mismatch")
    if message["Requires-Python"] != ">=3.12":
        _fail(location, "requires-python-mismatch")
    expected_requirements, expected_extras = _expected_requirements(source)
    actual_requirements = {
        _requirement_key(value) for value in message.get_all("Requires-Dist", ())
    }
    if actual_requirements != expected_requirements:
        _fail(location, "requires-dist-mismatch")
    if set(message.get_all("Provides-Extra", ())) != expected_extras:
        _fail(location, "provides-extra-mismatch")
    return message


def _entry_points(data: bytes, location: str) -> None:
    parser = configparser.ConfigParser()
    parser.read_string(data.decode("utf-8"))
    actual = dict(parser.items("console_scripts")) if parser.has_section("console_scripts") else {}
    if actual != EXPECTED_ENTRY_POINTS:
        _fail(location, "console-entry-point-mismatch")


def _wheel_metadata(data: bytes) -> None:
    message = email.message_from_bytes(data, policy=email.policy.default)
    if message["Wheel-Version"] != "1.0":
        _fail("wheel:WHEEL", "wheel-version-mismatch")
    if message["Root-Is-Purelib"] != "true":
        _fail("wheel:WHEEL", "wheel-purity-mismatch")
    if message.get_all("Tag", ()) != ["py3-none-any"]:
        _fail("wheel:WHEEL", "wheel-tag-mismatch")
    if message["Generator"] != "setuptools (83.0.0)":
        _fail("wheel:WHEEL", "wheel-generator-mismatch")


def _verify_record(archive: zipfile.ZipFile, metadata_root: str) -> None:
    record_name = f"{metadata_root}RECORD"
    rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    expected_names = {info.filename for info in archive.infolist() if not info.is_dir()}
    if any(len(row) != 3 for row in rows) or {row[0] for row in rows} != expected_names:
        _fail("wheel:RECORD", "wheel-record-member-mismatch")
    for path, recorded_hash, recorded_size in rows:
        if path == record_name:
            if recorded_hash or recorded_size:
                _fail("wheel:RECORD", "wheel-record-self-mismatch")
            continue
        data = archive.read(path)
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        )
        if recorded_hash != f"sha256={digest}" or recorded_size != str(len(data)):
            _fail(f"wheel:{path}", "wheel-record-hash-mismatch")


def verify_wheel(wheel: Path, source: Path, version: str) -> None:
    expected_payload = _tracked_payload(source)
    metadata_root = f"{NORMALIZED_NAME}-{version}.dist-info/"
    payload: set[str] = set()
    metadata_files: set[str] = set()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise VerificationError("wheel contains duplicate members")
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                _fail(f"wheel:{info.filename}", "archive-link")
            _check_member(f"wheel:{info.filename}", info.filename, b"")
            if info.is_dir():
                continue
            data = archive.read(info)
            _check_member(f"wheel:{info.filename}", info.filename, data)
            if info.filename.startswith(metadata_root):
                metadata_files.add(info.filename.removeprefix(metadata_root))
            else:
                payload.add(info.filename)
                if data != _git_blob(source, f"src/{info.filename}"):
                    _fail(f"wheel:{info.filename}", "tracked-payload-byte-mismatch")
        if payload != expected_payload:
            raise VerificationError("wheel payload does not exactly match tracked runtime sources")
        if metadata_files != _WHEEL_METADATA_FILES:
            raise VerificationError("wheel generated metadata allowlist mismatch")
        metadata = archive.read(f"{metadata_root}METADATA")
        _metadata(metadata, version, source, "wheel:METADATA")
        _entry_points(
            archive.read(f"{metadata_root}entry_points.txt"),
            "wheel:entry_points.txt",
        )
        _wheel_metadata(archive.read(f"{metadata_root}WHEEL"))
        if archive.read(f"{metadata_root}licenses/LICENSE") != _git_blob(source, "LICENSE"):
            _fail("wheel:licenses/LICENSE", "tracked-payload-byte-mismatch")
        _verify_record(archive, metadata_root)


def verify_sdist(sdist: Path, source: Path, version: str) -> None:
    prefix = f"{NORMALIZED_NAME}-{version}/"
    expected_payload = {f"src/{path}" for path in _tracked_payload(source)}
    repository_files: set[str] = set()
    generated: set[str] = set()
    egg_prefix = f"src/{NORMALIZED_NAME}.egg-info/"
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = [member.name for member in archive.getmembers()]
        if len(names) != len(set(names)):
            raise VerificationError("sdist contains duplicate members")
        for member in archive.getmembers():
            if member.isdir() and member.name.rstrip("/") == prefix.rstrip("/"):
                _check_member(f"sdist:{member.name}", member.name, b"")
                continue
            if not member.name.startswith(prefix):
                _fail(f"sdist:{member.name}", "sdist-root-mismatch")
            relative = member.name.removeprefix(prefix)
            is_egg_info = relative.rstrip("/") == egg_prefix.rstrip("/") or relative.startswith(
                egg_prefix
            )
            _check_member(
                f"sdist:{relative}",
                relative,
                b"",
                allow_egg_info=is_egg_info,
            )
            if not relative or member.isdir():
                continue
            if not member.isfile():
                _fail(f"sdist:{relative}", "archive-link-or-special-file")
            stream = archive.extractfile(member)
            if stream is None:
                _fail(f"sdist:{relative}", "unreadable-member")
            data = stream.read()
            _check_member(
                f"sdist:{relative}",
                relative,
                data,
                allow_egg_info=is_egg_info,
            )
            if is_egg_info:
                generated.add(relative.removeprefix(egg_prefix))
            elif relative in {"PKG-INFO", "setup.cfg"}:
                generated.add(relative)
            else:
                repository_files.add(relative)
                if data != _git_blob(source, relative):
                    _fail(f"sdist:{relative}", "tracked-payload-byte-mismatch")
        expected_repository = (
            expected_payload
            | _tracked_top_level_sdist_tests(source)
            | _tracked_sdist_documents(source)
            | {
                "LICENSE",
                "MANIFEST.in",
                "README.md",
                "pyproject.toml",
            }
        )
        if repository_files != expected_repository:
            raise VerificationError(
                "sdist payload does not exactly match the release source allowlist"
            )
        expected_generated = _SDIST_EGG_INFO_FILES | {"PKG-INFO", "setup.cfg"}
        if generated != expected_generated:
            raise VerificationError("sdist generated metadata allowlist mismatch")
        _metadata(
            archive.extractfile(f"{prefix}PKG-INFO").read(),
            version,
            source,
            "sdist:PKG-INFO",
        )
        _entry_points(
            archive.extractfile(f"{prefix}src/{NORMALIZED_NAME}.egg-info/entry_points.txt").read(),
            "sdist:entry_points.txt",
        )


def _run(
    command: list[str], *, cwd: Path, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _extract_artifact(artifact: Path, destination: Path, version: str) -> Path:
    """Extract a pre-verified archive and return its import/metadata root."""
    destination.mkdir()
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            archive.extractall(destination)
        return destination
    expected_root = destination / f"{NORMALIZED_NAME}-{version}"
    with tarfile.open(artifact, mode="r:gz") as archive:
        archive.extractall(destination, filter="data")
    if not expected_root.is_dir() or tuple(destination.iterdir()) != (expected_root,):
        raise VerificationError("sdist smoke extraction root mismatch")
    import_root = expected_root / "src"
    if not import_root.is_dir():
        raise VerificationError("sdist smoke import root is missing")
    return import_root


def _smoke_one(
    artifact: Path | None,
    version: str,
    work: Path,
    *,
    source: Path | None = None,
) -> None:
    if (artifact is None) == (source is None):
        raise VerificationError("smoke surface must be exactly one source or archive")
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("PIP_") or name in {"PYTHONHOME", "PYTHONPATH"}:
            environment.pop(name, None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    if source is not None:
        surface_name = "source-checkout"
        surface_work = work / surface_name
        surface_work.mkdir()
        import_root = source / "src"
        source_project = source
        documentation_root = source
    else:
        assert artifact is not None
        surface_name = artifact.name
        surface_work = work / artifact.name.replace(".", "-")
        import_root = _extract_artifact(artifact, surface_work, version)
        source_project = None
        documentation_root = import_root.parent if artifact.name.endswith(".tar.gz") else None
    if not import_root.is_dir():
        raise VerificationError(f"smoke import root is missing for {surface_name}")
    if documentation_root is not None:
        verify_documentation_links(documentation_root)
    run_root = surface_work / "offline-run"
    run_root.mkdir()
    output_root = run_root / "session-output"
    script = r"""
import contextlib
import io
import importlib
import importlib.metadata
import json
import sys
import tomllib
from pathlib import Path

import_root = Path(sys.argv[1]).resolve()
output_root = Path(sys.argv[2]).resolve()
source_project_arg = sys.argv[3]
source_project = Path(source_project_arg).resolve() if source_project_arg else None
sys.path.insert(0, str(import_root))

if source_project is not None:
    project = tomllib.loads((source_project / 'pyproject.toml').read_text(encoding='utf-8'))
    assert project['project']['name'] == 'poker-xai'
    assert project['project']['version'] == EXPECTED_VERSION
    actual = dict(project['project']['scripts'])
    assert actual == EXPECTED_ENTRY_POINTS

    def load_target(value):
        module_name, separator, attribute = value.partition(':')
        assert separator and module_name and attribute
        return getattr(importlib.import_module(module_name), attribute)

    loaded = {name: load_target(value) for name, value in actual.items()}
else:
    distributions = [
        item
        for item in importlib.metadata.distributions(path=[str(import_root)])
        if item.metadata['Name'] == 'poker-xai'
    ]
    assert len(distributions) == 1
    distribution = distributions[0]
    assert distribution.version == EXPECTED_VERSION
    actual = {
        entry.name: entry.value
        for entry in distribution.entry_points
        if entry.group == 'console_scripts'
    }
    assert actual == EXPECTED_ENTRY_POINTS
    entries = {
        entry.name: entry
        for entry in distribution.entry_points
        if entry.group == 'console_scripts'
    }
    loaded = {name: entry.load() for name, entry in entries.items()}
assert all(callable(value) for value in loaded.values())

import poker_ai.run_session_cli as session_cli
assert Path(session_cli.__file__).resolve().is_relative_to(import_root)
import poker_ai.explanation_bundle_cli as explanation_bundle_cli
assert Path(explanation_bundle_cli.__file__).resolve().is_relative_to(import_root)

version_output = io.StringIO()
try:
    with contextlib.redirect_stdout(version_output):
        loaded['poker-xai-run-session'](['--version'])
except SystemExit as stopped:
    assert stopped.code == 0
else:
    raise AssertionError('session --version did not stop through argparse')
assert version_output.getvalue() == f'poker-xai-run-session {EXPECTED_VERSION}\n'
assert not output_root.exists()

bundle_version_output = io.StringIO()
try:
    with contextlib.redirect_stdout(bundle_version_output):
        loaded['poker-xai-verify-explanation-bundle'](['--version'])
except SystemExit as stopped:
    assert stopped.code == 0
else:
    raise AssertionError('bundle verifier --version did not stop through argparse')
assert bundle_version_output.getvalue() == (
    f'poker-xai-verify-explanation-bundle {EXPECTED_VERSION}\n'
)
assert not output_root.exists()

help_output = io.StringIO()
try:
    with contextlib.redirect_stdout(help_output):
        loaded['poker-xai-run-session'](['--help'])
except SystemExit as stopped:
    assert stopped.code == 0
else:
    raise AssertionError('session --help did not stop through argparse')
assert '--solver-iterations' in help_output.getvalue()
assert '--out-dir' in help_output.getvalue()
assert '--version' in help_output.getvalue()
assert not output_root.exists()

bundle_help_output = io.StringIO()
try:
    with contextlib.redirect_stdout(bundle_help_output):
        loaded['poker-xai-verify-explanation-bundle'](['--help'])
except SystemExit as stopped:
    assert stopped.code == 0
else:
    raise AssertionError('bundle verifier --help did not stop through argparse')
assert '--manifest' in bundle_help_output.getvalue()
assert not output_root.exists()

schema_help = io.StringIO()
try:
    with contextlib.redirect_stdout(schema_help):
        loaded['poker-xai-export-schemas'](['--help'])
except SystemExit as stopped:
    assert stopped.code == 0
else:
    raise AssertionError('schema --help did not stop through argparse')
assert '--out-dir' in schema_help.getvalue()

gate_stdout = io.StringIO()
gate_stderr_bytes = io.BytesIO()
gate_stderr = io.TextIOWrapper(gate_stderr_bytes, encoding='ascii')
with contextlib.redirect_stdout(gate_stdout), contextlib.redirect_stderr(gate_stderr):
    gate_status = loaded['poker-xai-gate-b-v2']([])
gate_stderr.flush()
assert gate_status == 1
assert gate_stdout.getvalue() == ''
assert json.loads(gate_stderr_bytes.getvalue().decode('ascii')) == {
    'schema_version': 'phase6-gate-b-v2-cli-error-v1',
    'operation': 'pre-dispatch',
    'status': 'failed',
    'error_code': 'gate_b_invalid_preflight',
}

first_output_root = output_root / 'first'
first_argv = [
    '--seed',
    '7',
    '--hands',
    '1',
    '--solver-iterations',
    '1',
    '--explanations',
    '--safety-alpha',
    '0.25',
    '--exploration-epsilon',
    '0.2',
    '--out-dir',
    str(first_output_root),
]
with contextlib.redirect_stdout(io.StringIO()):
    assert loaded['poker-xai-run-session'](first_argv) == 0

from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest

first_manifest_paths = list(first_output_root.glob('*.manifest.json'))
assert len(first_manifest_paths) == 1
first_manifest_path = first_manifest_paths[0]

second_output_root = output_root / 'second'
second_argv = [
    '--seed',
    '8',
    '--hands',
    '1',
    '--solver-iterations',
    '1',
    '--explanations',
    '--previous-session-manifest',
    str(first_manifest_path),
    '--out-dir',
    str(second_output_root),
]
with contextlib.redirect_stdout(io.StringIO()):
    assert loaded['poker-xai-run-session'](second_argv) == 0

for session_root, raw_argv in (
    (first_output_root, first_argv),
    (second_output_root, second_argv),
):
    manifest_paths = list(session_root.glob('*.manifest.json'))
    dpl_paths = list(session_root.glob('*.dpl.jsonl'))
    assert len(manifest_paths) == len(dpl_paths) == 1
    manifest = RunManifest.model_validate_json(manifest_paths[0].read_text(encoding='utf-8'))
    assert RunManifest.model_validate_json(manifest.model_dump_json()) == manifest
    assert manifest.code.package_version == EXPECTED_VERSION
    if source_project is None:
        assert manifest.code.git_commit == 'unknown'
        assert manifest.code.git_dirty is None
    else:
        assert len(manifest.code.git_commit) == 40
        assert isinstance(manifest.code.git_dirty, bool)
    assert manifest.code.entrypoint == 'poker-xai-run-session'
    assert manifest.code.argv == raw_argv
    lines = dpl_paths[0].read_text(encoding='utf-8').splitlines()
    assert len(lines) == 1
    dpl = DecisionProvenanceLog.model_validate_json(lines[0])
    assert dpl.schema_version == '3.0.0'
    if raw_argv is second_argv:
        assert dpl.safety_alpha == 0.25
        execution_samplers = [item for item in manifest.configs if item.name == 'execution_sampler']
        assert len(execution_samplers) == 1
        assert execution_samplers[0].path == 'inline:epsilon-uniform-v1:epsilon=0.2'
    bundle_output = io.StringIO()
    with contextlib.redirect_stdout(bundle_output):
        assert loaded['poker-xai-verify-explanation-bundle'](
            ['--manifest', str(manifest_paths[0])]
        ) == 0
    assert bundle_output.getvalue().splitlines() == [
        'artifact_integrity=passed references=5',
        'explanation_checker=passed total=1 summary=consistent',
    ]
"""
    script = script.replace("EXPECTED_VERSION", repr(version)).replace(
        "EXPECTED_ENTRY_POINTS", repr(EXPECTED_ENTRY_POINTS)
    )
    checked = _run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(import_root),
            str(output_root),
            str(source_project) if source_project is not None else "",
        ],
        cwd=run_root,
        environment=environment,
    )
    if checked.returncode != 0:
        raise VerificationError(f"offline smoke failed for {surface_name}")


def smoke_release_surfaces(source: Path, wheel: Path, sdist: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="poker-xai-release-smoke-") as temporary:
        work = Path(temporary)
        _smoke_one(None, version, work, source=source)
        _smoke_one(wheel, version, work)
        _smoke_one(sdist, version, work)


def verify(
    source: Path,
    dist: Path,
    version: str,
    *,
    compare_dist: Path | None = None,
    report: Path | None = None,
) -> dict[str, object]:
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
    if project["project"]["version"] != version:
        raise VerificationError("source project version mismatch")
    wheel, sdist = _distribution_files(dist, version)
    verify_wheel(wheel, source, version)
    verify_sdist(sdist, source, version)
    hashes = {path.name: _hash(path) for path in (wheel, sdist)}
    if compare_dist is not None:
        compare_wheel, compare_sdist = _distribution_files(compare_dist, version)
        compare_hashes = {path.name: _hash(path) for path in (compare_wheel, compare_sdist)}
        if hashes != compare_hashes:
            raise VerificationError("independent release builds are not byte-for-byte reproducible")
    smoke_release_surfaces(source, wheel, sdist, version)
    result: dict[str, object] = {
        "distribution": DIST_NAME,
        "version": version,
        "source_commit": subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip(),
        "artifacts": hashes,
        "reproducible": compare_dist is not None,
        "offline_smoke": True,
        "smoke_mode": "source-and-archive-extraction-existing-python",
        "smoke_surfaces": ["source-checkout", "unpacked-wheel", "unpacked-sdist"],
        "smoke_checks": [
            "--version",
            "--help",
            "two-consecutive-hero-sessions",
            "explicit-previous-session-manifest",
            "manifest-round-trip",
            "saved-explanation-bundle-verification",
            "entry-point-metadata",
            "documentation-relative-links",
        ],
    }
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--compare-dist", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(
            args.source.resolve(),
            args.dist.resolve(),
            args.expected_version,
            compare_dist=args.compare_dist.resolve() if args.compare_dist else None,
            report=args.report.resolve() if args.report else None,
        )
    except VerificationError as exc:
        print(f"release artifact verification failed: {exc}", file=sys.stderr)
        return 1
    except (
        OSError,
        KeyError,
        ValueError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as exc:
        print(
            f"release artifact verification failed: category={type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
