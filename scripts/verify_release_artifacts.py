"""Verify reproducible poker-xai wheel/sdist artifacts and offline installs."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email.policy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urlparse

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from publication_policy import content_issues, path_issue

DIST_NAME = "poker-xai"
NORMALIZED_NAME = "poker_xai"
EXPECTED_ENTRY_POINTS = {
    "poker-xai-export-schemas": "poker_core.schema_export:main",
    "poker-xai-gate-b-v2": "gate_b_v2_launcher:main",
}
EXPECTED_SMOKE_DISTRIBUTIONS = {
    "annotated-types": "0.7.0",
    "pydantic": "2.11.7",
    "pydantic-core": "2.33.2",
    "PyYAML": "6.0.2",
    "typing-extensions": "4.14.1",
    "typing-inspection": "0.4.1",
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
            | {
                "LICENSE",
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


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


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


def _assert_report_sources(report: Path, artifact: Path, wheelhouse: Path) -> None:
    allowed_artifact = artifact.resolve()
    allowed_wheelhouse = wheelhouse.resolve()
    payload = json.loads(report.read_text(encoding="utf-8"))
    for item in payload.get("install", ()):
        url = item.get("download_info", {}).get("url")
        parsed = urlparse(url) if isinstance(url, str) else None
        if parsed is None or parsed.scheme != "file":
            raise VerificationError("offline smoke report contains a non-file source")
        raw_path = unquote(parsed.path)
        if os.name == "nt" and len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
            raw_path = raw_path[1:]
        resolved = Path(raw_path).resolve()
        if resolved != allowed_artifact and allowed_wheelhouse not in resolved.parents:
            raise VerificationError("offline smoke report escaped the approved wheelhouse")


def _smoke_one(artifact: Path, wheelhouse: Path, version: str, work: Path) -> None:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("PIP_") or name in {"PYTHONHOME", "PYTHONPATH"}:
            environment.pop(name, None)
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    venv_root = work / artifact.name.replace(".", "-")
    venv.EnvBuilder(with_pip=True, symlinks=False).create(venv_root)
    python = _venv_python(venv_root)
    find_links = str(wheelhouse.resolve())
    upgrade = _run(
        [
            str(python),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--find-links",
            find_links,
            "pip==25.2",
        ],
        cwd=work,
        environment=environment,
    )
    if upgrade.returncode != 0:
        raise VerificationError("offline smoke could not provision pinned pip")
    install_report = work / f"{artifact.name}.install-report.json"
    installed = _run(
        [
            str(python),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--no-compile",
            "--find-links",
            find_links,
            "--report",
            str(install_report),
            str(artifact.resolve()),
        ],
        cwd=work,
        environment=environment,
    )
    if installed.returncode != 0:
        raise VerificationError(f"offline smoke install failed for {artifact.name}")
    _assert_report_sources(install_report, artifact, wheelhouse)
    script = """
import importlib.metadata
distribution = importlib.metadata.distribution('poker-xai')
assert distribution.version == EXPECTED_VERSION
for name, expected_version in EXPECTED_DISTRIBUTIONS.items():
    assert importlib.metadata.version(name) == expected_version
actual = {
    entry.name: entry.value
    for entry in distribution.entry_points
    if entry.group == 'console_scripts'
}
assert actual == EXPECTED_ENTRY_POINTS
assert all(
    callable(entry.load())
    for entry in distribution.entry_points
    if entry.group == 'console_scripts'
)
"""
    script = (
        script.replace("EXPECTED_VERSION", repr(version))
        .replace("EXPECTED_DISTRIBUTIONS", repr(EXPECTED_SMOKE_DISTRIBUTIONS))
        .replace("EXPECTED_ENTRY_POINTS", repr(EXPECTED_ENTRY_POINTS))
    )
    checked = _run(
        [str(python), "-I", "-c", script],
        cwd=work,
        environment=environment,
    )
    if checked.returncode != 0:
        raise VerificationError(f"installed metadata check failed for {artifact.name}")
    scripts = venv_root / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    exported = _run(
        [str(scripts / f"poker-xai-export-schemas{suffix}"), "--help"],
        cwd=work,
        environment=environment,
    )
    if exported.returncode != 0 or "--out-dir" not in exported.stdout:
        raise VerificationError(f"console smoke failed for {artifact.name}")
    gated = _run(
        [str(scripts / f"poker-xai-gate-b-v2{suffix}")],
        cwd=work,
        environment=environment,
    )
    expected_error = {
        "schema_version": "phase6-gate-b-v2-cli-error-v1",
        "operation": "pre-dispatch",
        "status": "failed",
        "error_code": "gate_b_invalid_preflight",
    }
    try:
        gate_error = json.loads(gated.stderr)
    except json.JSONDecodeError:
        gate_error = None
    if gated.returncode != 1 or gated.stdout or gate_error != expected_error:
        raise VerificationError(f"Gate B console fail-closed smoke failed for {artifact.name}")


def smoke_install(wheel: Path, sdist: Path, wheelhouse: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="poker-xai-release-smoke-") as temporary:
        work = Path(temporary)
        _smoke_one(wheel, wheelhouse, version, work)
        _smoke_one(sdist, wheelhouse, version, work)


def verify(
    source: Path,
    dist: Path,
    version: str,
    *,
    compare_dist: Path | None = None,
    wheelhouse: Path | None = None,
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
    if wheelhouse is not None:
        smoke_install(wheel, sdist, wheelhouse, version)
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
        "offline_smoke": wheelhouse is not None,
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
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(
            args.source.resolve(),
            args.dist.resolve(),
            args.expected_version,
            compare_dist=args.compare_dist.resolve() if args.compare_dist else None,
            wheelhouse=args.wheelhouse.resolve() if args.wheelhouse else None,
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
