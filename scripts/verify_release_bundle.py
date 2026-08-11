"""Read-only verification of the final four-file GitHub Release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from publication_policy import content_issues, path_issue

DIST_NAME = "poker-xai"
NORMALIZED_NAME = "poker_xai"
MANIFEST_NAME = "artifact-manifest.json"
CHECKSUM_NAME = "SHA256SUMS"
INTERNAL_LAYOUT = "internal"
FLAT_LAYOUT = "flat"
SMOKE_SURFACES = ["source-checkout", "unpacked-wheel", "unpacked-sdist"]
SMOKE_CHECKS = [
    "--version",
    "--help",
    "minimal-session",
    "manifest-round-trip",
    "entry-point-metadata",
    "documentation-relative-links",
]


class BundleVerificationError(RuntimeError):
    """The final release bundle failed a redacted verification category."""


def _fail(filename: str, category: str) -> None:
    raise BundleVerificationError(f"release bundle issue: file={filename} category={category}")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checksum_entries(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii")
    except (OSError, UnicodeDecodeError):
        _fail(path.name, "checksum-encoding")
    if not text.endswith("\n"):
        _fail(path.name, "checksum-format")
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)", line)
        if match is None:
            _fail(path.name, "checksum-format")
        digest, filename = match.groups()
        if filename in result:
            _fail(path.name, "checksum-duplicate")
        result[filename] = digest
    return result


def _bundle_files(bundle: Path, version: str, layout: str) -> tuple[Path, Path, Path, Path]:
    wheel_name = f"{NORMALIZED_NAME}-{version}-py3-none-any.whl"
    sdist_name = f"{NORMALIZED_NAME}-{version}.tar.gz"
    if layout == INTERNAL_LAYOUT:
        relative = {
            f"dist/{wheel_name}",
            f"dist/{sdist_name}",
            f"evidence/{MANIFEST_NAME}",
            f"evidence/{CHECKSUM_NAME}",
        }
        expected_directories = {"dist", "evidence"}
        wheel = bundle / "dist" / wheel_name
        sdist = bundle / "dist" / sdist_name
        manifest_path = bundle / "evidence" / MANIFEST_NAME
        checksums_path = bundle / "evidence" / CHECKSUM_NAME
    elif layout == FLAT_LAYOUT:
        relative = {wheel_name, sdist_name, MANIFEST_NAME, CHECKSUM_NAME}
        expected_directories = set()
        wheel = bundle / wheel_name
        sdist = bundle / sdist_name
        manifest_path = bundle / MANIFEST_NAME
        checksums_path = bundle / CHECKSUM_NAME
    else:
        raise BundleVerificationError("release bundle issue: category=layout")

    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
    directories = {
        path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_dir()
    }
    if actual != relative or directories != expected_directories:
        raise BundleVerificationError("release bundle issue: category=exact-four-file-allowlist")
    return wheel, sdist, manifest_path, checksums_path


def verify_bundle(
    bundle: Path, version: str, *, layout: str = INTERNAL_LAYOUT
) -> dict[str, object]:
    wheel, sdist, manifest_path, checksums_path = _bundle_files(bundle, version, layout)
    for path in (wheel, sdist, manifest_path, checksums_path):
        category = path_issue(path.name)
        if category is not None:
            _fail(path.name, category)
    for path in (manifest_path, checksums_path):
        issues = content_issues(path.read_bytes())
        if issues:
            _fail(path.name, issues[0])

    checksum_entries = _checksum_entries(checksums_path)
    hashed_files = {wheel.name: wheel, sdist.name: sdist, manifest_path.name: manifest_path}
    if set(checksum_entries) != set(hashed_files):
        _fail(checksums_path.name, "checksum-asset-allowlist")
    for filename, path in hashed_files.items():
        if checksum_entries[filename] != _hash(path):
            _fail(filename, "checksum-mismatch")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(manifest_path.name, "manifest-json")
    if not isinstance(manifest, dict):
        _fail(manifest_path.name, "manifest-shape")
    if set(manifest) != {
        "distribution",
        "version",
        "source_commit",
        "artifacts",
        "reproducible",
        "offline_smoke",
        "smoke_mode",
        "smoke_surfaces",
        "smoke_checks",
    }:
        _fail(manifest_path.name, "manifest-key-allowlist")
    if manifest.get("distribution") != DIST_NAME:
        _fail(manifest_path.name, "manifest-distribution")
    if manifest.get("version") != version:
        _fail(manifest_path.name, "manifest-version")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        _fail(manifest_path.name, "manifest-source-commit")
    expected_artifacts = {wheel.name: _hash(wheel), sdist.name: _hash(sdist)}
    if manifest.get("artifacts") != expected_artifacts:
        _fail(manifest_path.name, "manifest-artifact-hashes")
    if manifest.get("reproducible") is not True:
        _fail(manifest_path.name, "manifest-reproducibility")
    if manifest.get("offline_smoke") is not True:
        _fail(manifest_path.name, "manifest-offline-smoke")
    if manifest.get("smoke_mode") != "source-and-archive-extraction-existing-python":
        _fail(manifest_path.name, "manifest-smoke-mode")
    if manifest.get("smoke_surfaces") != SMOKE_SURFACES:
        _fail(manifest_path.name, "manifest-smoke-surfaces")
    if manifest.get("smoke_checks") != SMOKE_CHECKS:
        _fail(manifest_path.name, "manifest-smoke-checks")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument(
        "--layout",
        choices=(INTERNAL_LAYOUT, FLAT_LAYOUT),
        default=INTERNAL_LAYOUT,
        help="internal workflow bundle or flat GitHub Release download directory",
    )
    args = parser.parse_args()
    try:
        verify_bundle(args.bundle.resolve(), args.expected_version, layout=args.layout)
    except BundleVerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"release bundle issue: category={type(exc).__name__}", file=sys.stderr)
        return 1
    print("release bundle verification: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
