"""Write the final release checksums exactly once."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

NORMALIZED_NAME = "poker_xai"
MANIFEST_NAME = "artifact-manifest.json"
CHECKSUM_NAME = "SHA256SUMS"


class ChecksumError(RuntimeError):
    """The release inputs cannot produce the final checksum file."""


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(dist: Path, manifest: Path, output: Path, version: str) -> None:
    """Hash the wheel, sdist, and manifest without replacing prior evidence."""
    wheel = dist / f"{NORMALIZED_NAME}-{version}-py3-none-any.whl"
    sdist = dist / f"{NORMALIZED_NAME}-{version}.tar.gz"
    files = tuple(sorted(path for path in dist.iterdir() if path.is_file()))
    if set(files) != {wheel, sdist}:
        raise ChecksumError("release dist does not contain the exact wheel/sdist pair")
    if manifest.name != MANIFEST_NAME or not manifest.is_file():
        raise ChecksumError("release artifact manifest is unavailable")
    if output.name != CHECKSUM_NAME:
        raise ChecksumError("release checksum filename is not canonical")
    if output.exists():
        raise ChecksumError("release checksum evidence already exists")

    candidates = sorted((wheel, sdist, manifest), key=lambda path: path.name)
    if len({path.name for path in candidates}) != len(candidates):
        raise ChecksumError("release asset basenames are not unique")
    lines = "".join(f"{_hash(path)}  {path.name}\n" for path in candidates)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="ascii", newline="\n") as stream:
        stream.write(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    try:
        write_checksums(
            args.dist.resolve(),
            args.manifest.resolve(),
            args.output.resolve(),
            args.expected_version,
        )
    except (ChecksumError, OSError) as exc:
        print(
            f"release checksum generation failed: category={type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    print("release checksum generation: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
