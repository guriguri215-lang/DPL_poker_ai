"""Read-only verification of a saved normal Hero explanation bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .explanation_artifacts import (
    SavedExplanationBundleVerificationError,
    verify_saved_explanation_bundle,
)
from .runtime_provenance import resolve_package_version

CONSOLE_ENTRYPOINT = "poker-xai-verify-explanation-bundle"


def _parser(*, entrypoint: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"{entrypoint} {resolve_package_version()}",
        help="show the executing poker-xai distribution version and exit",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="saved normal Hero RunManifest to verify without modifying its bundle",
    )
    return parser


def main(argv: list[str] | None = None, *, entrypoint: str = CONSOLE_ENTRYPOINT) -> int:
    """Verify only the saved bundle identified by ``--manifest``."""

    args = _parser(entrypoint=entrypoint).parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        result = verify_saved_explanation_bundle(args.manifest)
    except SavedExplanationBundleVerificationError as exc:
        print(f"explanation bundle verification failed: {exc}", file=sys.stderr)
        return 1

    print(f"artifact_integrity=passed references={result.artifact_count}")
    print(f"explanation_checker=passed total={result.checker_total} summary=consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
