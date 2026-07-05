"""CLI: run the Phase-2 river MVP session and write DPL JSONL + a manifest.

Usage::

    python cli/run_session.py --seed 20260704 --hands 200 --out-dir experiments_output/demo

Generates ``--hands`` river decisions deterministically from ``--seed``, validates
each against the frozen DPL schema, includes action-only public leak detection,
writes them as JSONL, and writes a RunManifest sidecar. Output goes under a
gitignored directory (``experiments_output/`` by default). Requires
``pip install -e .``.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from poker_ai.session import run_session, write_jsonl, write_manifest


def _current_git_commit() -> str:
    """The repo HEAD commit, or the ``"unknown"`` sentinel when unavailable."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed", type=int, default=20260704, help="master seed (default: 20260704)"
    )
    parser.add_argument("--hands", type=int, default=200, help="number of hands (default: 200)")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("experiments_output/task3_vertical_slice"),
        help="output directory (gitignored; default: experiments_output/task3_vertical_slice)",
    )
    args = parser.parse_args(argv)

    result = run_session(args.seed, args.hands, git_commit=_current_git_commit())
    jsonl_path = write_jsonl(result.logs, args.out_dir / f"{result.session_id}.dpl.jsonl")
    manifest_path = write_manifest(
        result.manifest, args.out_dir / f"{result.session_id}.manifest.json"
    )

    print(f"session {result.session_id}: {len(result.logs)} decisions validated against DPL v1")
    print(f"wrote {jsonl_path}")
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
