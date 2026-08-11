"""Compatibility wrapper for the distributed normal-session CLI.

Prefer ``poker-xai-run-session`` for installed artifacts.  This historical
source-checkout invocation remains supported::

    python cli/run_session.py --seed 20260704 --hands 200
"""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))


def main(argv: list[str] | None = None) -> int:
    from poker_ai import run_session_cli

    return run_session_cli.main(argv, entrypoint=run_session_cli.LEGACY_ENTRYPOINT)


if __name__ == "__main__":
    raise SystemExit(main())
