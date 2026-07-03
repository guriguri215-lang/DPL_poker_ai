"""CLI: export the frozen Phase-0 contracts as JSON Schema files.

Usage::

    python cli/export_schemas.py --out-dir docs/schemas

Requires the ``poker-xai`` package to be installed (``pip install -e .``). The
logic lives in :mod:`poker_core.schema_export` so it can be unit-tested and is
also exposed as the ``poker-xai-export-schemas`` console command.
"""

from __future__ import annotations

from poker_core.schema_export import main

if __name__ == "__main__":
    raise SystemExit(main())
