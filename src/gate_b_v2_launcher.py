"""Process-start production launcher for Gate B v2."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence

from gate_b_v2_startup import GateBV2StartupError, bootstrap_gate_b_v2_source_only_startup


def _startup_error() -> int:
    payload = {
        "schema_version": "phase6-gate-b-v2-cli-error-v1",
        "operation": "pre-dispatch",
        "status": "failed",
        "error_code": "gate_b_invalid_preflight",
    }
    raw = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )
    try:
        sys.stderr.buffer.write(raw)
        sys.stderr.buffer.flush()
    except BaseException:
        pass
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        bootstrap_gate_b_v2_source_only_startup()
    except GateBV2StartupError:
        return _startup_error()
    from phase6.gate_b_v2_cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    from gate_b_v2_launcher import main as canonical_main

    raise SystemExit(canonical_main())
