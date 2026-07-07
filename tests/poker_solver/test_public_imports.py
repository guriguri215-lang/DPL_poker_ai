"""Public import smoke tests for solver package entry points."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "src"


@pytest.mark.parametrize("module", ["poker_solver", "poker_solver.nodelock"])
def test_solver_public_imports_work_in_fresh_process(module: str) -> None:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(_SRC_ROOT)
        if not existing_pythonpath
        else os.pathsep.join((str(_SRC_ROOT), existing_pythonpath))
    )

    completed = subprocess.run(
        [sys.executable, "-c", f"import {module}; print('ok')"],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"
