from __future__ import annotations

import importlib
import os
import subprocess
import sys
import tomllib
from pathlib import Path


def test_gate_b_v2_console_entrypoint_targets_the_closed_cli() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"]["poker-xai-gate-b-v2"] == ("phase6.gate_b_v2_cli:main")
    module = importlib.import_module("phase6.gate_b_v2_cli")
    assert callable(module.main)


def test_readme_documents_the_exact_packaged_invocation() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "poker-xai-gate-b-v2 execute-once-v2" in readme
    for option in (
        "--spec-parent",
        "--spec-parent-identity-scheme",
        "--spec-parent-serialization-profile",
        "--spec-parent-volume-id-hex",
        "--spec-parent-file-id-hex",
        "--spec-name",
        "--expected-spec-sha256",
        "--expected-spec-size-bytes",
    ):
        assert option in readme


def test_fresh_non_windows_import_and_fixed_local_entry_fail_before_open() -> None:
    script = """
import os
from pathlib import Path
import phase6.gate_b_orchestrator
import phase6.gate_b_v2_cli
import phase6.gate_b_v2_route as route

if os.name == "nt":
    os.name = "posix"
opened = []
route.GateBPinnedDirectory.open = lambda *args, **kwargs: opened.append("opened")
try:
    route.validate_gate_b_v2_fixed_local_path(Path("/tmp/gate-b-v2.json"), "fixture")
except route.GateBV2RouteError:
    pass
else:
    raise AssertionError("non-Windows fixed-local gate did not fail closed")
assert opened == []
"""
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
