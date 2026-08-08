from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest


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
    assert "PYTHONPYCACHEPREFIX" in readme
    assert "-B -P -s -X pycache_prefix=<exact-python.exe>" in readme
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


def test_real_python_m_entrypoint_emits_the_fixed_invalid_argument_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONPATH": str(root / "src"),
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-P",
            "-s",
            "-X",
            f"pycache_prefix={Path(sys.executable).resolve()}",
            "-m",
            "phase6.gate_b_v2_cli",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        env=environment,
        timeout=30,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr) == {
        "schema_version": "phase6-gate-b-v2-cli-error-v1",
        "operation": "pre-dispatch",
        "status": "failed",
        "error_code": "gate_b_invalid_arguments",
    }


def test_console_metadata_survives_offline_target_install_without_mutating_venv(
    tmp_path: Path,
) -> None:
    if importlib.util.find_spec("setuptools") is None:
        pytest.skip("shared venv has no offline setuptools build backend")
    root = Path(__file__).resolve().parents[2]
    target = tmp_path / "offline-target"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PIP_NO_INDEX": "1",
        }
    )
    installed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--target",
            str(target),
            str(root),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    )
    assert installed.returncode == 0, installed.stderr
    entry_points = tuple(target.glob("poker_xai-*.dist-info/entry_points.txt"))
    assert len(entry_points) == 1
    assert "poker-xai-gate-b-v2 = phase6.gate_b_v2_cli:main" in entry_points[0].read_text(
        encoding="utf-8"
    )
    outside = tmp_path / "outside-repository"
    outside.mkdir()
    run_environment = environment.copy()
    run_environment.update(
        {
            "PYTHONPATH": str(target),
            "PYTHONSAFEPATH": "1",
            "PYTHONPYCACHEPREFIX": str(Path(sys.executable).resolve()),
        }
    )
    script = f"""
import importlib.metadata
from phase6.gate_b_loader import require_gate_b_v2_source_only_startup

require_gate_b_v2_source_only_startup()

distributions = tuple(importlib.metadata.distributions(path=[{str(target)!r}]))
matches = [
    entry
    for distribution in distributions
    for entry in distribution.entry_points
    if entry.group == 'console_scripts' and entry.name == 'poker-xai-gate-b-v2'
]
assert len(matches) == 1
raise SystemExit(matches[0].load()())
"""
    invoked = subprocess.run(
        [sys.executable, "-c", script],
        cwd=outside,
        check=False,
        capture_output=True,
        env=run_environment,
        timeout=30,
    )
    assert invoked.returncode == 2
    assert invoked.stdout == b""
    assert json.loads(invoked.stderr) == {
        "schema_version": "phase6-gate-b-v2-cli-error-v1",
        "operation": "pre-dispatch",
        "status": "failed",
        "error_code": "gate_b_invalid_arguments",
    }
