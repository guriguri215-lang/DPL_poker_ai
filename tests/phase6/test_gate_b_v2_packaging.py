from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
from pathlib import Path


def test_gate_b_v2_console_entrypoint_targets_the_closed_cli() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"]["poker-xai-gate-b-v2"] == ("gate_b_v2_launcher:main")
    module = importlib.import_module("gate_b_v2_launcher")
    assert callable(module.main)


def test_readme_documents_the_exact_packaged_invocation() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "-m gate_b_v2_launcher execute-once-v2" in readme
    assert "$env:PYTHONPATH = (Resolve-Path .\\src).Path" in readme
    assert "PYTHONPATH` must\ncontain exactly that checkout's resolved `src` directory" in readme
    assert "PYTHONPYCACHEPREFIX" in readme
    assert "-S -B -P -s -X pycache_prefix=<exact-python.exe>" in readme
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
            "PYTHONSAFEPATH": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONPATH": str(root / "src"),
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-B",
            "-P",
            "-s",
            "-X",
            f"pycache_prefix={Path(sys.executable).resolve()}",
            "-m",
            "gate_b_v2_launcher",
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


def test_exact_startup_blocks_pth_and_sitecustomize_before_bootstrap(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    isolated_venv = tmp_path / "isolated-venv"
    created = subprocess.run(
        [sys.executable, "-m", "venv", "--copies", str(isolated_venv)],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert created.returncode == 0, created.stderr
    if os.name == "nt":
        exact_python = isolated_venv / "Scripts" / "python.exe"
        site_packages = isolated_venv / "Lib" / "site-packages"
    else:
        exact_python = isolated_venv / "bin" / "python"
        site_packages = (
            isolated_venv
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
    side_effect = tmp_path / "startup-hook-ran.txt"
    hook = f"from pathlib import Path; Path({str(side_effect)!r}).write_text('ran')\n"
    (site_packages / "sitecustomize.py").write_text(hook, encoding="utf-8")
    (site_packages / "malicious-startup.pth").write_text("import sitecustomize\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONPATH": str((root / "src").resolve()),
        }
    )
    completed = subprocess.run(
        [
            str(exact_python.resolve()),
            "-S",
            "-B",
            "-P",
            "-s",
            "-X",
            f"pycache_prefix={exact_python.resolve()}",
            "-c",
            (
                "import gate_b_v2_startup as startup; "
                "startup.bootstrap_gate_b_v2_source_only_startup(); "
                "print('guarded')"
            ),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "guarded\n"
    assert completed.stderr == ""
    assert not side_effect.exists()


def test_console_metadata_survives_isolated_offline_target_install() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    build_requirements = project["build-system"]["requires"]
    dev_requirements = project["project"]["optional-dependencies"]["dev"]
    build_setuptools = [value for value in build_requirements if value.startswith("setuptools")]
    dev_setuptools = [value for value in dev_requirements if value.startswith("setuptools")]
    assert build_setuptools == dev_setuptools
    assert len(build_setuptools) == 1
    match = re.fullmatch(r"setuptools==([0-9]+\.[0-9]+\.[0-9]+)", build_setuptools[0])
    assert match is not None, "the build backend must use one complete setuptools pin"
    required_setuptools_version = match.group(1)

    scheme = sysconfig.get_preferred_scheme("prefix")
    configured_backend = os.environ.get("POKER_XAI_OFFLINE_BUILD_BACKEND_PATH")
    candidate_paths = tuple(
        dict.fromkeys(
            (
                *((Path(configured_backend).resolve(),) if configured_backend else ()),
                *(
                    Path(
                        sysconfig.get_path(
                            "purelib",
                            scheme=scheme,
                            vars={"base": prefix, "platbase": prefix},
                        )
                    ).resolve()
                    for prefix in (sys.prefix, sys.base_prefix)
                ),
            )
        )
    )
    backend_path: Path | None = None
    discovered_versions = []
    for path in candidate_paths:
        matches = tuple(
            distribution
            for distribution in importlib.metadata.distributions(path=[str(path)])
            if distribution.metadata["Name"] == "setuptools"
        )
        if matches:
            assert len(matches) == 1, "approved local setuptools backend path is ambiguous"
            discovered_versions.append(matches[0].version)
            if matches[0].version == required_setuptools_version:
                backend_path = path
                break
    if backend_path is None:
        raise AssertionError(
            "offline packaging evidence is incomplete: provision "
            f"setuptools=={required_setuptools_version} in the "
            "approved exact Python from an approved local environment or offline wheelhouse; "
            f"found {discovered_versions or ['none']}; network download is forbidden"
        ) from None

    with tempfile.TemporaryDirectory(prefix="gbp-") as temporary_directory:
        work = Path(temporary_directory)
        isolated_source = work / "source"
        target = work / "target"
        outside = work / "run"
        isolated_source.mkdir()
        outside.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copy2(root / name, isolated_source / name)
        shutil.copytree(
            root / "src",
            isolated_source / "src",
            ignore=shutil.ignore_patterns(
                "__pycache__",
                "*.py[cod]",
                "*.egg-info",
                "build",
                "dist",
            ),
        )
        assert not tuple(isolated_source.rglob("__pycache__"))
        assert not tuple(isolated_source.rglob("*.egg-info"))
        assert not (isolated_source / "build").exists()

        environment = os.environ.copy()
        for name in (
            "PYTHONHOME",
            "PYTHONPATH",
            "PIP_CONFIG_FILE",
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "PIP_FIND_LINKS",
            "PIP_REQUIRE_VIRTUALENV",
            "PIP_TARGET",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONPATH": str(backend_path),
            }
        )
        installed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-cache-dir",
                "--no-compile",
                "--no-deps",
                "--no-build-isolation",
                "--use-pep517",
                "--target",
                str(target),
                str(isolated_source),
            ],
            cwd=work,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
        )
        assert installed.returncode == 0, installed.stderr
        entry_points = tuple(target.glob("poker_xai-*.dist-info/entry_points.txt"))
        assert len(entry_points) == 1
        assert "poker-xai-gate-b-v2 = gate_b_v2_launcher:main" in entry_points[0].read_text(
            encoding="utf-8"
        )

        run_environment = os.environ.copy()
        run_environment.pop("PYTHONHOME", None)
        run_environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONPATH": str(target),
                "PYTHONSAFEPATH": "1",
                "PYTHONPYCACHEPREFIX": str(Path(sys.executable).resolve()),
            }
        )
        script = f"""
import importlib.metadata
import gate_b_v2_startup
from phase6.gate_b_loader import require_gate_b_v2_source_only_startup

gate_b_v2_startup.bootstrap_gate_b_v2_source_only_startup()
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
            [
                sys.executable,
                "-S",
                "-B",
                "-P",
                "-s",
                "-X",
                f"pycache_prefix={Path(sys.executable).resolve()}",
                "-c",
                script,
            ],
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
