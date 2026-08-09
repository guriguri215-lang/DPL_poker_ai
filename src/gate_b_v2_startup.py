"""Stdlib-only bootstrap for the Gate B v2 production process."""

from __future__ import annotations

import importlib.machinery
import inspect
import os
import stat
import sys
import sysconfig
from pathlib import Path
from types import ModuleType

_BOOTSTRAP_TOKEN = object()


class GateBV2StartupError(RuntimeError):
    """The interpreter was not created with the closed production startup."""


def _new_bootstrap_state():
    state: dict[str, tuple[object, ...] | None] = {"attestation": None}

    def get() -> tuple[object, ...] | None:
        return state["attestation"]

    def set_value(value: tuple[object, ...]) -> None:
        state["attestation"] = value

    return get, set_value


_BOOTSTRAP_STATE = _new_bootstrap_state()


def _reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _single_link_regular(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
        or metadata.st_nlink != 1
    ):
        raise GateBV2StartupError("Gate B v2 startup path topology mismatch")
    return metadata


def _venv_dependency_path(executable: Path) -> tuple[Path, Path]:
    scripts = executable.parent
    expected_scripts = "Scripts" if os.name == "nt" else "bin"
    if scripts.name != expected_scripts:
        raise GateBV2StartupError("Gate B v2 startup requires a copied virtual environment")
    venv_root = scripts.parent.resolve()
    configuration = venv_root / "pyvenv.cfg"
    _single_link_regular(configuration)
    if os.name == "nt":
        dependency_path = venv_root / "Lib" / "site-packages"
    else:
        dependency_path = (
            venv_root
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
    dependency_path = dependency_path.resolve(strict=True)
    metadata = dependency_path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
        raise GateBV2StartupError("Gate B v2 dependency path topology mismatch")
    if venv_root not in dependency_path.parents:
        raise GateBV2StartupError("Gate B v2 dependency path escaped its virtual environment")
    return venv_root, dependency_path


def _cpython_startup_config() -> dict[str, object]:
    try:
        import _testinternalcapi

        spec = _testinternalcapi.__spec__
        getter = _testinternalcapi.get_configs
        provider_root = Path(sys.base_prefix).resolve()
        if os.name == "nt":
            expected_origin = provider_root / "DLLs" / "_testinternalcapi.pyd"
        else:
            destination = sysconfig.get_config_var("DESTSHARED")
            extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
            if type(destination) is not str or type(extension_suffix) is not str:
                raise GateBV2StartupError("CPython startup provider mismatch")
            expected_origin = Path(destination) / f"_testinternalcapi{extension_suffix}"
        expected_origin = expected_origin.resolve()
        if (
            type(_testinternalcapi) is not ModuleType
            or provider_root not in expected_origin.parents
            or type(spec.loader) is not importlib.machinery.ExtensionFileLoader
            or spec.loader.name != "_testinternalcapi"
            or Path(spec.loader.path).resolve() != expected_origin
            or Path(spec.origin).resolve() != expected_origin
            or not inspect.isbuiltin(getter)
            or getter.__self__ is not _testinternalcapi
            or getter.__name__ != "get_configs"
        ):
            raise GateBV2StartupError("CPython startup provider mismatch")
        config = getter()["config"]
        if type(config) is not dict:
            raise GateBV2StartupError("CPython startup configuration mismatch")
        return config
    except GateBV2StartupError:
        raise
    except Exception as exc:
        raise GateBV2StartupError("CPython startup verification failed closed") from exc


def bootstrap_gate_b_v2_source_only_startup() -> Path:
    """Validate ``-S`` startup, then append exactly one fixed dependency path."""
    if _BOOTSTRAP_STATE[0]() is not None:
        return require_gate_b_v2_bootstrap()
    try:
        source_root = Path(__file__).resolve().parent
        executable = Path(sys.executable).resolve(strict=True)
        executable_metadata = _single_link_regular(executable)
        venv_root, dependency_path = _venv_dependency_path(executable)
        config = _cpython_startup_config()
        python_path = tuple(
            Path(value).resolve()
            for value in os.environ.get("PYTHONPATH", "").split(os.pathsep)
            if value
        )
        startup_paths = tuple(
            Path(value).resolve() for value in sys.path if value and Path(value).exists()
        )
        startup_prefix = Path(config["pycache_prefix"]).resolve()
        if os.name == "nt" and (
            not executable.drive or str(executable).startswith(("\\\\", "\\\\?\\", "\\\\.\\"))
        ):
            raise GateBV2StartupError("Gate B v2 startup requires a fixed local executable")
        if (
            config.get("write_bytecode") != 0
            or config.get("safe_path") != 1
            or config.get("user_site_directory") != 0
            or config.get("site_import") != 0
            or sys.flags.dont_write_bytecode != 1
            or sys.flags.safe_path != 1
            or sys.flags.no_user_site != 1
            or sys.flags.no_site != 1
            or not sys.dont_write_bytecode
            or sys.pycache_prefix is None
            or Path(sys.pycache_prefix).resolve() != startup_prefix
            or startup_prefix != executable
            or executable_metadata.st_nlink != 1
            or python_path != (source_root,)
            or startup_paths.count(source_root) != 1
            or "" in sys.path
            or any(path.name in {"site-packages", "dist-packages"} for path in startup_paths)
            or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
            or os.environ.get("PYTHONNOUSERSITE") != "1"
            or os.environ.get("PYTHONSAFEPATH") != "1"
            or any(name in sys.modules for name in ("site", "sitecustomize", "usercustomize"))
        ):
            raise GateBV2StartupError("Gate B v2 source-only startup mismatch")
        sys.path.append(str(dependency_path))
        _BOOTSTRAP_STATE[1](
            (
                _BOOTSTRAP_TOKEN,
                executable,
                venv_root,
                source_root,
                dependency_path,
            )
        )
        return dependency_path
    except GateBV2StartupError:
        raise
    except Exception as exc:
        raise GateBV2StartupError("Gate B v2 source-only startup failed closed") from exc


def require_gate_b_v2_bootstrap() -> Path:
    """Revalidate the in-memory proof created before dependencies were addressable."""
    attestation = _BOOTSTRAP_STATE[0]()
    if (
        type(attestation) is not tuple
        or len(attestation) != 5
        or attestation[0] is not _BOOTSTRAP_TOKEN
    ):
        raise GateBV2StartupError("Gate B v2 production bootstrap is missing")
    _token, executable, venv_root, source_root, dependency_path = attestation
    live_site_paths = {
        Path(value).resolve()
        for value in sys.path
        if value
        and Path(value).exists()
        and Path(value).resolve().name in {"site-packages", "dist-packages"}
    }
    if (
        Path(sys.executable).resolve() != executable
        or Path(__file__).resolve().parent != source_root
        or venv_root not in dependency_path.parents
        or live_site_paths != {dependency_path}
        or sum(Path(value).resolve() == source_root for value in sys.path if value) != 1
        or sys.flags.no_site != 1
        or sys.flags.safe_path != 1
        or sys.flags.no_user_site != 1
        or sys.flags.dont_write_bytecode != 1
    ):
        raise GateBV2StartupError("Gate B v2 production bootstrap provenance mismatch")
    return dependency_path
