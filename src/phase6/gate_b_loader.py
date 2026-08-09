"""Explicit-root fail-closed Gate B loader and capability boundary.

The callback is a research-governance trust boundary. This module is not a
security sandbox against a host administrator or malicious in-process code.
It never discovers a Test root from defaults, environment, home, or CWD.
"""

from __future__ import annotations

import ast
import builtins
import ctypes
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import inspect
import json
import marshal
import os
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
import tomllib
import unicodedata
from collections.abc import Mapping
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from types import CodeType, FunctionType, MappingProxyType, ModuleType
from typing import Any, BinaryIO, Protocol

import phase6.gate_b_contracts as gate_b_contracts_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACTIVE_MODULE_PATHS,
    COMPONENT_NAMES,
    DEPENDENCY_LOCK_SCHEMA_VERSION,
    EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
    ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
    SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
    GateBBatchManifest,
    GateBExecutionContext,
    GateBReadinessAuthorization,
    GateBV2CompatibilityObject,
    GateBV2CompatibilityTrustChain,
    build_gate_b_preapproval_root_identity_projection,
    is_gate_b_v2_compatibility_object,
    load_gate_b_batch_manifest_bytes,
    load_gate_b_execution_context_bytes,
    load_gate_b_readiness_authorization_bytes,
    load_gate_b_root_anchor_bytes,
    validate_gate_b_v2_compatibility_trust_chain,
)
from phase6.gate_b_ledger import (
    GateBAttemptReservation,
    GateBLedgerError,
    GateBLedgerRecord,
    GateBLedgerStore,
    GateBPinnedArtifact,
    GateBPinnedDirectory,
    GateBQuarantine,
    mark_gate_b_failed_closed,
    open_gate_b_v2_pinned_directory,
    seal_gate_b_attempt,
    verify_gate_b_v2_pinned_directory,
    verify_gate_b_v2_retained_root_topology,
)

# ACTIVE_MODULE_PATHS is the approved science baseline at science_commit.
# This separate complete inventory is the code Python executes and is bound to
# execution_route_commit, so neither evidence hash is ambiguous.
GATE_B_V2_RUNTIME_MODULE_PATHS = (
    ("opponents", "src/opponents/__init__.py"),
    ("opponents._canonical", "src/opponents/_canonical.py"),
    ("opponents.catalog", "src/opponents/catalog.py"),
    ("opponents.equilibrium", "src/opponents/equilibrium.py"),
    ("opponents.ground_truth", "src/opponents/ground_truth.py"),
    ("opponents.model", "src/opponents/model.py"),
    ("opponents.synthesis", "src/opponents/synthesis.py"),
    ("phase6", "src/phase6/__init__.py"),
    ("phase6.calibration", "src/phase6/calibration.py"),
    ("phase6.contracts", "src/phase6/contracts.py"),
    ("phase6.exact_ev", "src/phase6/exact_ev.py"),
    ("phase6.gate_b_contracts", "src/phase6/gate_b_contracts.py"),
    ("phase6.gate_b_executor", "src/phase6/gate_b_executor.py"),
    ("phase6.gate_b_ledger", "src/phase6/gate_b_ledger.py"),
    ("phase6.gate_b_loader", "src/phase6/gate_b_loader.py"),
    ("phase6.gate_b_orchestrator", "src/phase6/gate_b_orchestrator.py"),
    ("phase6.gate_b_v2_cli", "src/phase6/gate_b_v2_cli.py"),
    ("phase6.gate_b_v2_route", "src/phase6/gate_b_v2_route.py"),
    ("phase6.p6_10", "src/phase6/p6_10.py"),
    ("phase6.p6_10_freeze", "src/phase6/p6_10_freeze.py"),
    ("phase6.p6_10b", "src/phase6/p6_10b.py"),
    ("phase6.p6_10b_freeze", "src/phase6/p6_10b_freeze.py"),
    ("phase6.p6_7", "src/phase6/p6_7.py"),
    ("phase6.production_inputs", "src/phase6/production_inputs.py"),
    ("phase6.training_backend", "src/phase6/training_backend.py"),
    ("phase6.training_cli", "src/phase6/training_cli.py"),
    ("phase6.training_runner", "src/phase6/training_runner.py"),
    ("phase6.validation_backend", "src/phase6/validation_backend.py"),
    ("phase6.validation_cli", "src/phase6/validation_cli.py"),
    ("phase6.validation_execution", "src/phase6/validation_execution.py"),
    ("phase6.validation_freeze", "src/phase6/validation_freeze.py"),
    ("phase6.validation_runner", "src/phase6/validation_runner.py"),
    ("poker_ai", "src/poker_ai/__init__.py"),
    ("poker_ai.actions", "src/poker_ai/actions.py"),
    ("poker_ai.baseline_strategy", "src/poker_ai/baseline_strategy.py"),
    ("poker_ai.decision", "src/poker_ai/decision.py"),
    ("poker_ai.exploit", "src/poker_ai/exploit.py"),
    ("poker_ai.hand_bucket", "src/poker_ai/hand_bucket.py"),
    ("poker_ai.leak", "src/poker_ai/leak.py"),
    ("poker_ai.mixer", "src/poker_ai/mixer.py"),
    ("poker_ai.observation", "src/poker_ai/observation.py"),
    ("poker_ai.opponent", "src/poker_ai/opponent.py"),
    ("poker_ai.posterior_bundle", "src/poker_ai/posterior_bundle.py"),
    ("poker_ai.scenario", "src/poker_ai/scenario.py"),
    ("poker_ai.session", "src/poker_ai/session.py"),
    ("poker_core", "src/poker_core/__init__.py"),
    ("poker_core.card", "src/poker_core/card.py"),
    ("poker_core.combo", "src/poker_core/combo.py"),
    ("poker_core.dpl_schema", "src/poker_core/dpl_schema.py"),
    ("poker_core.hand_evaluator", "src/poker_core/hand_evaluator.py"),
    ("poker_core.range_model", "src/poker_core/range_model.py"),
    ("poker_core.reason_ontology", "src/poker_core/reason_ontology.py"),
    ("poker_core.run_manifest", "src/poker_core/run_manifest.py"),
    ("poker_core.showdown_ev", "src/poker_core/showdown_ev.py"),
    ("poker_core.state_cluster", "src/poker_core/state_cluster.py"),
    ("poker_core.strategy_table", "src/poker_core/strategy_table.py"),
    ("poker_solver", "src/poker_solver/__init__.py"),
    ("poker_solver.best_response", "src/poker_solver/best_response.py"),
    ("poker_solver.cfr", "src/poker_solver/cfr.py"),
    ("poker_solver.cfr_metrics", "src/poker_solver/cfr_metrics.py"),
    ("poker_solver.cfr_plus", "src/poker_solver/cfr_plus.py"),
    ("poker_solver.evaluate", "src/poker_solver/evaluate.py"),
    ("poker_solver.game", "src/poker_solver/game.py"),
    ("poker_solver.nodelock", "src/poker_solver/nodelock.py"),
    ("poker_solver.reach", "src/poker_solver/reach.py"),
    ("poker_solver.river_solve", "src/poker_solver/river_solve.py"),
    ("poker_solver.river_tree", "src/poker_solver/river_tree.py"),
    ("poker_solver.strategy", "src/poker_solver/strategy.py"),
)
# Compatibility alias for callers that consumed the R3 constant.
GATE_B_V2_ROUTE_MODULE_PATHS = GATE_B_V2_RUNTIME_MODULE_PATHS
GATE_B_V2_ROUTE_ALLOWED_CHANGE_PATHS = (
    "src/phase6/gate_b_contracts.py",
    "src/phase6/gate_b_ledger.py",
    "src/phase6/gate_b_loader.py",
    "src/phase6/gate_b_v2_route.py",
    "src/phase6/gate_b_orchestrator.py",
    "src/phase6/gate_b_v2_cli.py",
    "README.md",
    "docs/gate_b_v2.md",
    "pyproject.toml",
    "tests/phase6/test_gate_b_cli.py",
    "tests/phase6/test_gate_b_contracts.py",
    "tests/phase6/test_gate_b_executor.py",
    "tests/phase6/test_gate_b_ledger.py",
    "tests/phase6/test_gate_b_loader.py",
    "tests/phase6/test_gate_b_orchestrator.py",
    "tests/phase6/test_gate_b_v2_cli.py",
    "tests/phase6/test_gate_b_v2_packaging.py",
    "tests/phase6/test_gate_b_v2_route.py",
)
_OPTIONAL_V2_ROUTE_MODULES = {"phase6.gate_b_v2_cli"}

_SHA_ZERO = "0" * 64
_MAX_CHUNK = 1048576
_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DECIMAL_RE = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
_WRITABLE_OUTPUTS = ("stdout", "stderr", "progress", "metrics", "log", "result")
_REQUEST_REF_FIELDS = {"absolute_path", "sha256"}
_ROOT_REF_FIELDS = {
    "absolute_path",
    "anchor_relative_path",
    "anchor_sha256",
    "file_id_hex",
    "identity_scheme",
    "root_role",
    "volume_id_hex",
}
_RETAINED_MESSAGES = {
    "retained acquisition argument mismatch",
    "retained acquisition role mismatch",
    "retained directory acquisition failed closed",
    "retained artifact acquisition failed closed",
    "retained artifact creation failed closed",
    "retained provenance mismatch",
    "retained directory is closed",
    "retained directory close failed closed",
    "retained loader bundle mismatch",
    "retained loader request failed closed",
}
_RETAINED_TOKEN = object()
_V2_PREPARED_TOKEN = object()
_V2_PREPARED_REGISTRY: dict[int, tuple[object, ...]] = {}
_RETAINED_ARTIFACT_SLOTS: Mapping[str, str | None] = MappingProxyType(
    {
        "readiness.spec": None,
        "readiness.approval_record": None,
        "readiness.signature_record": None,
        "readiness.output": "readiness_authorization",
        "request.spec": None,
        "request.batch_manifest": "batch_manifest",
        "request.readiness_authorization": "readiness_authorization",
        "request.human_approval_record": None,
        "request.human_signature_record": None,
        "request.execution_context": "execution_context",
        "request.ledger_root_anchor": "ledger_root_anchor",
        "request.quarantine_root_anchor": "quarantine_root_anchor",
        "request.output": "request",
        "one_shot.spec": None,
        "one_shot.loader_request": "request",
        "one_shot.batch_manifest": "batch_manifest",
        "one_shot.readiness_authorization": "readiness_authorization",
        "one_shot.human_approval_record": None,
        "one_shot.human_signature_record": None,
        "one_shot.execution_context": "execution_context",
        "one_shot.calibration_root_manifest": None,
        "one_shot.ledger_root_anchor": "ledger_root_anchor",
        "one_shot.quarantine_root_anchor": "quarantine_root_anchor",
        "compatibility.loader_request": "request",
        "compatibility.batch_manifest": "batch_manifest",
        "compatibility.readiness_authorization": "readiness_authorization",
        "compatibility.execution_context": "execution_context",
        "compatibility.ledger_root_anchor": "ledger_root_anchor",
        "compatibility.quarantine_root_anchor": "quarantine_root_anchor",
    }
)
_RETAINED_DIRECTORY_SLOTS: Mapping[str, str | None] = MappingProxyType(
    {
        "readiness.spec.parent": None,
        "readiness.approval_record.parent": None,
        "readiness.signature_record.parent": None,
        "readiness.output.parent": None,
        "request.spec.parent": None,
        "request.batch_manifest.parent": None,
        "request.readiness_authorization.parent": None,
        "request.human_approval_record.parent": None,
        "request.human_signature_record.parent": None,
        "request.execution_context.parent": None,
        "request.output.parent": None,
        "request.test_root": "test_root",
        "request.ledger_base": "ledger_base",
        "request.quarantine_base": "quarantine_base",
        "one_shot.spec.parent": None,
        "one_shot.loader_request.parent": None,
        "one_shot.batch_manifest.parent": None,
        "one_shot.readiness_authorization.parent": None,
        "one_shot.human_approval_record.parent": None,
        "one_shot.human_signature_record.parent": None,
        "one_shot.execution_context.parent": None,
        "one_shot.calibration_root_manifest.parent": None,
        "one_shot.test_root": "test_root",
        "one_shot.ledger_base": "ledger_base",
        "one_shot.quarantine_base": "quarantine_base",
        "one_shot.common_parent": None,
        "compatibility.loader_request.parent": None,
        "compatibility.batch_manifest.parent": None,
        "compatibility.readiness_authorization.parent": None,
        "compatibility.execution_context.parent": None,
        "compatibility.test_root": "test_root",
        "compatibility.ledger_base": "ledger_base",
        "compatibility.quarantine_base": "quarantine_base",
    }
)
_RETAINED_ANCHOR_PARENTS: Mapping[str, str] = MappingProxyType(
    {
        "request.ledger_root_anchor": "request.ledger_base",
        "request.quarantine_root_anchor": "request.quarantine_base",
        "one_shot.ledger_root_anchor": "one_shot.ledger_base",
        "one_shot.quarantine_root_anchor": "one_shot.quarantine_base",
        "compatibility.ledger_root_anchor": "compatibility.ledger_base",
        "compatibility.quarantine_root_anchor": "compatibility.quarantine_base",
    }
)
_RETAINED_BUNDLE_ROLE_FAMILIES: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "compatibility": (
            "compatibility.loader_request",
            "compatibility.batch_manifest",
            "compatibility.readiness_authorization",
            "compatibility.execution_context",
            "compatibility.ledger_root_anchor",
            "compatibility.quarantine_root_anchor",
            "compatibility.test_root",
            "compatibility.ledger_base",
            "compatibility.quarantine_base",
        ),
        "request": (
            "request.output",
            "request.batch_manifest",
            "request.readiness_authorization",
            "request.execution_context",
            "request.ledger_root_anchor",
            "request.quarantine_root_anchor",
            "request.test_root",
            "request.ledger_base",
            "request.quarantine_base",
        ),
        "one_shot": (
            "one_shot.loader_request",
            "one_shot.batch_manifest",
            "one_shot.readiness_authorization",
            "one_shot.execution_context",
            "one_shot.ledger_root_anchor",
            "one_shot.quarantine_root_anchor",
            "one_shot.test_root",
            "one_shot.ledger_base",
            "one_shot.quarantine_base",
        ),
    }
)
_RETAINED_DYNAMIC_ARTIFACT_ROLES: set[str] = set()
_RETAINED_DYNAMIC_DIRECTORY_ROLES: set[str] = set()


class GateBLoaderError(RuntimeError):
    """Base sanitized loader rejection."""


class GateBExecutionEnvironmentFailure(GateBLoaderError):
    """Actual execution environment failed its complete hard gate."""


class GateBTestInputFailure(GateBLoaderError):
    """Closed-world framed Test input could not be verified."""


class GateBExecutorFailure(GateBLoaderError):
    """Approved executor failed its callback contract."""


class GateBExecutorContractViolation(GateBExecutorFailure):
    """Executor attempted a forbidden capability operation."""


class GateBCapabilityClosed(GateBExecutorFailure):
    """A retained capability was used outside its callback lifetime."""


class GateBPartialEvidenceError(GateBLoaderError):
    """A storage or indeterminate failure retained incomplete evidence."""


def require_gate_b_v2_source_only_startup() -> None:
    """Require an immutable CPython startup that cannot address a project pyc."""
    try:
        import _testinternalcapi

        spec = _testinternalcapi.__spec__
        getter = _testinternalcapi.get_configs
        expected_origin = Path(sys.base_prefix) / "DLLs" / "_testinternalcapi.pyd"
        if os.name == "nt":
            trusted_provider = (
                type(spec.loader) is importlib.machinery.ExtensionFileLoader
                and Path(spec.origin).resolve() == expected_origin.resolve()
            )
        else:
            trusted_provider = (
                spec.loader is importlib.machinery.BuiltinImporter and spec.origin == "built-in"
            )
        if (
            type(_testinternalcapi) is not ModuleType
            or not trusted_provider
            or not inspect.isbuiltin(getter)
            or getter.__self__ is not _testinternalcapi
            or getter.__name__ != "get_configs"
        ):
            raise GateBExecutionEnvironmentFailure(
                "CPython startup configuration provider mismatch"
            )
        config = getter()["config"]
        executable = Path(sys.executable).resolve()
        startup_prefix = Path(config["pycache_prefix"]).resolve()
        source_root = Path(__file__).resolve().parents[1]
        python_path = tuple(
            Path(value).resolve()
            for value in os.environ.get("PYTHONPATH", "").split(os.pathsep)
            if value
        )
        executable_metadata = executable.lstat()
        from phase6.gate_b_v2_route import validate_gate_b_v2_fixed_local_path

        if os.name == "nt":
            validate_gate_b_v2_fixed_local_path(executable, "v2 source-only pycache barrier")
            validate_gate_b_v2_fixed_local_path(expected_origin, "CPython startup provider")
        if (
            config["write_bytecode"] != 0
            or config["safe_path"] != 1
            or config["user_site_directory"] != 0
            or sys.flags.dont_write_bytecode != 1
            or sys.flags.safe_path != 1
            or sys.flags.no_user_site != 1
            or not sys.dont_write_bytecode
            or sys.pycache_prefix is None
            or Path(sys.pycache_prefix).resolve() != startup_prefix
            or startup_prefix != executable
            or type(executable_metadata.st_nlink) is not int
            or executable_metadata.st_nlink != 1
            or not stat.S_ISREG(executable_metadata.st_mode)
            or stat.S_ISLNK(executable_metadata.st_mode)
            or _reparse(executable_metadata)
            or python_path != (source_root,)
            or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
            or os.environ.get("PYTHONNOUSERSITE") != "1"
        ):
            raise GateBExecutionEnvironmentFailure("v2 source-only startup interpreter mismatch")
        impossible_cache = Path(
            importlib.util.cache_from_source(
                str(Path(__file__).resolve()),
                optimization=None if sys.flags.optimize == 0 else str(sys.flags.optimize),
            )
        )
        if impossible_cache == executable or executable not in impossible_cache.parents:
            raise GateBExecutionEnvironmentFailure(
                "v2 source cache did not remain below the executable barrier"
            )
    except GateBExecutionEnvironmentFailure:
        raise
    except Exception as exc:
        raise GateBExecutionEnvironmentFailure(
            "v2 source-only startup verification failed closed"
        ) from exc


def _sanitized_api(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        error_type: type[Exception] | None = None
        error_message = ""
        try:
            return function(*args, **kwargs)
        except (GateBLoaderError, GateBLedgerError) as exc:
            error_type = type(exc)
            error_message = str(exc)
        except Exception:
            error_type = GateBLoaderError
            error_message = "Gate B operation failed closed"
        error = error_type(error_message)
        error.__cause__ = None
        error.__context__ = None
        error.__traceback__ = None
        raise error

    return wrapped


def _loader_request_sanitized_api(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except GateBLoaderError as exc:
            error = type(exc)(str(exc))
        except GateBLedgerError as exc:
            error = GateBLoaderError(str(exc))
        except Exception:
            error = GateBLoaderError("Gate B operation failed closed")
        error.__cause__ = None
        error.__context__ = None
        error.__traceback__ = None
        raise error

    return wrapped


def _retained_sanitized_api(default_message: str):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            message = default_message
            try:
                return function(*args, **kwargs)
            except TypeError:
                message = "retained acquisition argument mismatch"
            except Exception as exc:
                if type(exc) is GateBLoaderError and str(exc) in _RETAINED_MESSAGES:
                    message = str(exc)
            error = GateBLoaderError(message)
            error.__cause__ = None
            error.__context__ = None
            error.__traceback__ = None
            raise error

        return wrapped

    return decorate


class GateBApprovedExecutor(Protocol):
    """Exact callback boundary for one physically verified execution sampler."""

    @property
    def executor_id(self) -> str: ...

    @property
    def executor_sha256(self) -> str: ...

    def execute(
        self, input_capability: GateBInputCapability, quarantine_outputs: GateBOutputsCapability
    ) -> None: ...


def _fail(message: str) -> None:
    raise GateBLoaderError(message)


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON field")
        result[key] = value
    return result


def _strict_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda _value: _fail("non-finite JSON number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateBLoaderError(f"{label} is not strict canonical JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise GateBLoaderError(f"{label} is not canonical JSON") from exc
    if canonical != raw:
        _fail(f"{label} bytes are not canonical")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        _fail(f"{label} must be fraction-free UTC RFC 3339")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GateBLoaderError(f"{label} must be fraction-free UTC RFC 3339") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} must use canonical UTC calendar fields")
    return value


def _decimal_string(value: object, label: str) -> str:
    text = _ascii(value, label)
    if _DECIMAL_RE.fullmatch(text) is None or text in {"-0", "-0.0"}:
        _fail(f"{label} must be canonical fixed-point decimal text")
    return text


def _reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _windows_api_path(path: Path) -> str:
    text = str(path)
    if text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def _lstat(path: Path) -> os.stat_result:
    if os.name == "nt":
        return os.lstat(_windows_api_path(path))
    return path.lstat()


def _path_entry_present_no_follow(path: Path) -> bool:
    try:
        _lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GateBExecutionEnvironmentFailure(
            "repository lock presence cannot be verified"
        ) from exc
    return True


def _root_identity_payload(path: Path | str) -> dict[str, str]:
    candidate = Path(path).resolve()
    metadata = _lstat(candidate)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
        _fail("root identity target must be a physical directory")
    scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    return {
        "absolute_path": str(candidate),
        "file_id_hex": format(metadata.st_ino, "x"),
        "identity_scheme": scheme,
        "volume_id_hex": format(metadata.st_dev, "x"),
    }


def _required_posix_flag(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GateBLedgerError(f"required POSIX {name} is unavailable")
    return value


def _posix_openat(
    name: str,
    flags: int,
    mode: int,
    parent_descriptor: int,
) -> int:
    nofollow = _required_posix_flag(
        getattr(os, "O_NOFOLLOW", None),
        "O_NOFOLLOW",
    )
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise GateBLedgerError("required POSIX openat primitive is unavailable")
    return os.open(name, flags | nofollow, mode, dir_fd=parent_descriptor)


def _posix_open_directory(path: Path) -> int:
    directory_flag = _required_posix_flag(
        getattr(os, "O_DIRECTORY", None),
        "O_DIRECTORY",
    )
    nofollow = _required_posix_flag(
        getattr(os, "O_NOFOLLOW", None),
        "O_NOFOLLOW",
    )
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise GateBLedgerError("required POSIX openat primitive is unavailable")
    parts = path.parts
    if not path.is_absolute() or not parts:
        raise GateBLedgerError("POSIX pinned directory path must be absolute")
    descriptor = os.open(path.anchor, os.O_RDONLY | directory_flag)
    try:
        for part in parts[1:]:
            child = _posix_openat(
                part,
                os.O_RDONLY | directory_flag | nofollow,
                0o600,
                descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _posix_open_direct(path: Path, flags: int) -> int:
    parent = _posix_open_directory(path.parent)
    try:
        return _posix_openat(path.name, flags, 0o600, parent)
    finally:
        os.close(parent)


def _windows_create_file_descriptor(
    path: Path,
    *,
    access: int,
    creation: int,
    share: int,
    directory: bool = False,
) -> int:
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    attributes = 0x00200000 | (0x02000000 if directory else 0x00000080)
    handle = create_file(
        _windows_api_path(path),
        access,
        share,
        None,
        creation,
        attributes,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    flags = getattr(os, "O_BINARY", 0)
    flags |= os.O_RDONLY if access == 0x80000000 else os.O_RDWR
    try:
        return msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise


def _open_existing_descriptor(path: Path, *, writable: bool = False) -> int:
    if os.name == "nt":
        return _windows_create_file_descriptor(
            path,
            access=0xC0000000 if writable else 0x80000000,
            creation=3,
            share=1 if not writable else 0,
        )
    return _posix_open_direct(path, os.O_RDWR if writable else os.O_RDONLY)


def _open_directory_descriptor(path: Path) -> int:
    if os.name == "nt":
        return _windows_create_file_descriptor(
            path,
            access=0x80000000,
            creation=3,
            share=3,
            directory=True,
        )
    return _posix_open_directory(path)


def _windows_stream_names(path: Path) -> tuple[str, ...]:
    if os.name != "nt":
        return ("::$DATA",)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class StreamData(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", ctypes.c_wchar * 296),
        ]

    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(StreamData),
        ctypes.c_uint32,
    )
    find_first.restype = ctypes.c_void_p
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = (ctypes.c_void_p, ctypes.POINTER(StreamData))
    find_next.restype = ctypes.c_int
    find_close = kernel32.FindClose
    find_close.argtypes = (ctypes.c_void_p,)
    invalid = ctypes.c_void_p(-1).value
    data = StreamData()
    handle = find_first(_windows_api_path(path), 0, ctypes.byref(data), 0)
    if handle in (None, invalid):
        raise GateBLedgerError("required stream enumeration failed closed")
    names = [data.cStreamName]
    try:
        while find_next(handle, ctypes.byref(data)):
            names.append(data.cStreamName)
        if ctypes.get_last_error() not in {0, 38}:
            raise GateBLedgerError("required stream enumeration failed closed")
    finally:
        find_close(handle)
    return tuple(names)


def _verify_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = _lstat(path)
    except OSError as exc:
        raise GateBLedgerError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
        raise GateBLedgerError(f"{label} must be a physical directory")
    if os.name == "nt":
        descriptor = _open_directory_descriptor(path)
        try:
            opened = os.fstat(descriptor)
            from phase6.gate_b_v2_route import (
                validate_gate_b_v2_open_descriptor_fixed_local,
            )

            validate_gate_b_v2_open_descriptor_fixed_local(descriptor, path, label)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _reparse(opened)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise GateBLedgerError(f"{label} handle identity or reparse state mismatch")
    return metadata


def _verify_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = _lstat(path)
    except OSError as exc:
        raise GateBLedgerError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
        or metadata.st_nlink != 1
        or _windows_stream_names(path) != ("::$DATA",)
    ):
        raise GateBLedgerError(f"{label} must be a single-link physical regular file")
    return metadata


def _read_pinned(path: Path, label: str) -> bytes:
    before = _verify_regular(path, label)
    try:
        descriptor = _open_existing_descriptor(path)
        try:
            opened = os.fstat(descriptor)
            if os.name == "nt":
                from phase6.gate_b_v2_route import (
                    validate_gate_b_v2_open_descriptor_fixed_local,
                )

                validate_gate_b_v2_open_descriptor_fixed_local(descriptor, path, label)
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_ISLNK(opened.st_mode)
                or _reparse(opened)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise GateBLedgerError(f"{label} identity changed before read")
            chunks = []
            while True:
                chunk = os.read(descriptor, _MAX_CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise GateBLedgerError(f"{label} cannot be read") from exc
    after = _verify_regular(path, label)
    if (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        raise GateBLedgerError(f"{label} identity changed while reading")
    return b"".join(chunks)


def _closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} fields are not closed-world")
    return value


def _ascii(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        _fail(f"{label} must be nonempty printable ASCII")
    return value


def _sha(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < (1 << 63):
        _fail(f"{label} must be a positive integer")
    return value


def _six_digit_positive(value: object, label: str) -> int:
    result = _positive(value, label)
    if result > 999999:
        _fail(f"{label} exceeds the six-digit physical namespace")
    return result


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or any(ord(character) < 0x20 for character in value):
        _fail(f"{label} must be a nonempty path without control characters")
    text = value
    path = Path(text)
    if not path.is_absolute() or str(path.resolve(strict=False)) != text:
        _fail(f"{label} must use canonical absolute spelling")
    return path


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _path_ref(value: object, label: str) -> tuple[Path, str]:
    ref = _closed(value, _REQUEST_REF_FIELDS, label)
    return _absolute(ref["absolute_path"], f"{label} path"), _sha(ref["sha256"], f"{label} hash")


def _retained_embedded_absolute(value: object, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        _fail(f"{label} must be a nonempty path without control characters")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        _fail(f"{label} must use canonical absolute spelling")
    return path


def _retained_path_ref(value: object, label: str) -> tuple[Path, str]:
    ref = _closed(value, _REQUEST_REF_FIELDS, label)
    return _retained_embedded_absolute(
        ref["absolute_path"],
        f"{label} path",
    ), _sha(ref["sha256"], f"{label} hash")


def _validate_root_ref(value: object, role: str) -> tuple[dict[str, Any], Path]:
    ref = _closed(value, _ROOT_REF_FIELDS, f"{role} root reference")
    if ref["root_role"] != role:
        _fail("root reference role mismatch")
    path = _absolute(ref["absolute_path"], f"{role} root path")
    try:
        _verify_directory(path, f"{role} root")
        identity = _root_identity_payload(path)
    except (OSError, ValueError, GateBLedgerError) as exc:
        raise GateBLoaderError(f"{role} root identity cannot be verified") from exc
    for name in ("absolute_path", "file_id_hex", "identity_scheme", "volume_id_hex"):
        if ref[name] != identity[name]:
            _fail(f"{role} root physical identity mismatch")
    if role == "test_root":
        if ref["anchor_relative_path"] is not None or ref["anchor_sha256"] is not None:
            _fail("Test root anchor fields must be null")
    else:
        if ref["anchor_relative_path"] != ".gate-b-root-anchor.json":
            _fail("writable root anchor path mismatch")
        _sha(ref["anchor_sha256"], f"{role} anchor hash")
    return ref, path


def _retained_hex(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(character not in "0123456789abcdef" for character in value)
        or (len(value) > 1 and value[0] == "0")
    ):
        raise GateBLoaderError("retained acquisition argument mismatch")
    return value


def _retained_path(value: object) -> Path:
    if type(value) is not type(Path()):
        raise GateBLoaderError("retained acquisition argument mismatch")
    text = str(value)
    if (
        not text
        or not value.is_absolute()
        or ".." in value.parts
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in text)
    ):
        raise GateBLoaderError("retained acquisition argument mismatch")
    return value


def _retained_role_slot(logical_role: object, *, directory: bool) -> str | None:
    if type(logical_role) is not str:
        raise GateBLoaderError("retained acquisition argument mismatch")
    mapping = _RETAINED_DIRECTORY_SLOTS if directory else _RETAINED_ARTIFACT_SLOTS
    dynamic = _RETAINED_DYNAMIC_DIRECTORY_ROLES if directory else _RETAINED_DYNAMIC_ARTIFACT_ROLES
    if logical_role in mapping:
        return mapping[logical_role]
    if logical_role in dynamic:
        return None
    raise GateBLoaderError("retained acquisition role mismatch")


def _register_gate_b_retained_calibration_roles(relative_paths: tuple[str, ...]) -> None:
    expected = tuple(sorted(set(relative_paths)))
    if relative_paths != expected or not relative_paths:
        raise GateBLoaderError("retained acquisition role mismatch")
    artifact_roles: set[str] = set()
    directory_roles: set[str] = set()
    for relative_path in relative_paths:
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or "\\" in relative_path
            or relative_path.startswith("/")
            or any(part in {"", ".", ".."} for part in relative_path.split("/"))
        ):
            raise GateBLoaderError("retained acquisition role mismatch")
        role = f"one_shot.calibration_artifact:{relative_path}"
        artifact_roles.add(role)
        directory_roles.add(f"{role}.parent")
    _RETAINED_DYNAMIC_ARTIFACT_ROLES.clear()
    _RETAINED_DYNAMIC_ARTIFACT_ROLES.update(artifact_roles)
    _RETAINED_DYNAMIC_DIRECTORY_ROLES.clear()
    _RETAINED_DYNAMIC_DIRECTORY_ROLES.update(directory_roles)


def _clear_gate_b_retained_calibration_roles() -> None:
    _RETAINED_DYNAMIC_ARTIFACT_ROLES.clear()
    _RETAINED_DYNAMIC_DIRECTORY_ROLES.clear()


@dataclass(frozen=True, slots=True, init=False)
class GateBRetainedArtifactSnapshot:
    logical_role: str
    bundle_slot_role: str | None
    reference_path: Path
    raw: bytes = field(repr=False)
    sha256: str
    size_bytes: int
    volume_id_hex: str
    file_id_hex: str
    physical_identity: tuple[str, str]
    _parent: GateBRetainedDirectorySnapshot = field(repr=False, compare=False)
    _provenance_token: object = field(repr=False, compare=False)
    _provenance: tuple[object, ...] = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBRetainedArtifactSnapshot:
        if _token is not _RETAINED_TOKEN:
            raise TypeError("retained artifact construction is private")
        return object.__new__(cls)


@dataclass(frozen=True, slots=True, init=False)
class GateBRetainedDirectorySnapshot:
    logical_role: str
    bundle_slot_role: str | None
    reference_path: Path
    volume_id_hex: str
    file_id_hex: str
    identity_scheme: str
    physical_identity: tuple[str, str]
    _directory: GateBPinnedDirectory = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _provenance_token: object = field(repr=False, compare=False)
    _provenance: tuple[object, ...] = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBRetainedDirectorySnapshot:
        if _token is not _RETAINED_TOKEN:
            raise TypeError("retained directory construction is private")
        return object.__new__(cls)

    @_retained_sanitized_api("retained provenance mismatch")
    def verify_identity(self) -> None:
        directory = _validated_retained_directory(self)
        if self._closed:
            raise GateBLoaderError("retained directory is closed")
        directory.verify_identity()

    @_retained_sanitized_api("retained provenance mismatch")
    def direct_child_names(self) -> tuple[str, ...]:
        directory = _validated_retained_directory(self)
        if self._closed:
            raise GateBLoaderError("retained directory is closed")
        return directory.direct_child_names()

    @_retained_sanitized_api("retained directory close failed closed")
    def close(self) -> None:
        try:
            directory = _validated_retained_directory(self)
        except GateBLoaderError:
            candidate = getattr(self, "_directory", None)
            if type(candidate) is GateBPinnedDirectory:
                with suppress(Exception):
                    candidate.close()
            raise
        if self._closed:
            return
        directory.close()
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_provenance", _retained_directory_provenance(self))

    @_retained_sanitized_api("retained provenance mismatch")
    def __enter__(self) -> GateBRetainedDirectorySnapshot:
        _validated_retained_directory(self)
        if self._closed:
            raise GateBLoaderError("retained directory is closed")
        return self

    @_retained_sanitized_api("retained directory close failed closed")
    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True, init=False)
class GateBRetainedLoaderBundle:
    request: GateBRetainedArtifactSnapshot
    batch_manifest: GateBRetainedArtifactSnapshot
    readiness_authorization: GateBRetainedArtifactSnapshot
    execution_context: GateBRetainedArtifactSnapshot
    ledger_root_anchor: GateBRetainedArtifactSnapshot
    quarantine_root_anchor: GateBRetainedArtifactSnapshot
    test_root: GateBRetainedDirectorySnapshot
    ledger_base: GateBRetainedDirectorySnapshot
    quarantine_base: GateBRetainedDirectorySnapshot
    _provenance_token: object = field(repr=False, compare=False)
    _provenance: tuple[object, ...] = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBRetainedLoaderBundle:
        if _token is not _RETAINED_TOKEN:
            raise TypeError("retained loader bundle construction is private")
        return object.__new__(cls)


def _validated_retained_artifact(
    snapshot: GateBRetainedArtifactSnapshot,
) -> GateBRetainedArtifactSnapshot:
    if type(snapshot) is not GateBRetainedArtifactSnapshot:
        raise GateBLoaderError("retained provenance mismatch")
    try:
        current = (
            snapshot.logical_role,
            snapshot.bundle_slot_role,
            snapshot.reference_path,
            snapshot.raw,
            snapshot.sha256,
            snapshot.size_bytes,
            snapshot.volume_id_hex,
            snapshot.file_id_hex,
            snapshot.physical_identity,
            snapshot._parent,
        )
    except Exception:
        raise GateBLoaderError("retained provenance mismatch") from None
    if (
        snapshot._provenance_token is not _RETAINED_TOKEN
        or snapshot._provenance != current
        or type(snapshot.raw) is not bytes
        or sha256_bytes(snapshot.raw) != snapshot.sha256
        or len(snapshot.raw) != snapshot.size_bytes
        or snapshot.physical_identity != (snapshot.volume_id_hex, snapshot.file_id_hex)
        or _retained_role_slot(snapshot.logical_role, directory=False) != snapshot.bundle_slot_role
        or snapshot.reference_path.parent != snapshot._parent.reference_path
    ):
        raise GateBLoaderError("retained provenance mismatch")
    _validated_retained_directory(snapshot._parent)
    return snapshot


def _retained_directory_provenance(
    snapshot: GateBRetainedDirectorySnapshot,
) -> tuple[object, ...]:
    return (
        snapshot.logical_role,
        snapshot.bundle_slot_role,
        snapshot.reference_path,
        snapshot.volume_id_hex,
        snapshot.file_id_hex,
        snapshot.identity_scheme,
        snapshot.physical_identity,
        snapshot._directory,
        snapshot._closed,
    )


def _validated_retained_directory(
    snapshot: GateBRetainedDirectorySnapshot,
) -> GateBPinnedDirectory:
    if type(snapshot) is not GateBRetainedDirectorySnapshot:
        raise GateBLoaderError("retained provenance mismatch")
    try:
        current = _retained_directory_provenance(snapshot)
    except Exception:
        raise GateBLoaderError("retained provenance mismatch") from None
    if (
        snapshot._provenance_token is not _RETAINED_TOKEN
        or snapshot._provenance != current
        or type(snapshot._directory) is not GateBPinnedDirectory
        or type(snapshot._closed) is not bool
        or snapshot._closed is not snapshot._directory._closed
        or snapshot.physical_identity != (snapshot.volume_id_hex, snapshot.file_id_hex)
        or _retained_role_slot(snapshot.logical_role, directory=True) != snapshot.bundle_slot_role
    ):
        raise GateBLoaderError("retained provenance mismatch")
    return snapshot._directory


def _new_retained_artifact(
    directory: GateBRetainedDirectorySnapshot,
    *,
    logical_role: str,
    direct_child_name: str,
    pinned: GateBPinnedArtifact,
) -> GateBRetainedArtifactSnapshot:
    slot = _retained_role_slot(logical_role, directory=False)
    if type(pinned) is not GateBPinnedArtifact:
        raise GateBLoaderError("retained provenance mismatch")
    raw = bytes(pinned.raw)
    reference_path = directory.reference_path / direct_child_name
    snapshot = GateBRetainedArtifactSnapshot(_token=_RETAINED_TOKEN)
    values = {
        "logical_role": logical_role,
        "bundle_slot_role": slot,
        "reference_path": reference_path,
        "raw": raw,
        "sha256": pinned.sha256,
        "size_bytes": pinned.size_bytes,
        "volume_id_hex": pinned.volume_id_hex,
        "file_id_hex": pinned.file_id_hex,
        "physical_identity": pinned.physical_identity,
        "_parent": directory,
    }
    for name, value in values.items():
        object.__setattr__(snapshot, name, value)
    provenance = (
        snapshot.logical_role,
        snapshot.bundle_slot_role,
        snapshot.reference_path,
        snapshot.raw,
        snapshot.sha256,
        snapshot.size_bytes,
        snapshot.volume_id_hex,
        snapshot.file_id_hex,
        snapshot.physical_identity,
        snapshot._parent,
    )
    object.__setattr__(snapshot, "_provenance_token", _RETAINED_TOKEN)
    object.__setattr__(snapshot, "_provenance", provenance)
    return snapshot


@_retained_sanitized_api("retained directory acquisition failed closed")
def open_gate_b_retained_directory(
    *,
    logical_role: str,
    absolute_path: Path,
    expected_volume_id_hex: str,
    expected_file_id_hex: str,
) -> GateBRetainedDirectorySnapshot:
    slot = _retained_role_slot(logical_role, directory=True)
    path = _retained_path(absolute_path)
    volume_id = _retained_hex(expected_volume_id_hex)
    file_id = _retained_hex(expected_file_id_hex)
    directory = GateBPinnedDirectory.open(
        path,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    )
    snapshot = GateBRetainedDirectorySnapshot(_token=_RETAINED_TOKEN)
    values = {
        "logical_role": logical_role,
        "bundle_slot_role": slot,
        "reference_path": path,
        "volume_id_hex": volume_id,
        "file_id_hex": file_id,
        "identity_scheme": (
            "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
        ),
        "physical_identity": (volume_id, file_id),
        "_directory": directory,
        "_closed": False,
    }
    for name, value in values.items():
        object.__setattr__(snapshot, name, value)
    provenance = _retained_directory_provenance(snapshot)
    object.__setattr__(snapshot, "_provenance_token", _RETAINED_TOKEN)
    object.__setattr__(snapshot, "_provenance", provenance)
    return snapshot


def _expected_retained_parent_role(logical_role: str) -> str:
    if logical_role in _RETAINED_ANCHOR_PARENTS:
        return _RETAINED_ANCHOR_PARENTS[logical_role]
    return f"{logical_role}.parent"


@_retained_sanitized_api("retained artifact acquisition failed closed")
def read_gate_b_retained_artifact(
    directory: GateBRetainedDirectorySnapshot,
    *,
    logical_role: str,
    direct_child_name: str,
    expected_sha256: str,
    expected_size_bytes: int,
) -> GateBRetainedArtifactSnapshot:
    pinned_directory = _validated_retained_directory(directory)
    if directory._closed:
        raise GateBLoaderError("retained directory is closed")
    _retained_role_slot(logical_role, directory=False)
    if directory.logical_role != _expected_retained_parent_role(logical_role):
        raise GateBLoaderError("retained acquisition role mismatch")
    expected_hash = _sha(expected_sha256, "retained artifact expected hash")
    expected_size = _positive(expected_size_bytes, "retained artifact expected size")
    pinned = pinned_directory.read_regular(
        direct_child_name,
        expected_sha256=expected_hash,
        expected_size_bytes=expected_size,
    )
    return _new_retained_artifact(
        directory,
        logical_role=logical_role,
        direct_child_name=direct_child_name,
        pinned=pinned,
    )


@_retained_sanitized_api("retained artifact creation failed closed")
def create_gate_b_retained_artifact(
    directory: GateBRetainedDirectorySnapshot,
    *,
    logical_role: str,
    direct_child_name: str,
    raw: bytes,
) -> GateBRetainedArtifactSnapshot:
    pinned_directory = _validated_retained_directory(directory)
    if directory._closed:
        raise GateBLoaderError("retained directory is closed")
    _retained_role_slot(logical_role, directory=False)
    if logical_role not in {"readiness.output", "request.output"}:
        raise GateBLoaderError("retained acquisition role mismatch")
    if directory.logical_role != f"{logical_role}.parent":
        raise GateBLoaderError("retained acquisition role mismatch")
    if type(raw) is not bytes:
        raise GateBLoaderError("retained acquisition argument mismatch")
    pinned = pinned_directory.create_regular(direct_child_name, bytes(raw))
    return _new_retained_artifact(
        directory,
        logical_role=logical_role,
        direct_child_name=direct_child_name,
        pinned=pinned,
    )


def _validated_retained_bundle(bundle: GateBRetainedLoaderBundle) -> GateBRetainedLoaderBundle:
    if type(bundle) is not GateBRetainedLoaderBundle:
        raise GateBLoaderError("retained loader bundle mismatch")
    artifact_names = (
        "request",
        "batch_manifest",
        "readiness_authorization",
        "execution_context",
        "ledger_root_anchor",
        "quarantine_root_anchor",
    )
    directory_names = ("test_root", "ledger_base", "quarantine_base")
    artifacts = tuple(
        _validated_retained_artifact(getattr(bundle, name)) for name in artifact_names
    )
    directories = tuple(getattr(bundle, name) for name in directory_names)
    for directory in directories:
        _validated_retained_directory(directory)
    expected_slots = artifact_names
    if tuple(item.bundle_slot_role for item in artifacts) != expected_slots:
        raise GateBLoaderError("retained loader bundle mismatch")
    if tuple(item.bundle_slot_role for item in directories) != directory_names:
        raise GateBLoaderError("retained loader bundle mismatch")
    role_tuple = tuple(item.logical_role for item in (*artifacts, *directories))
    if role_tuple not in _RETAINED_BUNDLE_ROLE_FAMILIES.values():
        raise GateBLoaderError("retained loader bundle mismatch")
    if artifacts[4]._parent is not directories[1] or artifacts[5]._parent is not directories[2]:
        raise GateBLoaderError("retained loader bundle mismatch")
    if (
        len({id(item) for item in (*artifacts, *directories)}) != len(artifacts) + len(directories)
        or len({item.physical_identity for item in artifacts}) != len(artifacts)
        or len({item.physical_identity for item in directories}) != len(directories)
    ):
        raise GateBLoaderError("retained loader bundle mismatch")
    paths = tuple(item.reference_path for item in directories)
    if len({os.path.normcase(str(path)) for path in paths}) != len(paths):
        raise GateBLoaderError("retained loader bundle mismatch")
    for left in paths:
        for right in paths:
            if left != right and (left in right.parents or right in left.parents):
                raise GateBLoaderError("retained loader bundle mismatch")
    current = (*artifacts, *directories)
    if bundle._provenance_token is not _RETAINED_TOKEN or bundle._provenance != current:
        raise GateBLoaderError("retained loader bundle mismatch")
    return bundle


@_retained_sanitized_api("retained loader bundle mismatch")
def build_gate_b_retained_loader_bundle(
    *,
    request: GateBRetainedArtifactSnapshot,
    batch_manifest: GateBRetainedArtifactSnapshot,
    readiness_authorization: GateBRetainedArtifactSnapshot,
    execution_context: GateBRetainedArtifactSnapshot,
    ledger_root_anchor: GateBRetainedArtifactSnapshot,
    quarantine_root_anchor: GateBRetainedArtifactSnapshot,
    test_root: GateBRetainedDirectorySnapshot,
    ledger_base: GateBRetainedDirectorySnapshot,
    quarantine_base: GateBRetainedDirectorySnapshot,
) -> GateBRetainedLoaderBundle:
    values = (
        request,
        batch_manifest,
        readiness_authorization,
        execution_context,
        ledger_root_anchor,
        quarantine_root_anchor,
        test_root,
        ledger_base,
        quarantine_base,
    )
    bundle = GateBRetainedLoaderBundle(_token=_RETAINED_TOKEN)
    for name, value in zip(
        (
            "request",
            "batch_manifest",
            "readiness_authorization",
            "execution_context",
            "ledger_root_anchor",
            "quarantine_root_anchor",
            "test_root",
            "ledger_base",
            "quarantine_base",
        ),
        values,
        strict=True,
    ):
        object.__setattr__(bundle, name, value)
    object.__setattr__(bundle, "_provenance_token", _RETAINED_TOKEN)
    object.__setattr__(bundle, "_provenance", values)
    return _validated_retained_bundle(bundle)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GateBLoaderRequest:
    """Strict loader request with all external identities already joined."""

    request_sha256: str
    batch: GateBBatchManifest
    readiness: GateBReadinessAuthorization
    execution_context: GateBExecutionContext
    roots: Mapping[str, Mapping[str, Any]] = field(repr=False)
    actor_id: str
    actor_role: str
    attempt_ordinal: int
    _payload: Mapping[str, Any] = field(repr=False)
    _path: Path = field(repr=False)
    _v2_reservation_origin: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _v2_reservation_state: str = field(
        default="legacy",
        init=False,
        repr=False,
        compare=False,
    )
    _v2_reservation_authorization: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        return (
            "GateBLoaderRequest("
            f"test_batch_hash={self.batch.test_batch_hash!r}, "
            f"attempt_ordinal={self.attempt_ordinal!r}, actor_role='test_runner')"
        )

    def __copy__(self) -> GateBLoaderRequest:
        """Copy immutable request data while preserving external v2 derivation."""
        duplicate = object.__new__(type(self))
        for name in (
            "request_sha256",
            "batch",
            "readiness",
            "execution_context",
            "roots",
            "actor_id",
            "actor_role",
            "attempt_ordinal",
            "_payload",
            "_path",
            "_v2_reservation_origin",
            "_v2_reservation_state",
            "_v2_reservation_authorization",
        ):
            object.__setattr__(duplicate, name, object.__getattribute__(self, name))
        from phase6.gate_b_v2_route import _inherit_gate_b_v2_request_copy_provenance

        _inherit_gate_b_v2_request_copy_provenance(self, duplicate)
        return duplicate


@dataclass(frozen=True, slots=True, init=False)
class PreparedGateBV2CompatibilityPreflight(GateBV2CompatibilityObject):
    """Retained-root v2 boundary with no reservation, Test, or output capability."""

    projection_sha256: str
    loader_request_sha256: str
    roots: Mapping[str, Mapping[str, Any]]
    _chain: GateBV2CompatibilityTrustChain = field(repr=False, compare=False)
    _directories: Mapping[str, GateBPinnedDirectory] = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)
    _close_tombstone: tuple[object, ...] | None = field(repr=False, compare=False)

    def __new__(
        cls,
        *,
        _token: object | None = None,
    ) -> PreparedGateBV2CompatibilityPreflight:
        if _token is not _V2_PREPARED_TOKEN:
            raise TypeError("v2 prepared-object construction is private")
        return object.__new__(cls)

    def __repr__(self) -> str:
        state = "closed" if self._closed else "compatibility-qualified"
        return (
            "PreparedGateBV2CompatibilityPreflight("
            f"projection_sha256={self.projection_sha256!r}, state={state!r})"
        )

    @_sanitized_api
    def verify_identity(self) -> None:
        prepared = validate_gate_b_v2_compatibility_preflight(self)
        if prepared._closed:
            _fail("v2 compatibility preflight is closed")
        for role in ("ledger_base", "quarantine_base", "test_root"):
            root = _plain(prepared.roots[role])
            verify_gate_b_v2_pinned_directory(
                prepared._directories[role],
                serialization_profile=ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
                expected_volume_id_hex=root["volume_id_hex"],
                expected_file_id_hex=root["file_id_hex"],
            )
        verify_gate_b_v2_retained_root_topology(prepared._directories)

    @_sanitized_api
    def close(self) -> None:
        registered = _V2_PREPARED_REGISTRY.get(id(self))
        expected_tombstone = (
            self.projection_sha256,
            self.loader_request_sha256,
            _V2_PREPARED_TOKEN,
        )
        if registered is None:
            if (
                type(self) is PreparedGateBV2CompatibilityPreflight
                and self._closed
                and self._token is _V2_PREPARED_TOKEN
                and self._close_tombstone == expected_tombstone
                and self._chain is None
                and not self._directories
                and not self.roots
            ):
                return
            _fail("v2 compatibility prepared-object close provenance mismatch")
        expected_tombstone = (registered[1], registered[2], _V2_PREPARED_TOKEN)
        validation_error: BaseException | None = None
        try:
            validate_gate_b_v2_compatibility_preflight(self)
        except BaseException as exc:
            validation_error = exc
        first_error: BaseException | None = None
        registered_directories = dict(registered[5])
        for role in ("test_root", "quarantine_base", "ledger_base"):
            try:
                registered_directories[role].close()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        registered_chain = registered[4]
        registered_projection = registered_chain.projection
        gate_b_contracts_module._V2_TRUST_CHAIN_REGISTRY.pop(
            id(registered_chain),
            None,
        )
        gate_b_contracts_module._V2_PROJECTION_REGISTRY.pop(
            id(registered_projection),
            None,
        )
        object.__setattr__(registered_chain, "projection", None)
        object.__setattr__(registered_chain, "descriptor", MappingProxyType({}))
        object.__setattr__(registered_chain, "roots", MappingProxyType({}))
        object.__setattr__(registered_chain, "artifact_hashes", MappingProxyType({}))
        object.__setattr__(registered_chain, "request_payload", MappingProxyType({}))
        object.__setattr__(registered_chain, "_artifact_raws", MappingProxyType({}))
        object.__setattr__(registered_projection, "payload", MappingProxyType({}))
        object.__setattr__(registered_projection, "canonical_bytes", b"")
        object.__setattr__(self, "roots", MappingProxyType({}))
        object.__setattr__(self, "_chain", None)
        object.__setattr__(self, "_directories", MappingProxyType({}))
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_close_tombstone", expected_tombstone)
        _V2_PREPARED_REGISTRY.pop(id(self), None)
        if validation_error is not None:
            _fail("v2 compatibility prepared-object close provenance mismatch")
        if first_error is not None:
            raise GateBLoaderError("v2 retained-root close failed closed") from first_error

    def __enter__(self) -> PreparedGateBV2CompatibilityPreflight:
        validate_gate_b_v2_compatibility_preflight(self)
        if self._closed:
            _fail("v2 compatibility preflight is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def validate_gate_b_v2_compatibility_preflight(
    prepared: PreparedGateBV2CompatibilityPreflight,
) -> PreparedGateBV2CompatibilityPreflight:
    """Validate the prepared object's exact nominal type and private provenance."""
    if type(prepared) is not PreparedGateBV2CompatibilityPreflight:
        _fail("v2 compatibility prepared-object nominal type mismatch")
    registered = _V2_PREPARED_REGISTRY.get(id(prepared))
    try:
        current = (
            prepared,
            prepared.projection_sha256,
            prepared.loader_request_sha256,
            canonical_json_bytes(_plain(prepared.roots)),
            prepared._chain,
            tuple(
                (role, prepared._directories[role])
                for role in ("ledger_base", "quarantine_base", "test_root")
            ),
            prepared._closed,
            prepared._token,
            prepared._close_tombstone,
        )
    except Exception:
        _fail("v2 compatibility prepared-object provenance mismatch")
    if (
        registered is None
        or registered[0] is not prepared
        or current != registered
        or current[7] is not _V2_PREPARED_TOKEN
    ):
        _fail("v2 compatibility prepared-object provenance mismatch")
    validate_gate_b_v2_compatibility_trust_chain(prepared._chain)
    return prepared


@_sanitized_api
def prepare_gate_b_v2_compatibility_preflight(
    chain: GateBV2CompatibilityTrustChain,
) -> PreparedGateBV2CompatibilityPreflight:
    """Verify fixed-width retained roots and stop before every lifecycle action."""
    validated = validate_gate_b_v2_compatibility_trust_chain(chain)
    roots = _plain(validated.roots)
    descriptor = _plain(validated.descriptor)
    profile = descriptor["serialization_profile"]
    opened: dict[str, GateBPinnedDirectory] = {}
    try:
        for role in ("ledger_base", "quarantine_base", "test_root"):
            root = roots[role]
            opened[role] = open_gate_b_v2_pinned_directory(
                root["absolute_path"],
                serialization_profile=profile,
                expected_volume_id_hex=root["volume_id_hex"],
                expected_file_id_hex=root["file_id_hex"],
            )
        verify_gate_b_v2_retained_root_topology(opened)
        for role, artifact_name in (
            ("ledger_base", "ledger_root_anchor"),
            ("quarantine_base", "quarantine_root_anchor"),
        ):
            root = roots[role]
            if opened[role].direct_child_names() != (root["anchor_relative_path"],):
                _fail("v2 writable root must contain only its direct-child anchor")
            expected_raw = validated._artifact_raws[artifact_name]
            retained_anchor = opened[role].read_regular(
                root["anchor_relative_path"],
                expected_sha256=validated.artifact_hashes[artifact_name],
                expected_size_bytes=len(expected_raw),
            )
            if (
                retained_anchor.raw != expected_raw
                or retained_anchor.sha256 != validated.artifact_hashes[artifact_name]
            ):
                _fail("v2 retained root anchor stored-byte identity mismatch")
        prepared = PreparedGateBV2CompatibilityPreflight(_token=_V2_PREPARED_TOKEN)
        values = {
            "projection_sha256": validated.projection.sha256,
            "loader_request_sha256": validated.artifact_hashes["loader_request"],
            "roots": _freeze(roots),
            "_chain": validated,
            "_directories": MappingProxyType(dict(opened)),
            "_closed": False,
            "_token": _V2_PREPARED_TOKEN,
            "_close_tombstone": None,
        }
        for name, value in values.items():
            object.__setattr__(prepared, name, value)
        snapshot = (
            prepared,
            prepared.projection_sha256,
            prepared.loader_request_sha256,
            canonical_json_bytes(roots),
            validated,
            tuple((role, opened[role]) for role in ("ledger_base", "quarantine_base", "test_root")),
            False,
            _V2_PREPARED_TOKEN,
            None,
        )
        _V2_PREPARED_REGISTRY[id(prepared)] = snapshot
        return prepared
    except BaseException:
        for role in ("test_root", "quarantine_base", "ledger_base"):
            directory = opened.get(role)
            if directory is not None:
                with suppress(Exception):
                    directory.close()
        raise


def _parse_gate_b_loader_request_envelope(
    raw: bytes,
    expected_sha256: str,
) -> tuple[dict[str, Any], str]:
    if type(raw) is not bytes:
        _fail("loader request input must be bytes")
    expected = _sha(expected_sha256, "request hash")
    if sha256_bytes(raw) != expected:
        _fail("loader request stored-byte hash mismatch")
    value = _strict_canonical_object(bytes(raw), "Gate B loader request")
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "requested_at_utc",
            "batch_manifest",
            "readiness_authorization",
            "execution_context",
            "roots",
            "actor",
            "attempt_ordinal",
        },
        "loader request",
    )
    if (
        value["schema_version"] != LOADER_REQUEST_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_test_loader_request"
    ):
        _fail("loader request schema identity mismatch")
    try:
        _timestamp(value["requested_at_utc"], "loader request timestamp")
    except ValueError as exc:
        raise GateBLoaderError("loader request timestamp is invalid") from exc
    return value, expected


def _root_ref_from_payload(
    value: object,
    role: str,
    *,
    retained: bool,
) -> tuple[dict[str, Any], Path]:
    ref = _closed(value, _ROOT_REF_FIELDS, f"{role} root reference")
    if ref["root_role"] != role:
        _fail("root reference role mismatch")
    path = (
        _retained_embedded_absolute(ref["absolute_path"], f"{role} root path")
        if retained
        else _absolute(ref["absolute_path"], f"{role} root path")
    )
    expected_scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    if ref["identity_scheme"] != expected_scheme:
        _fail(f"{role} root identity scheme mismatch")
    for name in ("volume_id_hex", "file_id_hex"):
        value_hex = ref[name]
        if (
            not isinstance(value_hex, str)
            or not value_hex
            or any(character not in "0123456789abcdef" for character in value_hex)
            or (len(value_hex) > 1 and value_hex[0] == "0")
        ):
            _fail(f"{role} root physical identity mismatch")
    if role == "test_root":
        if ref["anchor_relative_path"] is not None or ref["anchor_sha256"] is not None:
            _fail("Test root anchor fields must be null")
    else:
        if ref["anchor_relative_path"] != ".gate-b-root-anchor.json":
            _fail("writable root anchor path mismatch")
        _sha(ref["anchor_sha256"], f"{role} anchor hash")
    return ref, path


def _join_gate_b_loader_request(
    value: dict[str, Any],
    *,
    request_sha256: str,
    request_path: Path,
    batch: GateBBatchManifest,
    readiness: GateBReadinessAuthorization,
    context: GateBExecutionContext,
    bundle: GateBRetainedLoaderBundle,
) -> GateBLoaderRequest:
    batch_path, batch_hash = _retained_path_ref(
        value["batch_manifest"],
        "batch manifest ref",
    )
    readiness_path, readiness_hash = _retained_path_ref(
        value["readiness_authorization"], "readiness authorization ref"
    )
    context_path, context_hash = _retained_path_ref(
        value["execution_context"],
        "execution context ref",
    )
    for artifact_path, artifact_hash, snapshot, label in (
        (batch_path, batch_hash, bundle.batch_manifest, "batch manifest"),
        (
            readiness_path,
            readiness_hash,
            bundle.readiness_authorization,
            "readiness authorization",
        ),
        (context_path, context_hash, bundle.execution_context, "execution context"),
    ):
        if artifact_path != snapshot.reference_path or artifact_hash != snapshot.sha256:
            _fail(f"{label} retained reference mismatch")

    roots_value = _closed(
        value["roots"], {"ledger_base", "quarantine_base", "test_root"}, "loader roots"
    )
    roots: dict[str, dict[str, Any]] = {}
    paths: dict[str, Path] = {}
    for role in ("ledger_base", "quarantine_base", "test_root"):
        ref, root_path = _root_ref_from_payload(
            roots_value[role],
            role,
            retained=True,
        )
        retained_root = getattr(bundle, role)
        if (
            root_path != retained_root.reference_path
            or ref["volume_id_hex"] != retained_root.volume_id_hex
            or ref["file_id_hex"] != retained_root.file_id_hex
            or ref["identity_scheme"] != retained_root.identity_scheme
        ):
            _fail(f"{role} root physical identity mismatch")
        roots[role] = ref
        paths[role] = root_path
    if len({os.path.normcase(str(root)) for root in paths.values()}) != 3:
        _fail("loader roots must be distinct")
    physical_root_ids = {
        (roots[role]["volume_id_hex"], roots[role]["file_id_hex"]) for role in roots
    }
    if len(physical_root_ids) != 3:
        _fail("loader roots must have distinct physical identities")
    for left_name, left in paths.items():
        for right_name, right in paths.items():
            if left_name != right_name and (left in right.parents or right in left.parents):
                _fail("loader roots must be non-nested")
    approval_hash = readiness.payload["approval_record_sha256"]
    for role, anchor_snapshot in (
        ("ledger_base", bundle.ledger_root_anchor),
        ("quarantine_base", bundle.quarantine_root_anchor),
    ):
        matching_root = getattr(bundle, role)
        anchor_path = paths[role] / str(roots[role]["anchor_relative_path"])
        if (
            anchor_snapshot.reference_path != anchor_path
            or anchor_snapshot.sha256 != roots[role]["anchor_sha256"]
            or anchor_snapshot._parent is not matching_root
        ):
            _fail(f"{role} root anchor stored-byte hash mismatch")
        anchor = load_gate_b_root_anchor_bytes(
            anchor_snapshot.raw,
            expected_sha256=anchor_snapshot.sha256,
            expected_root_role=role,
            expected_approval_record_sha256=approval_hash,
            reference_path=anchor_snapshot.reference_path,
        )
        if anchor.payload["root_role"] != role:
            _fail("writable root anchor role mismatch")

    actor = _closed(value["actor"], {"actor_id", "actor_role"}, "request actor")
    actor_id = _ascii(actor["actor_id"], "request actor ID")
    if (
        actor["actor_role"] != "test_runner"
        or actor_id != readiness.payload["authorized_runner_actor_id"]
    ):
        _fail("request actor differs from readiness authorization")
    attempt_ordinal = _six_digit_positive(value["attempt_ordinal"], "request attempt ordinal")
    if (
        batch.test_batch_hash != readiness.payload["test_batch_hash"]
        or context_hash != readiness.payload["approved_execution_context_sha256"]
        or batch.payload["git"]["commit_oid"] != readiness.payload["approved_implementation_commit"]
        or context.payload["expected_implementation_commit"]
        != readiness.payload["approved_implementation_commit"]
    ):
        _fail("batch, readiness, and execution-context commit join failed")
    roots_hash = build_gate_b_preapproval_root_identity_projection(roots_value).sha256
    if roots_hash != readiness.payload["approved_roots_sha256"]:
        _fail("preapproval root-identity projection hash mismatch")
    batch_runtime = batch.payload["runtime"]
    context_fingerprint = context.payload["runtime_fingerprint"]
    expected_runtime = {
        "python_implementation": context_fingerprint["python_implementation"],
        "python_version": context_fingerprint["python_version"],
        "machine": context_fingerprint["machine"],
        "os_name": context_fingerprint["system"],
        "os_release": context_fingerprint["release"],
    }
    for name, expected in expected_runtime.items():
        if batch_runtime[name] != expected:
            _fail("batch and context runtime projection mismatch")
    batch_lock = batch_runtime["dependency_lock"]
    context_lock = context.payload["dependency_lock"]
    if (
        batch_lock["sha256"] != context_lock["sha256"]
        or batch_lock["size_bytes"] != context_lock["size_bytes"]
    ):
        _fail("batch and context dependency-lock identity mismatch")
    return GateBLoaderRequest(
        request_sha256,
        batch,
        readiness,
        context,
        _freeze(roots),
        actor_id,
        actor["actor_role"],
        attempt_ordinal,
        _freeze(value),
        request_path,
    )


def _load_gate_b_loader_request_from_retained_impl(
    bundle: GateBRetainedLoaderBundle,
    *,
    expected_sha256: str,
    expected_readiness_authorization_sha256: str,
    expected_readiness_approval_record_sha256: str,
    expected_readiness_signature_record_sha256: str,
    parsed_envelope: tuple[dict[str, Any], str] | None = None,
) -> GateBLoaderRequest:
    retained = _validated_retained_bundle(bundle)
    envelope = (
        _parse_gate_b_loader_request_envelope(retained.request.raw, expected_sha256)
        if parsed_envelope is None
        else parsed_envelope
    )
    value, request_hash = envelope
    if (
        request_hash != retained.request.sha256
        or sha256_bytes(retained.request.raw) != request_hash
    ):
        _fail("loader request retained snapshot mismatch")
    readiness_hash = _sha(
        expected_readiness_authorization_sha256,
        "request readiness caller trust anchor",
    )
    if retained.readiness_authorization.sha256 != readiness_hash:
        _fail("request readiness hash differs from its caller trust anchor")

    retained.test_root.verify_identity()
    retained.ledger_base.verify_identity()
    retained.quarantine_base.verify_identity()

    batch = load_gate_b_batch_manifest_bytes(
        retained.batch_manifest.raw,
        expected_sha256=retained.batch_manifest.sha256,
        reference_path=retained.batch_manifest.reference_path,
    )
    readiness = load_gate_b_readiness_authorization_bytes(
        retained.readiness_authorization.raw,
        expected_sha256=readiness_hash,
        expected_approval_record_sha256=expected_readiness_approval_record_sha256,
        expected_signature_record_sha256=expected_readiness_signature_record_sha256,
        reference_path=retained.readiness_authorization.reference_path,
    )
    context = load_gate_b_execution_context_bytes(
        retained.execution_context.raw,
        expected_sha256=retained.execution_context.sha256,
        reference_path=retained.execution_context.reference_path,
    )
    return _join_gate_b_loader_request(
        value,
        request_sha256=request_hash,
        request_path=retained.request.reference_path,
        batch=batch,
        readiness=readiness,
        context=context,
        bundle=retained,
    )


@_retained_sanitized_api("retained loader request failed closed")
def load_gate_b_loader_request_from_retained(
    bundle: GateBRetainedLoaderBundle,
    *,
    expected_sha256: str,
    expected_readiness_authorization_sha256: str,
    expected_readiness_approval_record_sha256: str,
    expected_readiness_signature_record_sha256: str,
) -> GateBLoaderRequest:
    """Load a request exclusively from loader-provenance-bearing retained state."""
    return _load_gate_b_loader_request_from_retained_impl(
        bundle,
        expected_sha256=expected_sha256,
        expected_readiness_authorization_sha256=expected_readiness_authorization_sha256,
        expected_readiness_approval_record_sha256=expected_readiness_approval_record_sha256,
        expected_readiness_signature_record_sha256=expected_readiness_signature_record_sha256,
    )


def _canonicalize_loader_request_path(path: Path | str) -> Path:
    request_path = Path(path)
    return request_path.resolve(strict=False)


def _compatibility_read_artifact(
    path: Path,
    *,
    logical_role: str,
    expected_sha256: str,
    stack: ExitStack,
) -> GateBRetainedArtifactSnapshot:
    metadata = _verify_regular(path, "compatibility retained artifact")
    parent_identity = _root_identity_payload(path.parent)
    parent = stack.enter_context(
        open_gate_b_retained_directory(
            logical_role=f"{logical_role}.parent",
            absolute_path=Path(parent_identity["absolute_path"]),
            expected_volume_id_hex=parent_identity["volume_id_hex"],
            expected_file_id_hex=parent_identity["file_id_hex"],
        )
    )
    return read_gate_b_retained_artifact(
        parent,
        logical_role=logical_role,
        direct_child_name=path.name,
        expected_sha256=expected_sha256,
        expected_size_bytes=metadata.st_size,
    )


@_loader_request_sanitized_api
def load_gate_b_loader_request(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_readiness_authorization_sha256: str,
    expected_readiness_approval_record_sha256: str,
    expected_readiness_signature_record_sha256: str,
) -> GateBLoaderRequest:
    """Compatibility route with one named canonicalization and retained joins."""
    if is_gate_b_v2_compatibility_object(path):
        _fail("legacy loader request route rejects v2 compatibility objects")
    request_path = _canonicalize_loader_request_path(path)
    with ExitStack() as stack:
        request = _compatibility_read_artifact(
            request_path,
            logical_role="compatibility.loader_request",
            expected_sha256=expected_sha256,
            stack=stack,
        )
        envelope = _parse_gate_b_loader_request_envelope(request.raw, expected_sha256)
        value = envelope[0]
        batch_path, batch_hash = _path_ref(value["batch_manifest"], "batch manifest ref")
        readiness_path, readiness_hash = _path_ref(
            value["readiness_authorization"],
            "readiness authorization ref",
        )
        context_path, context_hash = _path_ref(
            value["execution_context"],
            "execution context ref",
        )
        batch = _compatibility_read_artifact(
            batch_path,
            logical_role="compatibility.batch_manifest",
            expected_sha256=batch_hash,
            stack=stack,
        )
        readiness = _compatibility_read_artifact(
            readiness_path,
            logical_role="compatibility.readiness_authorization",
            expected_sha256=readiness_hash,
            stack=stack,
        )
        context = _compatibility_read_artifact(
            context_path,
            logical_role="compatibility.execution_context",
            expected_sha256=context_hash,
            stack=stack,
        )

        roots_payload = _closed(
            value["roots"],
            {"ledger_base", "quarantine_base", "test_root"},
            "loader roots",
        )
        retained_roots: dict[str, GateBRetainedDirectorySnapshot] = {}
        parsed_roots: dict[str, dict[str, Any]] = {}
        root_paths: dict[str, Path] = {}
        for role in ("test_root", "ledger_base", "quarantine_base"):
            ref, root_path = _root_ref_from_payload(
                roots_payload[role],
                role,
                retained=False,
            )
            parsed_roots[role] = ref
            root_paths[role] = root_path
        anchor_sizes = {
            role: _verify_regular(
                root_paths[role] / str(parsed_roots[role]["anchor_relative_path"]),
                f"compatibility {role} root anchor",
            ).st_size
            for role in ("ledger_base", "quarantine_base")
        }
        for role, logical_role in (
            ("test_root", "compatibility.test_root"),
            ("ledger_base", "compatibility.ledger_base"),
            ("quarantine_base", "compatibility.quarantine_base"),
        ):
            ref = parsed_roots[role]
            try:
                retained_roots[role] = stack.enter_context(
                    open_gate_b_retained_directory(
                        logical_role=logical_role,
                        absolute_path=root_paths[role],
                        expected_volume_id_hex=ref["volume_id_hex"],
                        expected_file_id_hex=ref["file_id_hex"],
                    )
                )
            except GateBLoaderError:
                _fail(f"{role} root physical identity mismatch")
        ledger_anchor = read_gate_b_retained_artifact(
            retained_roots["ledger_base"],
            logical_role="compatibility.ledger_root_anchor",
            direct_child_name=str(parsed_roots["ledger_base"]["anchor_relative_path"]),
            expected_sha256=str(parsed_roots["ledger_base"]["anchor_sha256"]),
            expected_size_bytes=anchor_sizes["ledger_base"],
        )
        quarantine_anchor = read_gate_b_retained_artifact(
            retained_roots["quarantine_base"],
            logical_role="compatibility.quarantine_root_anchor",
            direct_child_name=str(parsed_roots["quarantine_base"]["anchor_relative_path"]),
            expected_sha256=str(parsed_roots["quarantine_base"]["anchor_sha256"]),
            expected_size_bytes=anchor_sizes["quarantine_base"],
        )
        bundle = build_gate_b_retained_loader_bundle(
            request=request,
            batch_manifest=batch,
            readiness_authorization=readiness,
            execution_context=context,
            ledger_root_anchor=ledger_anchor,
            quarantine_root_anchor=quarantine_anchor,
            test_root=retained_roots["test_root"],
            ledger_base=retained_roots["ledger_base"],
            quarantine_base=retained_roots["quarantine_base"],
        )
        return _load_gate_b_loader_request_from_retained_impl(
            bundle,
            expected_sha256=expected_sha256,
            expected_readiness_authorization_sha256=(expected_readiness_authorization_sha256),
            expected_readiness_approval_record_sha256=(expected_readiness_approval_record_sha256),
            expected_readiness_signature_record_sha256=(expected_readiness_signature_record_sha256),
            parsed_envelope=envelope,
        )


@dataclass(frozen=True, slots=True)
class GateBExecutionEvidence:
    """Path-free immutable evidence digests from the complete hard gate."""

    execution_context_sha256: str
    implementation_commit: str
    active_module_sources_sha256: str
    dependency_lock_sha256: str
    runtime_fingerprint_sha256: str
    execution_route_commit: str | None = None
    runtime_module_sources_sha256: str | None = None


def _execution_evidence_sha256(evidence: GateBExecutionEvidence) -> str:
    payload = {
        "execution_context_sha256": evidence.execution_context_sha256,
        "implementation_commit": evidence.implementation_commit,
        "active_module_sources_sha256": evidence.active_module_sources_sha256,
        "dependency_lock_sha256": evidence.dependency_lock_sha256,
        "runtime_fingerprint_sha256": evidence.runtime_fingerprint_sha256,
    }
    if evidence.execution_route_commit is not None:
        payload.update(
            {
                "execution_route_commit": evidence.execution_route_commit,
                "runtime_module_sources_sha256": evidence.runtime_module_sources_sha256,
            }
        )
    return sha256_bytes(canonical_json_bytes(payload))


def _git_command(root: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "--no-optional-locks",
        "-c",
        f"safe.directory={root.as_posix()}",
        "-C",
        str(root),
        *arguments,
    ]


def _run_git(root: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        completed = subprocess.run(
            _git_command(root, *arguments),
            capture_output=True,
            check=True,
            timeout=30,
            text=text,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateBExecutionEnvironmentFailure("repository evidence probe failed") from exc
    return completed.stdout


def _file_snapshot(path: Path) -> tuple[int, int, int, int, str]:
    metadata = path.lstat()
    try:
        raw = _read_pinned(path, "repository index")
    except GateBLedgerError as exc:
        raise GateBExecutionEnvironmentFailure(
            "repository index physical verification failed"
        ) from exc
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        sha256_bytes(raw),
    )


def _verify_helper_bindings() -> None:
    contracts_module = sys.modules.get("phase6.contracts")
    if contracts_module is None:
        raise GateBExecutionEnvironmentFailure("active contract module is unavailable")
    for module_name in (
        "phase6.gate_b_contracts",
        "phase6.gate_b_ledger",
        "phase6.gate_b_loader",
    ):
        module = sys.modules.get(module_name)
        if module is None:
            raise GateBExecutionEnvironmentFailure("active Gate B module is unavailable")
        for helper_name in ("canonical_json_bytes", "sha256_bytes"):
            helper = getattr(module, helper_name, None)
            contract_helper = getattr(contracts_module, helper_name, None)
            if (
                helper is not contract_helper
                or getattr(helper, "__module__", None) != "phase6.contracts"
            ):
                raise GateBExecutionEnvironmentFailure("canonical helper binding mismatch")


def _module_sources(root: Path, context: GateBExecutionContext) -> list[dict[str, str]]:
    expected_entries = context.payload["active_modules"]
    verified = []
    for expected, fixed in zip(expected_entries, ACTIVE_MODULE_PATHS, strict=True):
        module_name, relative_path = fixed
        module = sys.modules.get(module_name)
        if module is None or module.__name__ != module_name or module.__package__ != "phase6":
            raise GateBExecutionEnvironmentFailure("active module identity mismatch")
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None)
        if not isinstance(loader, importlib.machinery.SourceFileLoader):
            raise GateBExecutionEnvironmentFailure("active module loader is not source-only")
        expected_path = (root / relative_path).resolve()
        origin = Path(getattr(spec, "origin", "")).resolve()
        file_path = Path(getattr(module, "__file__", "")).resolve()
        if origin != expected_path or file_path != expected_path:
            raise GateBExecutionEnvironmentFailure("active module origin mismatch")
        metadata = expected_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise GateBExecutionEnvironmentFailure("active module source topology mismatch")
        try:
            raw = _read_pinned(expected_path, "active module source")
        except GateBLedgerError as exc:
            raise GateBExecutionEnvironmentFailure(
                "active module source physical verification failed"
            ) from exc
        blob = _run_git(
            root,
            "cat-file",
            "blob",
            f"{context.payload['expected_implementation_commit']}:{relative_path}",
            text=False,
        )
        source_hash = sha256_bytes(raw)
        if raw != blob or source_hash != expected["sha256"]:
            raise GateBExecutionEnvironmentFailure("active module source evidence mismatch")
        after = expected_path.lstat()
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise GateBExecutionEnvironmentFailure("active module source identity changed")
        verified.append(
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": source_hash,
            }
        )
    _verify_helper_bindings()
    return verified


def _commit_blob(root: Path, commit: str, relative_path: str) -> bytes:
    value = _run_git(root, "cat-file", "blob", f"{commit}:{relative_path}", text=False)
    if type(value) is not bytes:
        raise GateBExecutionEnvironmentFailure("Git blob probe returned invalid bytes")
    return value


def _verify_commit_object(root: Path, commit: str, label: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise GateBExecutionEnvironmentFailure(f"{label} commit identity is invalid")
    _run_git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    resolved = _run_git(root, "rev-parse", f"{commit}^{{commit}}").strip()
    if resolved != commit:
        raise GateBExecutionEnvironmentFailure(f"{label} is not the exact commit object")


def _verify_gate_b_v2_route_diff(
    root: Path,
    science_commit: str,
    route_commit: str,
) -> tuple[str, ...]:
    changed = tuple(
        line
        for line in _run_git(
            root,
            "diff",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            science_commit,
            route_commit,
            "--",
        ).splitlines()
        if line
    )
    allowed = set(GATE_B_V2_ROUTE_ALLOWED_CHANGE_PATHS)
    if (
        not changed
        or len(changed) != len(set(changed))
        or any(path not in allowed for path in changed)
    ):
        raise GateBExecutionEnvironmentFailure("execution route changed a forbidden source path")
    return changed


def _verify_source_parent_chain(root: Path, path: Path) -> None:
    if path == root or root not in path.parents:
        raise GateBExecutionEnvironmentFailure("route source escapes repository")
    relative = path.relative_to(root)
    current = root
    try:
        for part in relative.parts[:-1]:
            current = current / part
            _verify_directory(current, "route source parent")
    except GateBLedgerError as exc:
        raise GateBExecutionEnvironmentFailure("route source parent topology mismatch") from exc


def _verify_loaded_route_module(module_name: str, expected_path: Path) -> None:
    module = sys.modules.get(module_name)
    if module is None:
        if module_name in _OPTIONAL_V2_ROUTE_MODULES:
            return
        raise GateBExecutionEnvironmentFailure("active v2 route module is unavailable")
    expected_package = (
        module_name if expected_path.name == "__init__.py" else module_name.rpartition(".")[0]
    )
    if module.__name__ != module_name or module.__package__ != expected_package:
        raise GateBExecutionEnvironmentFailure("active v2 route module identity mismatch")
    spec = getattr(module, "__spec__", None)
    loader = getattr(spec, "loader", None)
    if type(module) is not ModuleType:
        raise GateBExecutionEnvironmentFailure("active v2 route module nominal type mismatch")
    if type(loader) is not importlib.machinery.SourceFileLoader:
        raise GateBExecutionEnvironmentFailure("active v2 route module loader is not source-only")
    expected = os.path.normcase(os.path.abspath(str(expected_path)))
    origin = os.path.normcase(os.path.abspath(str(getattr(spec, "origin", ""))))
    module_file = os.path.normcase(os.path.abspath(str(getattr(module, "__file__", ""))))
    if origin != expected or module_file != expected:
        raise GateBExecutionEnvironmentFailure("active v2 route module origin mismatch")


def _normalized_code_object(code: CodeType, expected_path: Path) -> CodeType:
    expected = os.path.normcase(os.path.abspath(str(expected_path)))
    filename = os.path.normcase(os.path.abspath(code.co_filename))
    if filename != expected:
        raise GateBExecutionEnvironmentFailure("executed code filename differs from source")
    constants = tuple(
        _normalized_code_object(value, expected_path) if type(value) is CodeType else value
        for value in code.co_consts
    )
    return code.replace(co_consts=constants, co_filename="<gate-b-repository-source>")


def _code_object_sha256(code: CodeType, expected_path: Path) -> str:
    def constant_payload(value: object) -> object:
        if type(value) is CodeType:
            return {"type": "code", "value": code_payload(value)}
        if value is None or type(value) in {bool, int, str}:
            return {"type": type(value).__name__, "value": value}
        if type(value) is bytes:
            return {"type": "bytes", "value": value.hex()}
        if type(value) is float:
            return {"type": "float", "value": value.hex()}
        if type(value) is complex:
            return {
                "type": "complex",
                "real": value.real.hex(),
                "imag": value.imag.hex(),
            }
        if type(value) is tuple:
            return {"type": "tuple", "value": [constant_payload(item) for item in value]}
        if type(value) is frozenset:
            values = [constant_payload(item) for item in value]
            values.sort(key=lambda item: canonical_json_bytes(item))
            return {"type": "frozenset", "value": values}
        if value is Ellipsis:
            return {"type": "ellipsis"}
        raise GateBExecutionEnvironmentFailure("code constant cannot be fingerprinted")

    def code_payload(value: CodeType) -> dict[str, object]:
        return {
            "argcount": value.co_argcount,
            "posonlyargcount": value.co_posonlyargcount,
            "kwonlyargcount": value.co_kwonlyargcount,
            "nlocals": value.co_nlocals,
            "stacksize": value.co_stacksize,
            "flags": value.co_flags,
            "code": value.co_code.hex(),
            "consts": [constant_payload(item) for item in value.co_consts],
            "names": list(value.co_names),
            "varnames": list(value.co_varnames),
            "filename": value.co_filename,
            "name": value.co_name,
            "qualname": value.co_qualname,
            "firstlineno": value.co_firstlineno,
            "linetable": value.co_linetable.hex(),
            "exceptiontable": value.co_exceptiontable.hex(),
            "freevars": list(value.co_freevars),
            "cellvars": list(value.co_cellvars),
        }

    try:
        normalized = _normalized_code_object(code, expected_path)
        return sha256_bytes(canonical_json_bytes(code_payload(normalized)))
    except GateBExecutionEnvironmentFailure:
        raise
    except Exception as exc:
        raise GateBExecutionEnvironmentFailure("executed code cannot be fingerprinted") from exc


def _nested_code_hashes(code: CodeType, expected_path: Path) -> set[str]:
    values = {_code_object_sha256(code, expected_path)}
    for constant in code.co_consts:
        if type(constant) is CodeType:
            values.update(_nested_code_hashes(constant, expected_path))
    return values


def _live_module_functions(
    module: ModuleType,
) -> tuple[tuple[type | None, str, FunctionType], ...]:
    found: dict[int, tuple[type | None, str, FunctionType]] = {}
    visited_classes: set[int] = set()

    def add(value: object, owner: type | None, binding_name: str) -> None:
        if type(value) is FunctionType:
            found[id(value)] = (owner, binding_name, value)
            return
        if isinstance(value, staticmethod | classmethod):
            add(value.__func__, owner, binding_name)
            return
        if isinstance(value, property):
            for accessor in (value.fget, value.fset, value.fdel):
                if accessor is not None:
                    add(accessor, owner, binding_name)
            return
        if isinstance(value, type) and value.__module__ == module.__name__:
            if id(value) in visited_classes:
                return
            visited_classes.add(id(value))
            for name, member in vars(value).items():
                add(member, value, name)

    for name, value in vars(module).items():
        if isinstance(value, FunctionType | type) and value.__module__ == module.__name__:
            add(value, None, name)
    return tuple(found.values())


_DATACLASS_GENERATED_METHODS = {
    "__delattr__",
    "__eq__",
    "__ge__",
    "__getstate__",
    "__gt__",
    "__hash__",
    "__init__",
    "__le__",
    "__lt__",
    "__repr__",
    "__setattr__",
    "__setstate__",
}
_PROTOCOL_GENERATED_METHODS = {"__init__", "__subclasshook__"}


def _source_code_hashes_by_qualname(
    code: CodeType,
    expected_path: Path,
) -> dict[str, set[str]]:
    values = {
        code.co_qualname: {_code_object_sha256(code, expected_path)},
    }
    for constant in code.co_consts:
        if type(constant) is CodeType:
            for qualname, hashes in _source_code_hashes_by_qualname(
                constant,
                expected_path,
            ).items():
                values.setdefault(qualname, set()).update(hashes)
    return values


def _verify_import_bindings(
    module: ModuleType,
    source_tree: ast.Module,
) -> dict[str, object]:
    expected_bindings: dict[str, object] = {}
    for node in source_tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_name = alias.name
                binding_name = alias.asname or imported_name.split(".", 1)[0]
                expected_name = imported_name if alias.asname else binding_name
                expected = sys.modules.get(expected_name)
                if (
                    type(expected) is not ModuleType
                    or vars(module).get(binding_name) is not expected
                ):
                    raise GateBExecutionEnvironmentFailure(
                        "live module import binding differs from verified source"
                    )
                expected_bindings[binding_name] = expected
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            relative_name = "." * node.level + (node.module or "")
            try:
                imported_name = importlib.util.resolve_name(relative_name, module.__package__)
            except (ImportError, ValueError) as exc:
                raise GateBExecutionEnvironmentFailure(
                    "project import binding cannot be resolved"
                ) from exc
            imported = sys.modules.get(imported_name)
            if type(imported) is not ModuleType:
                raise GateBExecutionEnvironmentFailure(
                    "imported module is unavailable during attestation"
                )
            for alias in node.names:
                if alias.name == "*":
                    raise GateBExecutionEnvironmentFailure(
                        "runtime modules may not use wildcard imports"
                    )
                binding_name = alias.asname or alias.name
                expected = getattr(imported, alias.name, None)
                if expected is None or vars(module).get(binding_name) is not expected:
                    raise GateBExecutionEnvironmentFailure(
                        "live imported symbol binding differs from verified source"
                    )
                expected_bindings[binding_name] = expected
    return expected_bindings


def _module_state_equal(observed: object, expected: object) -> bool:
    if type(expected) is object:
        return type(observed) is object
    if isinstance(expected, re.Pattern):
        return (
            isinstance(observed, re.Pattern)
            and observed.pattern == expected.pattern
            and observed.flags == expected.flags
        )
    if type(expected) is MappingProxyType:
        return type(observed) is MappingProxyType and _module_state_equal(
            dict(observed),
            dict(expected),
        )
    if type(expected) is dict:
        return (
            type(observed) is dict
            and tuple(observed) == tuple(expected)
            and all(_module_state_equal(observed[key], value) for key, value in expected.items())
        )
    if type(expected) in {tuple, list}:
        return (
            type(observed) is type(expected)
            and len(observed) == len(expected)
            and all(
                _module_state_equal(left, right)
                for left, right in zip(observed, expected, strict=True)
            )
        )
    if type(expected) in {set, frozenset}:
        return type(observed) is type(expected) and observed == expected
    if isinstance(expected, Path):
        return type(observed) is type(expected) and observed == expected
    if type(expected) is FunctionType:
        if type(observed) is not FunctionType:
            return False
        expected_source = Path(expected.__code__.co_filename)
        return (
            _code_object_sha256(observed.__code__, expected_source)
            == _code_object_sha256(expected.__code__, expected_source)
            and _module_state_equal(
                observed.__defaults__ or (),
                expected.__defaults__ or (),
            )
            and _module_state_equal(
                observed.__kwdefaults__ or {},
                expected.__kwdefaults__ or {},
            )
        )
    if isinstance(expected, type):
        return observed is expected
    if type(expected).__module__ in {"types", "typing", "typing_extensions"}:
        return type(observed) is type(expected) and repr(observed) == repr(expected)
    if type(expected).__module__ in {"_thread", "weakref"}:
        return type(observed) is type(expected)
    try:
        return type(observed) is type(expected) and bool(observed == expected)
    except Exception:
        return False


def _verify_module_assignment_state(
    module: ModuleType,
    source_tree: ast.Module,
    expected_path: Path,
    import_bindings: Mapping[str, object],
    compiler_flags: int,
) -> None:
    reference: dict[str, object] = {
        "__builtins__": builtins.__dict__,
        "__file__": str(expected_path),
        "__name__": module.__name__,
        "__package__": module.__package__,
        **import_bindings,
    }
    for node in source_tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            reference[node.name] = vars(module)[node.name]

    object_sentinels: list[object] = []
    for node in source_tree.body:
        targets: list[ast.expr]
        value_node: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value_node = node.value
        else:
            continue
        if value_node is None:
            continue
        try:
            expected = eval(
                compile(
                    ast.Expression(value_node),
                    str(expected_path),
                    "eval",
                    flags=compiler_flags,
                    dont_inherit=True,
                    optimize=sys.flags.optimize,
                ),
                reference,
            )
        except Exception as exc:
            raise GateBExecutionEnvironmentFailure(
                "verified module state cannot be reconstructed"
            ) from exc
        for target in targets:
            if isinstance(target, ast.Name):
                observed = vars(module).get(target.id, object())
                if not _module_state_equal(observed, expected):
                    raise GateBExecutionEnvironmentFailure(
                        f"live module state differs from verified source: {target.id}"
                    )
                reference[target.id] = expected
                if type(expected) is object:
                    object_sentinels.append(observed)
            else:
                raise GateBExecutionEnvironmentFailure(
                    "module assignment target cannot be attested"
                )
    if len({id(value) for value in object_sentinels}) != len(object_sentinels):
        raise GateBExecutionEnvironmentFailure("module sentinel bindings alias")


def _verify_source_function_defaults(
    module: ModuleType,
    source_tree: ast.Module,
    expected_path: Path,
    expected_code: Mapping[str, set[str]],
) -> None:
    def verify(
        function: object,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        expected_qualname: str,
    ) -> None:
        if isinstance(function, property):
            decorator_names = {
                decorator.attr
                for decorator in node.decorator_list
                if isinstance(decorator, ast.Attribute)
            }
            function = (
                function.fset
                if "setter" in decorator_names
                else function.fdel
                if "deleter" in decorator_names
                else function.fget
            )
        if isinstance(function, staticmethod | classmethod):
            function = function.__func__
        if function is not None:
            function = inspect.unwrap(function)
        if not isinstance(function, FunctionType):
            raise GateBExecutionEnvironmentFailure("source callable binding is missing")
        expected_hashes = expected_code.get(expected_qualname)
        if (
            not expected_hashes
            or function.__code__.co_qualname != expected_qualname
            or os.path.normcase(os.path.abspath(function.__code__.co_filename))
            != os.path.normcase(os.path.abspath(str(expected_path)))
            or _code_object_sha256(function.__code__, expected_path) not in expected_hashes
        ):
            raise GateBExecutionEnvironmentFailure(
                "source callable binding differs from its verified definition"
            )
        observed_defaults = function.__defaults__ or ()
        for offset, value_node in enumerate(reversed(node.args.defaults), 1):
            try:
                expected = ast.literal_eval(value_node)
            except (ValueError, TypeError):
                continue
            if len(observed_defaults) < offset:
                raise GateBExecutionEnvironmentFailure("source callable default is missing")
            observed = observed_defaults[-offset]
            if type(observed) is not type(expected) or observed != expected:
                raise GateBExecutionEnvironmentFailure(
                    "live function default differs from verified source"
                )
        observed_keywords = function.__kwdefaults__ or {}
        for argument, value_node in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            if value_node is None:
                continue
            try:
                expected = ast.literal_eval(value_node)
            except (ValueError, TypeError):
                continue
            observed = observed_keywords.get(argument.arg, object())
            if type(observed) is not type(expected) or observed != expected:
                raise GateBExecutionEnvironmentFailure(
                    "live keyword default differs from verified source"
                )

    for node in source_tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            verify(vars(module).get(node.name), node, node.name)
        elif isinstance(node, ast.ClassDef):
            owner = vars(module).get(node.name)
            if (
                not isinstance(owner, type)
                or owner.__module__ != module.__name__
                or owner.__qualname__ != node.name
            ):
                raise GateBExecutionEnvironmentFailure("source class binding is missing")
            for member in node.body:
                if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
                    verify(
                        vars(owner).get(member.name),
                        member,
                        f"{node.name}.{member.name}",
                    )


def _verify_executed_source_code(
    module_name: str,
    expected_path: Path,
    raw: bytes,
) -> str:
    """Join live functions and any timestamp-valid pyc to verified source bytes."""
    module = sys.modules.get(module_name)
    if type(module) is not ModuleType:
        raise GateBExecutionEnvironmentFailure("active module nominal type mismatch")
    spec = module.__spec__
    loader = spec.loader
    if type(loader) is not importlib.machinery.SourceFileLoader:
        raise GateBExecutionEnvironmentFailure("active module loader is not exact source loader")
    try:
        compiled = compile(
            raw,
            str(expected_path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
        source_tree = ast.parse(raw, filename=str(expected_path))
    except (SyntaxError, ValueError, TypeError) as exc:
        raise GateBExecutionEnvironmentFailure("verified source cannot be compiled") from exc
    expected_hash = _code_object_sha256(compiled, expected_path)
    loaded_code = loader.get_code(module_name)
    if (
        type(loaded_code) is not CodeType
        or _code_object_sha256(loaded_code, expected_path) != expected_hash
    ):
        raise GateBExecutionEnvironmentFailure("loader code differs from verified source")

    cached_text = getattr(module, "__cached__", None)
    if type(cached_text) is not str or not cached_text:
        raise GateBExecutionEnvironmentFailure("active source cache declaration is unavailable")
    optimization = None if sys.flags.optimize == 0 else str(sys.flags.optimize)
    expected_cached = importlib.util.cache_from_source(
        str(expected_path),
        optimization=optimization,
    )
    if os.path.normcase(os.path.abspath(cached_text)) != os.path.normcase(
        os.path.abspath(expected_cached)
    ):
        raise GateBExecutionEnvironmentFailure("active source cache path escaped repository")
    cached_path = Path(cached_text)
    if _path_entry_present_no_follow(cached_path):
        try:
            metadata = _lstat(cached_path)
            cached_raw = _read_pinned(cached_path, "active module bytecode cache")
            cached_code = marshal.loads(cached_raw[16:])
        except (OSError, ValueError, EOFError, TypeError, GateBLedgerError) as exc:
            raise GateBExecutionEnvironmentFailure("bytecode cache cannot be attested") from exc
        if (
            len(cached_raw) < 16
            or cached_raw[:4] != importlib.util.MAGIC_NUMBER
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _reparse(metadata)
            or metadata.st_nlink != 1
            or type(cached_code) is not CodeType
            or _code_object_sha256(cached_code, expected_path) != expected_hash
        ):
            raise GateBExecutionEnvironmentFailure("bytecode cache differs from verified source")

    expected_nested = _nested_code_hashes(compiled, expected_path)
    expected_code = _source_code_hashes_by_qualname(compiled, expected_path)
    for owner, binding_name, function in _live_module_functions(module):
        expected_binding = binding_name if owner is None else f"{owner.__qualname__}.{binding_name}"
        code_filename = os.path.normcase(os.path.abspath(function.__code__.co_filename))
        source_filename = os.path.normcase(os.path.abspath(str(expected_path)))
        if code_filename != source_filename:
            generated = owner is not None and (
                (
                    hasattr(owner, "__dataclass_fields__")
                    and binding_name in _DATACLASS_GENERATED_METHODS
                    and function.__code__.co_filename == "<string>"
                )
                or (
                    owner is not None
                    and hasattr(owner, "__dataclass_fields__")
                    and binding_name in {"__repr__", "__getstate__", "__setstate__"}
                    and Path(function.__code__.co_filename).name == "dataclasses.py"
                )
                or (
                    bool(getattr(owner, "_is_protocol", False))
                    and binding_name in _PROTOCOL_GENERATED_METHODS
                    and Path(function.__code__.co_filename).name == "typing.py"
                )
                or (
                    binding_name == "__hash__"
                    and any(base.__module__ == "pydantic.main" for base in owner.__mro__)
                    and Path(function.__code__.co_filename).name == "_model_construction.py"
                )
                or (
                    any(
                        base.__module__ == "enum" and base.__name__ == "Enum"
                        for base in owner.__mro__
                    )
                    and binding_name in {"_generate_next_value_", "__new__"}
                    and Path(function.__code__.co_filename).name == "enum.py"
                )
            )
            if expected_binding in expected_code or not generated:
                raise GateBExecutionEnvironmentFailure(
                    "live source callable was replaced by dynamic code"
                )
            continue
        if _code_object_sha256(function.__code__, expected_path) not in expected_nested:
            raise GateBExecutionEnvironmentFailure("live function differs from verified source")
        wrapped = getattr(function, "__wrapped__", None)
        if (
            type(wrapped) is FunctionType
            and _code_object_sha256(
                wrapped.__code__,
                expected_path,
            )
            not in expected_nested
        ):
            raise GateBExecutionEnvironmentFailure(
                "wrapped live function differs from verified source"
            )
        for cell in function.__closure__ or ():
            closed_value = cell.cell_contents
            if (
                type(closed_value) is FunctionType
                and closed_value.__module__ == module_name
                and _code_object_sha256(closed_value.__code__, expected_path) not in expected_nested
            ):
                raise GateBExecutionEnvironmentFailure(
                    "live function closure differs from verified source"
                )
    import_bindings = _verify_import_bindings(module, source_tree)
    _verify_source_function_defaults(
        module,
        source_tree,
        expected_path,
        expected_code,
    )
    _verify_module_assignment_state(
        module,
        source_tree,
        expected_path,
        import_bindings,
        compiled.co_flags,
    )
    return expected_hash


def _working_tree_source_matches_git_blob(raw: bytes, blob: bytes) -> bool:
    """Accept only Git's complete LF-to-CRLF Windows checkout transform."""
    if b"\r" in blob:
        return False
    if raw == blob:
        return True
    return raw == blob.replace(b"\n", b"\r\n")


def _v2_science_module_sources(
    root: Path,
    context: GateBExecutionContext,
    science_commit: str,
) -> list[dict[str, str]]:
    verified = []
    for expected, fixed in zip(context.payload["active_modules"], ACTIVE_MODULE_PATHS, strict=True):
        module_name, relative_path = fixed
        blob = _commit_blob(root, science_commit, relative_path)
        source_hash = sha256_bytes(blob)
        if (
            expected["module_name"] != module_name
            or expected["repository_relative_path"] != relative_path
            or expected["sha256"] != source_hash
        ):
            raise GateBExecutionEnvironmentFailure("science-module commit evidence mismatch")
        verified.append(
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": source_hash,
            }
        )
    return verified


def _v2_runtime_module_sources(root: Path, route_commit: str) -> list[dict[str, str]]:
    verified = []
    identities: set[tuple[int, int]] = set()
    for module_name, relative_path in GATE_B_V2_RUNTIME_MODULE_PATHS:
        expected_path = root / Path(relative_path)
        _verify_source_parent_chain(root, expected_path)
        _verify_loaded_route_module(module_name, expected_path)
        try:
            before = expected_path.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_nlink != 1
                or bool(getattr(before, "st_file_attributes", 0) & 0x400)
            ):
                raise GateBExecutionEnvironmentFailure("v2 route source topology mismatch")
            raw = _read_pinned(expected_path, "v2 route module source")
            after = expected_path.lstat()
        except (OSError, GateBLedgerError) as exc:
            raise GateBExecutionEnvironmentFailure(
                "v2 route source physical verification failed"
            ) from exc
        identity = (before.st_dev, before.st_ino)
        if identity in identities:
            raise GateBExecutionEnvironmentFailure("v2 route source physical alias")
        identities.add(identity)
        blob = _commit_blob(root, route_commit, relative_path)
        source_hash = sha256_bytes(blob)
        if not _working_tree_source_matches_git_blob(raw, blob) or (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise GateBExecutionEnvironmentFailure("v2 route source commit evidence mismatch")
        if sys.modules.get(module_name) is not None:
            _verify_executed_source_code(module_name, expected_path, raw)
        verified.append(
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": source_hash,
            }
        )
    _verify_helper_bindings()
    return verified


def _v2_route_module_sources(root: Path, route_commit: str) -> list[dict[str, str]]:
    """Compatibility name for the complete execution-commit inventory."""
    return _v2_runtime_module_sources(root, route_commit)


def _runtime_fingerprint() -> dict[str, str]:
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_compiler": platform.python_compiler(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }


def _normalize_distribution_name(value: str) -> str:
    import re

    return re.sub(r"[-_.]+", "-", value).lower()


def _installed_distributions(local_project: str) -> list[dict[str, str]]:
    local_name = _normalize_distribution_name(local_project)
    purelib = Path(sysconfig.get_path("purelib")).resolve()
    values = []
    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise GateBExecutionEnvironmentFailure("installed distribution lacks a name")
        name = _normalize_distribution_name(raw_name)
        if name != local_name:
            if Path(distribution.locate_file("")).resolve() != purelib:
                raise GateBExecutionEnvironmentFailure(
                    "installed distribution escaped the locked site-packages directory"
                )
            values.append({"name": name, "version": distribution.version})
    values.sort(key=lambda item: item["name"])
    if len(values) != len({item["name"] for item in values}):
        raise GateBExecutionEnvironmentFailure("installed distribution inventory is duplicated")
    return values


def _canonical_repository_relative_path(value: object, label: str) -> Path:
    text = _ascii(value, label)
    parts = text.split("/")
    if (
        "\\" in text
        or ":" in text
        or "://" in text
        or text.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or "/".join(parts) != text
    ):
        raise GateBExecutionEnvironmentFailure("locked repository-relative path is not canonical")
    return Path(*parts)


def _locked_dependency_path(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise GateBExecutionEnvironmentFailure(f"{label} is invalid")
    candidate = Path(value)
    if candidate.is_absolute():
        if ".." in candidate.parts or str(candidate) != os.path.abspath(value):
            raise GateBExecutionEnvironmentFailure(f"{label} is not canonical absolute")
        return candidate
    relative = _canonical_repository_relative_path(value, label)
    target = (root / relative).resolve()
    if root not in target.parents:
        raise GateBExecutionEnvironmentFailure("locked path escapes repository")
    return target


def _verify_dependency_lock_unchecked(root: Path, context: GateBExecutionContext) -> str:
    lock_ref = context.payload["dependency_lock"]
    path = Path(lock_ref["absolute_path"])
    if os.name == "nt":
        from phase6.gate_b_v2_route import validate_gate_b_v2_fixed_local_path

        validate_gate_b_v2_fixed_local_path(path, "dependency lock")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise GateBExecutionEnvironmentFailure("dependency lock topology mismatch")
    try:
        raw = _read_pinned(path, "dependency lock")
    except GateBLedgerError as exc:
        raise GateBExecutionEnvironmentFailure(
            "dependency lock physical verification failed"
        ) from exc
    if len(raw) != lock_ref["size_bytes"] or sha256_bytes(raw) != lock_ref["sha256"]:
        raise GateBExecutionEnvironmentFailure("dependency lock bytes mismatch")
    lock = _strict_canonical_object(raw, "dependency lock")
    _closed(
        lock,
        {"schema_version", "lock_scope", "distributions", "project", "python"},
        "dependency lock",
    )
    if (
        lock["schema_version"] != DEPENDENCY_LOCK_SCHEMA_VERSION
        or lock["lock_scope"] != "complete-installed-environment-snapshot"
    ):
        raise GateBExecutionEnvironmentFailure("dependency lock schema mismatch")
    project = _closed(
        lock["project"], {"git_commit", "name", "repository_path", "source", "version"}, "project"
    )
    if (
        project["source"] != "repository"
        or project["repository_path"] != "."
        or project["git_commit"] != context.payload["expected_implementation_commit"]
    ):
        raise GateBExecutionEnvironmentFailure("locked project provenance mismatch")
    distributions = lock["distributions"]
    if not isinstance(distributions, list):
        raise GateBExecutionEnvironmentFailure("locked distribution inventory is invalid")
    for entry in distributions:
        _closed(entry, {"name", "version"}, "locked distribution")
        _ascii(entry["name"], "locked distribution name")
        _ascii(entry["version"], "locked distribution version")
    python = _closed(
        lock["python"],
        {
            "base_executable_path",
            "base_executable_sha256",
            "compiler",
            "implementation",
            "platform",
            "pyvenv_cfg_path",
            "pyvenv_cfg_sha256",
            "site_packages_path",
            "venv_executable_path",
            "venv_executable_sha256",
            "version",
        },
        "locked Python",
    )
    path_fields = ("pyvenv_cfg_path", "site_packages_path", "venv_executable_path")
    resolved = {}
    for name in path_fields:
        resolved[name] = _locked_dependency_path(root, python[name], f"locked {name}")
    base_executable_text = python["base_executable_path"]
    if not isinstance(base_executable_text, str) or not base_executable_text:
        raise GateBExecutionEnvironmentFailure("locked base executable path is invalid")
    locked_base_executable = Path(base_executable_text)
    if not locked_base_executable.is_absolute() or str(locked_base_executable) != os.path.abspath(
        base_executable_text
    ):
        raise GateBExecutionEnvironmentFailure("locked base executable path is not canonical")
    # Validate every storage target, including the external base executable,
    # before the first executable/config artifact read.  In particular this
    # rejects UNC/device/ADS paths and a non-fixed nested mount under C:\\.
    active_paths = {
        "venv executable": Path(sys.executable),
        "base executable": Path(getattr(sys, "_base_executable", sys.executable)),
        "site-packages": Path(sysconfig.get_path("purelib")),
        "pyvenv configuration": Path(sys.prefix) / "pyvenv.cfg",
    }
    if os.name == "nt":
        for label, target in (
            ("locked venv executable", resolved["venv_executable_path"]),
            ("locked site-packages", resolved["site_packages_path"]),
            ("locked pyvenv configuration", resolved["pyvenv_cfg_path"]),
            ("locked base executable", locked_base_executable),
            *((f"active {label}", target) for label, target in active_paths.items()),
        ):
            validate_gate_b_v2_fixed_local_path(target, label)
    executable = active_paths["venv executable"].resolve()
    base_executable = active_paths["base executable"].resolve()
    purelib = active_paths["site-packages"].resolve()
    pyvenv = active_paths["pyvenv configuration"].resolve()
    locked_base_executable = locked_base_executable.resolve()
    if (
        executable != resolved["venv_executable_path"]
        or purelib != resolved["site_packages_path"]
        or pyvenv != resolved["pyvenv_cfg_path"]
        or base_executable != locked_base_executable
    ):
        raise GateBExecutionEnvironmentFailure("active Python path topology drifted")
    project_name = _ascii(project["name"], "locked project name")
    project_version = _ascii(project["version"], "locked project version")
    try:
        project_metadata = tomllib.loads(
            _commit_blob(root, project["git_commit"], "pyproject.toml").decode("utf-8")
        )["project"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise GateBExecutionEnvironmentFailure(
            "locked project metadata cannot be verified"
        ) from exc
    if (
        type(project_metadata) is not dict
        or project_metadata.get("name") != project_name
        or project_metadata.get("version") != project_version
    ):
        raise GateBExecutionEnvironmentFailure("locked project metadata mismatch")
    if distributions != _installed_distributions(project["name"]):
        raise GateBExecutionEnvironmentFailure("installed distribution inventory drifted")
    try:
        executable_hash = sha256_bytes(_read_pinned(executable, "venv executable"))
        base_executable_hash = sha256_bytes(_read_pinned(base_executable, "base executable"))
        pyvenv_hash = sha256_bytes(_read_pinned(pyvenv, "pyvenv configuration"))
        _verify_directory(purelib, "site-packages directory")
    except GateBLedgerError as exc:
        raise GateBExecutionEnvironmentFailure(
            "active Python topology verification failed"
        ) from exc
    if (
        executable_hash != python["venv_executable_sha256"]
        or base_executable_hash != python["base_executable_sha256"]
        or pyvenv_hash != python["pyvenv_cfg_sha256"]
        or python["compiler"] != platform.python_compiler()
        or python["implementation"] != platform.python_implementation()
        or python["platform"] != platform.platform()
        or python["version"] != platform.python_version()
    ):
        raise GateBExecutionEnvironmentFailure("active Python environment drifted")
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise GateBExecutionEnvironmentFailure("dependency lock identity changed")
    return sha256_bytes(raw)


def _verify_dependency_lock(root: Path, context: GateBExecutionContext) -> str:
    try:
        return _verify_dependency_lock_unchecked(root, context)
    except GateBExecutionEnvironmentFailure:
        raise
    except BaseException as exc:
        raise GateBExecutionEnvironmentFailure("dependency lock verification failed") from exc


def gate_b_v2_route_attestation_sha256(science_commit: str, route_commit: str) -> str:
    """Hash the external two-commit route declaration without self-reference."""
    if (
        type(science_commit) is not str
        or re.fullmatch(r"[0-9a-f]{40}", science_commit) is None
        or type(route_commit) is not str
        or re.fullmatch(r"[0-9a-f]{40}", route_commit) is None
        or route_commit == science_commit
    ):
        raise GateBExecutionEnvironmentFailure("v2 route commit declaration mismatch")
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "phase6-gate-b-v2-runtime-attestation-v2",
                "science_commit": science_commit,
                "execution_route_commit": route_commit,
                "science_baseline_modules": [
                    {
                        "module_name": module_name,
                        "repository_relative_path": relative_path,
                        "reported_hash": "active_module_sources_sha256",
                    }
                    for module_name, relative_path in ACTIVE_MODULE_PATHS
                ],
                "runtime_modules": [
                    {
                        "module_name": module_name,
                        "repository_relative_path": relative_path,
                        "source_commit": "execution_route_commit",
                    }
                    for module_name, relative_path in GATE_B_V2_RUNTIME_MODULE_PATHS
                ],
                "allowed_change_paths": list(GATE_B_V2_ROUTE_ALLOWED_CHANGE_PATHS),
            }
        )
    )


def _verify_gate_b_v2_execution_environment_unchecked(
    request: GateBLoaderRequest,
    context: GateBExecutionContext,
    *,
    science_commit: str,
    execution_route_commit: str,
) -> tuple[GateBExecutionEvidence, str]:
    """Verify the approved science object and the active route object separately."""
    require_gate_b_v2_source_only_startup()
    if context is not request.execution_context:
        raise GateBExecutionEnvironmentFailure("execution context object mismatch")
    if context.payload["expected_implementation_commit"] != science_commit:
        raise GateBExecutionEnvironmentFailure("science commit declaration mismatch")
    attestation_sha256 = gate_b_v2_route_attestation_sha256(
        science_commit,
        execution_route_commit,
    )
    repository_ref = context.payload["repository_root"]
    root = Path(repository_ref["absolute_path"])
    if _root_identity_payload(root) != _plain(repository_ref):
        raise GateBExecutionEnvironmentFailure("repository physical identity mismatch")
    git_directory = _run_git(root, "rev-parse", "--git-dir")
    index_path = Path(_run_git(root, "rev-parse", "--git-path", "index").strip())
    if not index_path.is_absolute():
        index_path = root / index_path
    before_index = _file_snapshot(index_path)
    _verify_commit_object(root, science_commit, "science")
    _verify_commit_object(root, execution_route_commit, "execution route")
    _run_git(root, "merge-base", "--is-ancestor", science_commit, execution_route_commit)
    _verify_gate_b_v2_route_diff(root, science_commit, execution_route_commit)
    head = _run_git(root, "rev-parse", "HEAD").strip()
    dirty = _run_git(root, "status", "--porcelain=v1", "--untracked-files=all").strip()
    staged = _run_git(root, "diff", "--cached", "--name-only").strip()
    git_dir_path = Path(git_directory.strip())
    if not git_dir_path.is_absolute():
        git_dir_path = root / git_dir_path
    if (
        head != execution_route_commit
        or dirty
        or staged
        or _path_entry_present_no_follow(git_dir_path / "index.lock")
    ):
        raise GateBExecutionEnvironmentFailure("v2 route repository state drifted")
    science_modules = _v2_science_module_sources(root, context, science_commit)
    runtime_modules = _v2_runtime_module_sources(root, execution_route_commit)
    runtime = _runtime_fingerprint()
    if runtime != _plain(context.payload["runtime_fingerprint"]):
        raise GateBExecutionEnvironmentFailure("runtime fingerprint drifted")
    dependency_hash = _verify_dependency_lock(root, context)
    if _file_snapshot(index_path) != before_index:
        raise GateBExecutionEnvironmentFailure("repository index changed during read-only probe")
    return (
        GateBExecutionEvidence(
            context.sha256,
            science_commit,
            sha256_bytes(canonical_json_bytes(science_modules)),
            dependency_hash,
            sha256_bytes(canonical_json_bytes(runtime)),
            execution_route_commit,
            sha256_bytes(canonical_json_bytes(runtime_modules)),
        ),
        attestation_sha256,
    )


@_sanitized_api
def verify_gate_b_v2_execution_environment(
    request: GateBLoaderRequest,
    context: GateBExecutionContext,
    *,
    science_commit: str,
    execution_route_commit: str,
) -> tuple[GateBExecutionEvidence, str]:
    """Fail closed unless both Git commits and every active route source bind."""
    try:
        return _verify_gate_b_v2_execution_environment_unchecked(
            request,
            context,
            science_commit=science_commit,
            execution_route_commit=execution_route_commit,
        )
    except GateBExecutionEnvironmentFailure:
        raise
    except BaseException as exc:
        raise GateBExecutionEnvironmentFailure(
            "v2 execution environment verification failed closed"
        ) from exc


def _verify_gate_b_execution_environment_unchecked(
    request: GateBLoaderRequest, context: GateBExecutionContext
) -> GateBExecutionEvidence:
    """Verify current repository, code, runtime, and dependency evidence exactly."""
    if context is not request.execution_context:
        raise GateBExecutionEnvironmentFailure("execution context object mismatch")
    repository_ref = context.payload["repository_root"]
    root = Path(repository_ref["absolute_path"])
    if _root_identity_payload(root) != _plain(repository_ref):
        raise GateBExecutionEnvironmentFailure("repository physical identity mismatch")
    git_directory = _run_git(root, "rev-parse", "--git-dir")
    index_path = Path(_run_git(root, "rev-parse", "--git-path", "index").strip())
    if not index_path.is_absolute():
        index_path = root / index_path
    before_index = _file_snapshot(index_path)
    expected = context.payload["expected_implementation_commit"]
    branch = _run_git(root, "branch", "--show-current").strip()
    head = _run_git(root, "rev-parse", "HEAD").strip()
    local = _run_git(root, "rev-parse", "refs/heads/main").strip()
    cached = _run_git(root, "rev-parse", "refs/remotes/origin/main").strip()
    divergence = _run_git(
        root, "rev-list", "--left-right", "--count", "main...refs/remotes/origin/main"
    ).split()
    dirty = _run_git(root, "status", "--porcelain=v1", "--untracked-files=all").strip()
    staged = _run_git(root, "diff", "--cached", "--name-only").strip()
    git_dir_path = Path(git_directory.strip())
    if not git_dir_path.is_absolute():
        git_dir_path = root / git_dir_path
    if (
        branch != "main"
        or {head, local, cached} != {expected}
        or divergence != ["0", "0"]
        or dirty
        or staged
        or _path_entry_present_no_follow(git_dir_path / "index.lock")
    ):
        raise GateBExecutionEnvironmentFailure("repository state drifted")
    modules = _module_sources(root, context)
    runtime = _runtime_fingerprint()
    if runtime != _plain(context.payload["runtime_fingerprint"]):
        raise GateBExecutionEnvironmentFailure("runtime fingerprint drifted")
    dependency_hash = _verify_dependency_lock(root, context)
    if _file_snapshot(index_path) != before_index:
        raise GateBExecutionEnvironmentFailure("repository index changed during read-only probe")
    return GateBExecutionEvidence(
        context.sha256,
        expected,
        sha256_bytes(canonical_json_bytes(modules)),
        dependency_hash,
        sha256_bytes(canonical_json_bytes(runtime)),
    )


@_sanitized_api
def verify_gate_b_execution_environment(
    request: GateBLoaderRequest, context: GateBExecutionContext
) -> GateBExecutionEvidence:
    """Fail closed with one sanitized type for every environment mismatch."""
    try:
        return _verify_gate_b_execution_environment_unchecked(request, context)
    except GateBExecutionEnvironmentFailure:
        raise
    except BaseException as exc:
        raise GateBExecutionEnvironmentFailure(
            "execution environment verification failed closed"
        ) from exc


def _reserve_attempt(
    request: GateBLoaderRequest, *, expected_latest_record_sha256: str | None
) -> GateBAttemptReservation:
    if is_gate_b_v2_compatibility_object(request):
        _fail("legacy reservation rejects v2 compatibility objects")
    return GateBLedgerStore.reserve_attempt(
        request,
        expected_latest_record_sha256=expected_latest_record_sha256,
    )


def _append_started(
    request: GateBLoaderRequest,
    reservation: GateBAttemptReservation,
    *,
    store: GateBLedgerStore,
) -> GateBLedgerRecord:
    if is_gate_b_v2_compatibility_object(request):
        _fail("legacy STARTED append rejects v2 compatibility objects")
    return store.append_started(request, reservation)


@_sanitized_api
def reserve_gate_b_attempt(
    request: GateBLoaderRequest, *, expected_latest_record_sha256: str | None
) -> GateBAttemptReservation:
    """Create the one durable reservation path before any Test-child open."""
    if is_gate_b_v2_compatibility_object(request):
        _fail("legacy reservation rejects v2 compatibility objects")
    from phase6.gate_b_v2_route import validate_gate_b_v2_reservation_entry

    try:
        validate_gate_b_v2_reservation_entry(request)
    except Exception:
        raise GateBLedgerError("v2 reservation is not authorized by a consumed route") from None
    return GateBLedgerStore.reserve_attempt(
        request,
        expected_latest_record_sha256=expected_latest_record_sha256,
    )


@dataclass(slots=True)
class PreparedGateBTestOpen:
    """Opaque single-use lock-held preparation with no Test-child side effect."""

    request: GateBLoaderRequest = field(repr=False)
    reservation: GateBAttemptReservation = field(repr=False)
    _store: GateBLedgerStore = field(repr=False)
    _lock: Any = field(repr=False)
    _root_descriptors: dict[str, int] = field(repr=False)
    _root_paths: dict[str, Path] = field(repr=False)
    _consumed: bool = field(default=False, repr=False)
    _closed: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        return (
            "PreparedGateBTestOpen("
            f"test_batch_hash={self.reservation.test_batch_hash!r}, "
            f"attempt_ordinal={self.reservation.attempt_ordinal!r}, "
            f"reserved_record_sha256={self.reservation.reserved_record_sha256!r}, "
            "state='RESERVED')"
        )

    def __enter__(self) -> PreparedGateBTestOpen:
        if self._closed:
            _fail("prepared open is already closed")
        return self

    def close(self) -> None:
        if not self._closed:
            try:
                for descriptor in self._root_descriptors.values():
                    os.close(descriptor)
            finally:
                self._lock.__exit__(None, None, None)
                self._closed = True

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


@_sanitized_api
def prepare_gate_b_test_open(
    request: GateBLoaderRequest, reservation: GateBAttemptReservation
) -> PreparedGateBTestOpen:
    """Acquire and retain the namespace lock without opening any Test child."""
    if is_gate_b_v2_compatibility_object(request) or is_gate_b_v2_compatibility_object(reservation):
        _fail("legacy Test preparation rejects v2 compatibility objects")
    if (
        reservation.test_batch_hash != request.batch.test_batch_hash
        or reservation.attempt_ordinal != request.attempt_ordinal
        or reservation.state != "RESERVED"
    ):
        _fail("reservation and request identity mismatch")
    store = GateBLedgerStore(request)
    lock = store.lock()
    lock.__enter__()
    root_descriptors: dict[str, int] = {}
    root_paths: dict[str, Path] = {}
    try:
        for role in ("ledger_base", "quarantine_base", "test_root"):
            ref, root = _validate_root_ref(_plain(request.roots[role]), role)
            descriptor = _open_directory_descriptor(root)
            metadata = os.fstat(descriptor)
            if (
                format(metadata.st_ino, "x") != ref["file_id_hex"]
                or format(metadata.st_dev, "x") != ref["volume_id_hex"]
            ):
                os.close(descriptor)
                _fail("prepared root handle identity mismatch")
            root_descriptors[role] = descriptor
            root_paths[role] = root
        chain = store.load_chain()
        latest = chain[-1] if chain else None
        if (
            latest is None
            or latest.record_sha256 != reservation.reserved_record_sha256
            or latest.to_state != "RESERVED"
        ):
            _fail("reservation is stale before prepare")
    except BaseException:
        for descriptor in root_descriptors.values():
            os.close(descriptor)
        lock.__exit__(*sys.exc_info())
        raise
    return PreparedGateBTestOpen(
        request,
        reservation,
        store,
        lock,
        root_descriptors,
        root_paths,
    )


def _open_child_from_root(
    root_descriptor: int,
    root: Path,
    relative: str,
) -> tuple[Path, int, tuple[int, ...], str]:
    path = _child(root, relative)
    parts = relative.split("/")
    parent_descriptors = [os.dup(root_descriptor)]
    descriptor: int | None = None
    try:
        if os.name == "nt":
            current_path = root
            for part in parts[:-1]:
                current_path /= part
                child_directory = _open_directory_descriptor(current_path)
                metadata = os.fstat(child_directory)
                if not stat.S_ISDIR(metadata.st_mode) or bool(
                    getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                ):
                    os.close(child_directory)
                    raise GateBTestInputFailure("Test input parent is not a physical directory")
                parent_descriptors.append(child_directory)
            descriptor = _open_existing_descriptor(path)
        else:
            nofollow = _required_posix_flag(
                getattr(os, "O_NOFOLLOW", None),
                "O_NOFOLLOW",
            )
            directory_flag = _required_posix_flag(
                getattr(os, "O_DIRECTORY", None),
                "O_DIRECTORY",
            )
            if os.open not in getattr(os, "supports_dir_fd", set()):
                raise GateBTestInputFailure("required openat primitive is unavailable")
            for part in parts[:-1]:
                child_directory = os.open(
                    part,
                    os.O_RDONLY | directory_flag | nofollow,
                    dir_fd=parent_descriptors[-1],
                )
                parent_descriptors.append(child_directory)
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | nofollow,
                dir_fd=parent_descriptors[-1],
            )
        return path, descriptor, tuple(parent_descriptors), parts[-1]
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        for parent_descriptor in reversed(parent_descriptors):
            os.close(parent_descriptor)
        raise


@dataclass(slots=True)
class _PinnedInput:
    path: Path
    descriptor: int
    size: int
    sha256: str
    identity: tuple[int, int]
    parent_descriptors: tuple[int, ...] = field(default=(), repr=False)
    leaf_name: str = field(default="", repr=False)
    _closed: bool = False
    _verified_bytes: bytes | None = field(default=None, repr=False)
    _verified_offset: int = field(default=0, repr=False)

    @staticmethod
    def _validate_topology(metadata: os.stat_result, path: Path) -> None:
        try:
            streams = _windows_stream_names(path)
        except GateBLedgerError as exc:
            raise GateBTestInputFailure(
                "Test input stream topology verification failed closed"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            or streams != ("::$DATA",)
        ):
            raise GateBTestInputFailure("Test input is not a single-link regular file")

    @classmethod
    def open_unread(cls, path: Path) -> _PinnedInput:
        try:
            descriptor = _open_existing_descriptor(path)
        except (OSError, GateBLedgerError) as exc:
            raise GateBTestInputFailure("Test input OS-open failed closed") from exc
        metadata = os.fstat(descriptor)
        try:
            cls._validate_topology(metadata, path)
        except GateBTestInputFailure:
            os.close(descriptor)
            raise
        return cls(path, descriptor, metadata.st_size, "", (metadata.st_dev, metadata.st_ino))

    @classmethod
    def open_unread_at(
        cls,
        root_descriptor: int,
        root: Path,
        relative: str,
    ) -> _PinnedInput:
        try:
            path, descriptor, parents, leaf_name = _open_child_from_root(
                root_descriptor,
                root,
                relative,
            )
        except (OSError, GateBLedgerError, GateBTestInputFailure) as exc:
            raise GateBTestInputFailure("Test input OS-open failed closed") from exc
        metadata = os.fstat(descriptor)
        try:
            cls._validate_topology(metadata, path)
        except GateBTestInputFailure:
            os.close(descriptor)
            for parent_descriptor in reversed(parents):
                os.close(parent_descriptor)
            raise
        return cls(
            path,
            descriptor,
            metadata.st_size,
            "",
            (metadata.st_dev, metadata.st_ino),
            parents,
            leaf_name,
        )

    @classmethod
    def open_first_unverified(cls, path: Path) -> _PinnedInput:
        """OS-open the first payload without any intervening descriptor operation."""
        try:
            descriptor = _open_existing_descriptor(path)
        except (OSError, GateBLedgerError) as exc:
            raise GateBTestInputFailure("first Test input OS-open failed closed") from exc
        return cls(path, descriptor, -1, "", (-1, -1))

    def pin_identity(self) -> None:
        if self._closed:
            raise GateBTestInputFailure("Test input handle is closed")
        metadata = os.fstat(self.descriptor)
        self._validate_topology(metadata, self.path)
        self.size = metadata.st_size
        self.identity = (metadata.st_dev, metadata.st_ino)

    @classmethod
    def open_first_unverified_at(
        cls,
        root_descriptor: int,
        root: Path,
        relative: str,
    ) -> _PinnedInput:
        """OS-open the first payload through its pinned root without probing it."""
        try:
            path, descriptor, parents, leaf_name = _open_child_from_root(
                root_descriptor,
                root,
                relative,
            )
        except (OSError, GateBLedgerError, GateBTestInputFailure) as exc:
            raise GateBTestInputFailure("first Test input OS-open failed closed") from exc
        return cls(path, descriptor, -1, "", (-1, -1), parents, leaf_name)

    def verify(self, *, expected_size: int, expected_sha256: str, canonical: bool) -> bytes:
        if self._closed:
            raise GateBTestInputFailure("Test input handle is closed")
        if self.identity == (-1, -1):
            raise GateBTestInputFailure("Test input identity was not pinned")
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        chunks = []
        while True:
            chunk = os.read(self.descriptor, _MAX_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
        raw = b"".join(chunks)
        if len(raw) != expected_size or digest.hexdigest() != expected_sha256:
            raise GateBTestInputFailure("Test input size or hash mismatch")
        if canonical:
            _strict_canonical_object(raw, "canonical Test input")
        metadata = os.fstat(self.descriptor)
        self._validate_topology(metadata, self.path)
        if (metadata.st_dev, metadata.st_ino) != self.identity or metadata.st_size != len(raw):
            raise GateBTestInputFailure("Test input identity changed")
        try:
            if os.name != "nt" and self.parent_descriptors:
                nofollow = _required_posix_flag(
                    getattr(os, "O_NOFOLLOW", None),
                    "O_NOFOLLOW",
                )
                if os.open not in getattr(os, "supports_dir_fd", set()):
                    raise GateBTestInputFailure("required reopenat primitive is unavailable")
                reopened = os.open(
                    self.leaf_name,
                    os.O_RDONLY | nofollow,
                    dir_fd=self.parent_descriptors[-1],
                )
            else:
                reopened = _open_existing_descriptor(self.path)
            try:
                named = os.fstat(reopened)
                self._validate_topology(named, self.path)
            finally:
                os.close(reopened)
        except (OSError, GateBLedgerError) as exc:
            raise GateBTestInputFailure("Test input path cannot be identity-reopened") from exc
        if (named.st_dev, named.st_ino) != self.identity or named.st_size != len(raw):
            raise GateBTestInputFailure("Test input path identity was substituted")
        self.size = len(raw)
        self.sha256 = digest.hexdigest()
        self._verified_bytes = raw
        self._verified_offset = 0
        return raw

    def reset(self) -> None:
        if self._verified_bytes is None:
            raise GateBTestInputFailure("Test input bytes were not verified")
        self._verified_offset = 0

    def read(self, size: int) -> bytes:
        if self._verified_bytes is None:
            raise GateBTestInputFailure("Test input bytes were not verified")
        end = min(self._verified_offset + size, len(self._verified_bytes))
        chunk = self._verified_bytes[self._verified_offset : end]
        self._verified_offset = end
        return chunk

    def close(self) -> None:
        if not self._closed:
            first_error: BaseException | None = None
            try:
                os.close(self.descriptor)
            except BaseException as exc:
                first_error = exc
            for descriptor in reversed(self.parent_descriptors):
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
            self._closed = True
            if first_error is not None:
                raise first_error


def _child(root: Path, relative: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or not relative.isascii()
        or any(not 0x20 <= ord(character) <= 0x7E for character in relative)
        or "\\" in relative
        or ":" in relative
        or "://" in relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise GateBTestInputFailure("Test input relative path is unsafe")
    candidate = root.joinpath(*relative.split("/"))
    if root != candidate and root not in candidate.parents:
        raise GateBTestInputFailure("Test input path escapes its explicit root")
    return candidate


def _component_payload(
    request: GateBLoaderRequest,
    name: str,
    root: Path,
    root_descriptor: int,
) -> tuple[_PinnedInput, dict[str, Any], bytes]:
    ref = request.batch.payload["components"][name]
    handle = _PinnedInput.open_unread_at(
        root_descriptor,
        root,
        ref["relative_path"],
    )
    try:
        raw = handle.verify(
            expected_size=ref["size_bytes"],
            expected_sha256=ref["sha256"],
            canonical=True,
        )
        payload = _strict_canonical_object(raw, f"{name} component")
        if payload.get("schema_version") != ref["schema_version"]:
            raise GateBTestInputFailure("component schema version mismatch")
        return handle, payload, raw
    except BaseException:
        handle.close()
        raise


def _validate_opponent_index(
    request: GateBLoaderRequest, payload: dict[str, Any]
) -> list[dict[str, Any]]:
    _closed(
        payload,
        {
            "schema_version",
            "artifact_type",
            "format_id",
            "physical_split_id",
            "split_id",
            "opponents",
        },
        "opponent payload index",
    )
    test_input = request.batch.payload["test_input"]
    if (
        payload["schema_version"] != OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION
        or payload["artifact_type"] != "gate_b_opponent_payload_index"
        or payload["format_id"] != test_input["format_id"]
        or payload["physical_split_id"] != test_input["physical_split_id"]
        or payload["split_id"] != test_input["split_id"]
    ):
        raise GateBTestInputFailure("opponent payload index identity mismatch")
    expected_ids = list(request.batch.payload["coordinates"]["opponent_ids"])
    opponents = payload["opponents"]
    if not isinstance(opponents, list) or len(opponents) != len(expected_ids):
        raise GateBTestInputFailure("opponent payload index cardinality mismatch")
    paths = []
    for raw, expected_id in zip(opponents, expected_ids, strict=True):
        ref = _closed(raw, {"opponent_id", "relative_path", "sha256", "size_bytes"}, "opponent ref")
        if ref["opponent_id"] != expected_id:
            raise GateBTestInputFailure("opponent payload order mismatch")
        _child(Path("synthetic-root"), ref["relative_path"])
        _sha(ref["sha256"], "opponent payload hash")
        _positive(ref["size_bytes"], "opponent payload size")
        paths.append(ref["relative_path"])
    if len(paths) != len(set(paths)):
        raise GateBTestInputFailure("opponent payload paths are duplicated")
    return opponents


def _validate_selected_lock(request: GateBLoaderRequest, payload: dict[str, Any]) -> bytes:
    _closed(
        payload,
        {
            "schema_version",
            "artifact_type",
            "split",
            "validation_batch_manifest_sha256",
            "primary_selection_report_sha256",
            "selected_config_count",
            "selected_candidate_id",
            "selected_config",
            "selected_config_sha256",
            "manual_override",
        },
        "selected config lock",
    )
    selection = request.batch.payload["selection"]
    _sha(
        payload["validation_batch_manifest_sha256"],
        "selected lock validation batch hash",
    )
    _sha(
        payload["primary_selection_report_sha256"],
        "selected lock selection report hash",
    )
    _sha(payload["selected_config_sha256"], "selected lock config hash")
    if (
        payload["schema_version"] != SELECTED_CONFIG_LOCK_SCHEMA_VERSION
        or payload["artifact_type"] != "selected_config_lock"
        or payload["split"] != "validation"
        or isinstance(payload["selected_config_count"], bool)
        or not isinstance(payload["selected_config_count"], int)
        or payload["selected_config_count"] != 1
        or payload["selected_candidate_id"] != selection["primary_config_id"]
        or payload["primary_selection_report_sha256"] != selection["selection_report_sha256"]
        or payload["manual_override"] is not False
    ):
        raise GateBTestInputFailure("selected config lock identity mismatch")
    selected = _closed(
        payload["selected_config"],
        {
            "detector_confidence",
            "epsilon",
            "grid_version",
            "provider_confidence",
            "safety_alpha",
            "sample_floor",
            "sampling_contract_sha256",
        },
        "selected config",
    )
    if selected["grid_version"] != "phase6-primary-grid-v1":
        raise GateBTestInputFailure("selected config grid mismatch")
    for name in (
        "detector_confidence",
        "epsilon",
        "provider_confidence",
        "safety_alpha",
    ):
        _decimal_string(selected[name], f"selected config {name}")
    _positive(selected["sample_floor"], "selected config sample floor")
    _sha(selected["sampling_contract_sha256"], "selected sampling contract hash")
    raw = canonical_json_bytes(selected)
    digest = sha256_bytes(raw)
    if digest != payload["selected_config_sha256"] or digest != selection["primary_config_sha256"]:
        raise GateBTestInputFailure("selected config semantic hash mismatch")
    return raw


def _validate_execution_index(
    request: GateBLoaderRequest,
    payload: dict[str, Any],
    primary_raw: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    _closed(
        payload,
        {
            "schema_version",
            "artifact_type",
            "estimator_config_sha256",
            "selected_config_lock_sha256",
            "primary",
            "comparators",
            "ablations",
        },
        "execution config index",
    )
    components = request.batch.payload["components"]
    selection = request.batch.payload["selection"]
    if (
        payload["schema_version"] != EXECUTION_CONFIG_INDEX_SCHEMA_VERSION
        or payload["artifact_type"] != "gate_b_execution_config_index"
        or payload["estimator_config_sha256"] != components["estimator_config"]["sha256"]
        or payload["selected_config_lock_sha256"] != components["selected_config_lock"]["sha256"]
        or payload["selected_config_lock_sha256"] == selection["primary_config_sha256"]
    ):
        raise GateBTestInputFailure("execution config index identity mismatch")
    primary = _closed(
        payload["primary"],
        {
            "config_id",
            "derivation",
            "name",
            "sha256",
            "size_bytes",
            "source_component_sha256",
        },
        "primary config ref",
    )
    _positive(primary["size_bytes"], "primary config size")
    if (
        primary["config_id"] != selection["primary_config_id"]
        or primary["derivation"] != "canonical_json_bytes(selected_config_lock#/selected_config)"
        or primary["name"] != "primary"
        or primary["sha256"] != selection["primary_config_sha256"]
        or primary["size_bytes"] != len(primary_raw)
        or primary["source_component_sha256"] != components["selected_config_lock"]["sha256"]
    ):
        raise GateBTestInputFailure("derived primary config ref mismatch")
    groups = []
    for group_name in ("comparators", "ablations"):
        indexed = payload[group_name]
        selected = selection[group_name]
        if not isinstance(indexed, list) or len(indexed) != len(selected):
            raise GateBTestInputFailure("indexed config cardinality mismatch")
        for raw, expected in zip(indexed, selected, strict=True):
            ref = _closed(
                raw,
                {
                    "config_id",
                    "name",
                    "relative_path",
                    "schema_version",
                    "sha256",
                    "size_bytes",
                },
                "indexed config",
            )
            if (
                ref["config_id"] != expected["config_id"]
                or ref["name"] != expected["name"]
                or ref["sha256"] != expected["sha256"]
            ):
                raise GateBTestInputFailure("indexed config selection join mismatch")
            _child(Path("synthetic-root"), ref["relative_path"])
            _ascii(ref["schema_version"], "indexed config schema")
            _positive(ref["size_bytes"], "indexed config size")
        groups.append(indexed)
    return primary, groups[0], groups[1]


@dataclass(slots=True)
class _Frame:
    prefix: bytes
    source: bytes | _PinnedInput
    size: int


class _FramedSource:
    def __init__(self, frames: list[_Frame]) -> None:
        self._frames = frames
        self._frame_index = 0
        self._prefix_offset = 0
        self._source_offset = 0

    def read(self, maximum: int) -> bytes:
        result = bytearray()
        while len(result) < maximum and self._frame_index < len(self._frames):
            frame = self._frames[self._frame_index]
            if self._prefix_offset < len(frame.prefix):
                take = min(maximum - len(result), len(frame.prefix) - self._prefix_offset)
                result.extend(frame.prefix[self._prefix_offset : self._prefix_offset + take])
                self._prefix_offset += take
                continue
            remaining = frame.size - self._source_offset
            if remaining:
                take = min(maximum - len(result), remaining)
                if isinstance(frame.source, bytes):
                    chunk = frame.source[self._source_offset : self._source_offset + take]
                else:
                    chunk = frame.source.read(take)
                if len(chunk) != take:
                    raise GateBTestInputFailure("framed Test input truncated")
                result.extend(chunk)
                self._source_offset += len(chunk)
                continue
            self._frame_index += 1
            self._prefix_offset = 0
            self._source_offset = 0
        return bytes(result)


def _frame(
    frame_type: str,
    identifier: str,
    name: str,
    sha256: str,
    size: int,
    source: bytes | _PinnedInput,
) -> _Frame:
    header = canonical_json_bytes(
        {
            "frame_type": frame_type,
            "id": identifier,
            "name": name,
            "sha256": sha256,
            "size_bytes": size,
        }
    )
    if len(header) >= 1 << 64 or size >= 1 << 64:
        raise GateBTestInputFailure("framing length overflow")
    prefix = struct.pack(">Q", len(header)) + header + struct.pack(">Q", size)
    return _Frame(prefix, source, size)


class _AccessLog:
    def __init__(
        self,
        handle: BinaryIO,
        request: GateBLoaderRequest,
        *,
        evidence: GateBExecutionEvidence | None = None,
    ) -> None:
        self.handle = handle
        self.request = request
        self.sequence = 0
        self.previous = _SHA_ZERO
        self.evidence = evidence

    def set_evidence(self, evidence: GateBExecutionEvidence) -> None:
        self.evidence = evidence

    def append(
        self,
        event_type: str,
        *,
        failure_class: str | None = None,
        reason_id: str | None = None,
        byte_count: int | None = None,
        output_name: str | None = None,
        cumulative_input_sha256: str | None = None,
    ) -> None:
        self.sequence += 1
        from datetime import UTC, datetime

        entry = {
            "schema_version": "phase6-gate-b-access-log-entry-v1",
            "artifact_type": "gate_b_test_access_log_entry",
            "event_sequence": self.sequence,
            "previous_entry_sha256": self.previous,
            "test_batch_hash": self.request.batch.test_batch_hash,
            "attempt_ordinal": self.request.attempt_ordinal,
            "actor_id": self.request.actor_id,
            "timestamp_utc": datetime.now(UTC)
            .replace(microsecond=0)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": event_type,
            "execution_context_sha256": self.request.execution_context.sha256,
            "execution_evidence_sha256": (
                None if self.evidence is None else _execution_evidence_sha256(self.evidence)
            ),
            "failure_class": failure_class,
            "byte_count": byte_count,
            "output_name": output_name,
            "cumulative_input_sha256": cumulative_input_sha256,
            "reason_id": reason_id,
        }
        raw = canonical_json_bytes(entry)
        try:
            written = self.handle.write(raw)
            if written != len(raw):
                raise OSError("short access-log write")
            self.handle.flush()
            os.fsync(self.handle.fileno())
        except OSError as exc:
            raise GateBPartialEvidenceError("access-log durability failed") from exc
        self.previous = sha256_bytes(raw)


@dataclass(slots=True)
class _CapabilityState:
    active: bool = True
    eof_seen: bool = False
    violation: bool = False
    terminal_closed: bool = False
    loader_failure: BaseException | None = None

    def reject(self, message: str) -> None:
        self.violation = True
        self.active = False
        raise GateBExecutorContractViolation(message)


class GateBInputCapability:
    """Bounded forward-only framed input with one acknowledged EOF."""

    __slots__ = ("_state", "_source", "_access", "_digest")

    def __init__(self, state: _CapabilityState, source: _FramedSource, access: _AccessLog) -> None:
        self._state = state
        self._source = source
        self._access = access
        self._digest = hashlib.sha256()

    def __repr__(self) -> str:
        return "<GateBInputCapability>"

    @_sanitized_api
    def read_chunk(self, max_bytes: int) -> bytes:
        if self._state.terminal_closed:
            raise GateBCapabilityClosed("input capability is closed")
        if not self._state.active:
            if self._state.eof_seen:
                self._state.reject("input read after EOF")
            raise GateBCapabilityClosed("input capability is closed")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= _MAX_CHUNK
        ):
            self._state.reject("invalid input chunk bound")
        if self._state.eof_seen:
            self._state.reject("input read after EOF")
        try:
            chunk = self._source.read(max_bytes)
        except BaseException as exc:
            self._state.loader_failure = exc
            self._state.active = False
            raise GateBTestInputFailure("framed input source failed") from exc
        if chunk:
            self._digest.update(chunk)
            try:
                self._access.append(
                    "input_read",
                    byte_count=len(chunk),
                    cumulative_input_sha256=self._digest.hexdigest(),
                )
            except BaseException as exc:
                self._state.loader_failure = exc
                self._state.active = False
                raise
            return chunk
        self._state.eof_seen = True
        try:
            self._access.append(
                "input_eof",
                byte_count=0,
                cumulative_input_sha256=self._digest.hexdigest(),
            )
        except BaseException as exc:
            self._state.loader_failure = exc
            self._state.active = False
            raise
        return b""


class GateBOutputsCapability:
    """Six append-only quarantine sinks; access-log ownership stays loader-only."""

    __slots__ = ("_state", "_quarantine", "_access")

    def __init__(
        self, state: _CapabilityState, quarantine: GateBQuarantine, access: _AccessLog
    ) -> None:
        self._state = state
        self._quarantine = quarantine
        self._access = access

    def __repr__(self) -> str:
        return "<GateBOutputsCapability>"

    @_sanitized_api
    def write_chunk(self, name: str, data: bytes) -> None:
        if self._state.terminal_closed or not self._state.active:
            raise GateBCapabilityClosed("output capability is closed")
        if name not in _WRITABLE_OUTPUTS:
            self._state.reject("invalid quarantine output name")
        if not isinstance(data, bytes) or not 1 <= len(data) <= _MAX_CHUNK:
            self._state.reject("invalid quarantine output chunk")
        handle = self._quarantine.writable_handle(name)
        try:
            written = handle.write(data)
            if written != len(data):
                raise OSError("short quarantine output write")
            handle.flush()
            os.fsync(handle.fileno())
            self._access.append("output_write", byte_count=len(data), output_name=name)
        except BaseException as exc:
            self._state.loader_failure = exc
            self._state.active = False
            raise GateBPartialEvidenceError("quarantine output durability failed") from exc


@dataclass(frozen=True, slots=True)
class GateBExecutionReceipt:
    """Sanitized receipt returned only after SEALED is durable."""

    test_batch_hash: str
    attempt_ordinal: int
    started_record_sha256: str
    sealed_record_sha256: str
    executor_id: str
    state: str


def _verify_nonpayload_inputs(
    request: GateBLoaderRequest,
    test_root_descriptor: int,
) -> tuple[
    dict[str, _PinnedInput],
    bytes,
    list[tuple[dict[str, Any], _PinnedInput]],
    list[tuple[dict[str, Any], _PinnedInput]],
    list[dict[str, Any]],
]:
    _root_ref, root = _validate_root_ref(_plain(request.roots["test_root"]), "test_root")
    components: dict[str, _PinnedInput] = {}
    payloads: dict[str, dict[str, Any]] = {}
    relative_paths: set[str] = set()
    identities: set[tuple[int, int]] = set()
    all_handles: list[_PinnedInput] = []
    try:
        for name in COMPONENT_NAMES:
            ref = request.batch.payload["components"][name]
            if ref["relative_path"] in relative_paths:
                raise GateBTestInputFailure("component relative path alias detected")
            handle, payload, _raw = _component_payload(
                request,
                name,
                root,
                test_root_descriptor,
            )
            if handle.identity in identities:
                handle.close()
                raise GateBTestInputFailure("component physical identity alias detected")
            all_handles.append(handle)
            relative_paths.add(ref["relative_path"])
            identities.add(handle.identity)
            components[name] = handle
            payloads[name] = payload
        primary_raw = _validate_selected_lock(request, payloads["selected_config_lock"])
        primary, comparators, ablations = _validate_execution_index(
            request, payloads["execution_config_index"], primary_raw
        )
        opponents = _validate_opponent_index(request, payloads["opponent_payload_index"])
        indexed_groups = []
        for refs in (comparators, ablations):
            opened = []
            for ref in refs:
                if ref["relative_path"] in relative_paths:
                    raise GateBTestInputFailure("indexed config relative path alias detected")
                handle = _PinnedInput.open_unread_at(
                    test_root_descriptor,
                    root,
                    ref["relative_path"],
                )
                all_handles.append(handle)
                raw = handle.verify(
                    expected_size=ref["size_bytes"],
                    expected_sha256=ref["sha256"],
                    canonical=True,
                )
                payload = _strict_canonical_object(raw, "indexed config")
                if payload.get("schema_version") != ref["schema_version"]:
                    handle.close()
                    raise GateBTestInputFailure("indexed config schema mismatch")
                if handle.identity in identities:
                    handle.close()
                    raise GateBTestInputFailure("indexed config physical alias detected")
                identities.add(handle.identity)
                relative_paths.add(ref["relative_path"])
                opened.append((ref, handle))
            indexed_groups.append(opened)
        for opponent in opponents:
            if opponent["relative_path"] in relative_paths:
                raise GateBTestInputFailure("opponent payload path aliases nonpayload input")
            relative_paths.add(opponent["relative_path"])
        return components, primary_raw, indexed_groups[0], indexed_groups[1], opponents
    except BaseException:
        for handle in all_handles:
            handle.close()
        raise


def _close_input_handles(
    handles: list[_PinnedInput],
    extra: _PinnedInput | None = None,
) -> None:
    first_error: BaseException | None = None
    seen: set[int] = set()
    for handle in [*handles, *([] if extra is None else [extra])]:
        if id(handle) in seen:
            continue
        seen.add(id(handle))
        try:
            handle.close()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise GateBPartialEvidenceError("Test input handle closure failed") from first_error


def _build_frames(
    request: GateBLoaderRequest,
    components: Mapping[str, _PinnedInput],
    primary_raw: bytes,
    comparators: list[tuple[dict[str, Any], _PinnedInput]],
    ablations: list[tuple[dict[str, Any], _PinnedInput]],
    payloads: list[tuple[dict[str, Any], _PinnedInput]],
) -> _FramedSource:
    frames = []
    context_raw = canonical_json_bytes(
        {
            "coordinates": _plain(request.batch.payload["coordinates"]),
            "selection": _plain(request.batch.payload["selection"]),
            "test_input": _plain(request.batch.payload["test_input"]),
        }
    )
    frames.append(
        _frame(
            "batch_context",
            "test_batch_context",
            "test_batch_context",
            sha256_bytes(context_raw),
            len(context_raw),
            context_raw,
        )
    )
    for name in COMPONENT_NAMES:
        handle = components[name]
        handle.reset()
        ref = request.batch.payload["components"][name]
        frames.append(_frame("component", name, name, ref["sha256"], ref["size_bytes"], handle))
    primary = request.batch.payload["selection"]
    frames.append(
        _frame(
            "config",
            primary["primary_config_id"],
            "primary",
            primary["primary_config_sha256"],
            len(primary_raw),
            primary_raw,
        )
    )
    for refs in (comparators, ablations):
        for ref, handle in refs:
            handle.reset()
            frames.append(
                _frame(
                    "config",
                    ref["config_id"],
                    ref["name"],
                    ref["sha256"],
                    ref["size_bytes"],
                    handle,
                )
            )
    for ref, handle in payloads:
        handle.reset()
        frames.append(
            _frame(
                "opponent_payload",
                ref["opponent_id"],
                ref["opponent_id"],
                ref["sha256"],
                ref["size_bytes"],
                handle,
            )
        )
    return _FramedSource(frames)


def _complete_failure(
    request: GateBLoaderRequest,
    quarantine: GateBQuarantine,
    access: _AccessLog,
    *,
    failure_class: str,
    event_type: str,
    reservation_or_started: GateBAttemptReservation | GateBLedgerRecord,
    started_record: GateBLedgerRecord | None,
    event_already_written: bool = False,
) -> GateBLedgerRecord:
    state = "STARTED" if started_record is not None else "RESERVED"
    reason_id = request.batch.reason_for(failure_class, state)
    if not event_already_written:
        access.append(event_type, failure_class=failure_class, reason_id=reason_id)
    access.append("failure_seal_started")
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="failed_closed",
        started_record_sha256=(None if started_record is None else started_record.record_sha256),
    )
    return mark_gate_b_failed_closed(
        request,
        reservation_or_started,
        failure_class=failure_class,
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )


def _verify_execution_environment_for_open(
    request: GateBLoaderRequest,
) -> GateBExecutionEvidence:
    """Preserve the v1 API while dispatching only an exact registered v2 request."""
    from phase6.gate_b_v2_route import (
        is_gate_b_v2_runtime_request,
        verify_gate_b_v2_runtime_execution_environment,
    )

    if is_gate_b_v2_runtime_request(request):
        return verify_gate_b_v2_runtime_execution_environment(
            request,
            request.execution_context,
        )
    return verify_gate_b_execution_environment(request, request.execution_context)


@_sanitized_api
def open_gate_b_test_input(
    prepared: PreparedGateBTestOpen, *, executor: GateBApprovedExecutor
) -> GateBExecutionReceipt:
    """Run one approved callback and return only a sanitized sealed receipt."""
    if is_gate_b_v2_compatibility_object(prepared):
        _fail("legacy Test input route rejects v2 compatibility objects")
    if prepared._closed or prepared._consumed:
        _fail("prepared Test open is not single-use")
    prepared._consumed = True
    request = prepared.request
    quarantine: GateBQuarantine | None = None
    handles: list[_PinnedInput] = []
    first_payload: _PinnedInput | None = None
    started_record: GateBLedgerRecord | None = None
    try:
        sampler_ref = request.batch.payload["components"]["execution_sampler"]
        if (
            not isinstance(executor.executor_id, str)
            or executor.executor_id != sampler_ref["schema_version"]
            or not isinstance(executor.executor_sha256, str)
            or executor.executor_sha256 != sampler_ref["sha256"]
        ):
            _fail("executor identity differs from the verified sampler component")
        quarantine = GateBQuarantine.create(
            request,
            prepared._root_descriptors["quarantine_base"],
        )
        access = _AccessLog(quarantine.access_log_handle(), request)
        try:
            evidence = _verify_execution_environment_for_open(request)
        except BaseException as exc:
            try:
                prepared.close()
                _complete_failure(
                    request,
                    quarantine,
                    access,
                    failure_class="execution_environment_failure",
                    event_type="environment_verification_failed",
                    reservation_or_started=prepared.reservation,
                    started_record=None,
                )
            except GateBPartialEvidenceError:
                raise
            raise GateBExecutionEnvironmentFailure("execution environment failed closed") from exc
        access.set_evidence(evidence)
        access.append("environment_verified")
        try:
            prepared._lock.verify_identity()
            (
                components,
                primary_raw,
                comparators,
                ablations,
                opponent_refs,
            ) = _verify_nonpayload_inputs(
                request,
                prepared._root_descriptors["test_root"],
            )
            handles.extend(components.values())
            handles.extend(handle for _ref, handle in comparators)
            handles.extend(handle for _ref, handle in ablations)
            test_root = prepared._root_paths["test_root"]
            prepared._lock.verify_identity()
            first_payload = _PinnedInput.open_first_unverified_at(
                prepared._root_descriptors["test_root"],
                test_root,
                opponent_refs[0]["relative_path"],
            )
        except BaseException as exc:
            _close_input_handles(handles, first_payload)
            prepared.close()
            _complete_failure(
                request,
                quarantine,
                access,
                failure_class="test_input_prestart_failure",
                event_type="test_input_prestart_failed",
                reservation_or_started=prepared.reservation,
                started_record=None,
            )
            raise GateBTestInputFailure("prestart Test input failed closed") from exc
        try:
            started_record = _append_started(request, prepared.reservation, store=prepared._store)
        except BaseException as exc:
            chain = prepared._store.load_chain()
            latest = chain[-1] if chain else None
            if (
                latest is not None
                and latest.record_sha256 == prepared.reservation.reserved_record_sha256
            ):
                _close_input_handles(handles, first_payload)
                prepared.close()
                _complete_failure(
                    request,
                    quarantine,
                    access,
                    failure_class="started_append_failure",
                    event_type="started_append_failed",
                    reservation_or_started=prepared.reservation,
                    started_record=None,
                )
                raise GateBLoaderError("STARTED append failed closed") from exc
            _close_input_handles(handles, first_payload)
            quarantine.invalidate_partial()
            prepared.close()
            raise GateBPartialEvidenceError("STARTED append outcome is indeterminate") from exc
        access.append("started_appended")
        payloads = []
        try:
            assert first_payload is not None
            handles.append(first_payload)
            first_ref = opponent_refs[0]
            first_payload.pin_identity()
            first_payload.verify(
                expected_size=first_ref["size_bytes"],
                expected_sha256=first_ref["sha256"],
                canonical=False,
            )
            payloads.append((first_ref, first_payload))
            known_identities = {handle.identity for handle in handles[:-1]}
            if first_payload.identity in known_identities:
                raise GateBTestInputFailure("opponent payload physical alias detected")
            known_identities.add(first_payload.identity)
            test_root = prepared._root_paths["test_root"]
            for ref in opponent_refs[1:]:
                handle = _PinnedInput.open_unread_at(
                    prepared._root_descriptors["test_root"],
                    test_root,
                    ref["relative_path"],
                )
                handles.append(handle)
                handle.verify(
                    expected_size=ref["size_bytes"],
                    expected_sha256=ref["sha256"],
                    canonical=False,
                )
                if handle.identity in known_identities:
                    raise GateBTestInputFailure("opponent payload physical alias detected")
                known_identities.add(handle.identity)
                payloads.append((ref, handle))
        except BaseException as exc:
            _close_input_handles(handles, first_payload)
            prepared.close()
            _complete_failure(
                request,
                quarantine,
                access,
                failure_class="test_input_poststart_failure",
                event_type="test_input_poststart_failed",
                reservation_or_started=started_record,
                started_record=started_record,
            )
            raise GateBTestInputFailure("poststart Test input failed closed") from exc
        prepared.close()
        access.append("test_input_verified")
        source = _build_frames(request, components, primary_raw, comparators, ablations, payloads)
        state = _CapabilityState()
        input_capability = GateBInputCapability(state, source, access)
        output_capability = GateBOutputsCapability(state, quarantine, access)
        callback_error: BaseException | None = None
        callback_result: object = None
        try:
            callback_result = executor.execute(input_capability, output_capability)
        except BaseException as exc:
            callback_error = exc
        if state.loader_failure is not None:
            if isinstance(state.loader_failure, GateBTestInputFailure):
                state.active = False
                state.terminal_closed = True
                access.append("capabilities_closed")
                _close_input_handles(handles, first_payload)
                _complete_failure(
                    request,
                    quarantine,
                    access,
                    failure_class="test_input_poststart_failure",
                    event_type="test_input_poststart_failed",
                    reservation_or_started=started_record,
                    started_record=started_record,
                )
                raise GateBTestInputFailure(
                    "poststart Test input failed closed"
                ) from state.loader_failure
            _close_input_handles(handles, first_payload)
            quarantine.invalidate_partial()
            raise GateBPartialEvidenceError("loader-owned callback storage failed")
        callback_failed = (
            callback_error is not None
            or callback_result is not None
            or not state.eof_seen
            or state.violation
        )
        state.active = False
        state.terminal_closed = True
        access.append("capabilities_closed")
        _close_input_handles(handles, first_payload)
        if callback_failed:
            reason_id = request.batch.reason_for("executor_callback_failure", "STARTED")
            access.append(
                "executor_failed",
                failure_class="executor_callback_failure",
                reason_id=reason_id,
            )
            _complete_failure(
                request,
                quarantine,
                access,
                failure_class="executor_callback_failure",
                event_type="executor_failed",
                reservation_or_started=started_record,
                started_record=started_record,
                event_already_written=True,
            )
            raise GateBExecutorFailure("executor callback failed closed")
        access.append("executor_returned")
        access.append("seal_started")
        manifest_path, manifest_hash = quarantine.seal(
            request,
            status="sealed",
            started_record_sha256=started_record.record_sha256,
        )
        sealed = seal_gate_b_attempt(
            request,
            started_record,
            quarantine_manifest_path=manifest_path,
            expected_quarantine_manifest_sha256=manifest_hash,
        )
        return GateBExecutionReceipt(
            request.batch.test_batch_hash,
            request.attempt_ordinal,
            started_record.record_sha256,
            sealed.record_sha256,
            executor.executor_id,
            "SEALED",
        )
    except GateBPartialEvidenceError:
        if quarantine is not None:
            quarantine.invalidate_partial()
        raise
    except (GateBLoaderError, GateBLedgerError):
        raise
    except BaseException as exc:
        if quarantine is not None:
            quarantine.invalidate_partial()
        raise GateBPartialEvidenceError("unclassified loader failure retained evidence") from exc
    finally:
        _close_input_handles(handles, first_payload)
        prepared.close()
