"""Explicit-root fail-closed Gate B loader and capability boundary.

The callback is a research-governance trust boundary. This module is not a
security sandbox against a host administrator or malicious in-process code.
It never discovers a Test root from defaults, environment, home, or CWD.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib.machinery
import importlib.metadata
import json
import os
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol

from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACTIVE_MODULE_PATHS,
    COMPONENT_NAMES,
    DEPENDENCY_LOCK_SCHEMA_VERSION,
    EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
    SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
    GateBBatchManifest,
    GateBExecutionContext,
    GateBReadinessAuthorization,
    load_gate_b_batch_manifest,
    load_gate_b_execution_context,
    load_gate_b_readiness_authorization,
    load_gate_b_root_anchor,
)
from phase6.gate_b_ledger import (
    GateBAttemptReservation,
    GateBLedgerError,
    GateBLedgerRecord,
    GateBLedgerStore,
    GateBQuarantine,
    mark_gate_b_failed_closed,
    seal_gate_b_attempt,
)

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


@dataclass(frozen=True, slots=True)
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

    def __repr__(self) -> str:
        return (
            "GateBLoaderRequest("
            f"test_batch_hash={self.batch.test_batch_hash!r}, "
            f"attempt_ordinal={self.attempt_ordinal!r}, actor_role='test_runner')"
        )


@_sanitized_api
def load_gate_b_loader_request(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_readiness_authorization_sha256: str,
    expected_readiness_approval_record_sha256: str,
    expected_readiness_signature_record_sha256: str,
) -> GateBLoaderRequest:
    """Load and join one explicit request without opening any Test-root child."""
    request_path = Path(path)
    try:
        raw = _read_pinned(request_path, "loader request")
    except GateBLedgerError as exc:
        raise GateBLoaderError("loader request physical verification failed") from exc
    if sha256_bytes(raw) != _sha(expected_sha256, "request hash"):
        _fail("loader request stored-byte hash mismatch")
    value = _strict_canonical_object(raw, "Gate B loader request")
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
    batch_path, batch_hash = _path_ref(value["batch_manifest"], "batch manifest ref")
    readiness_path, readiness_hash = _path_ref(
        value["readiness_authorization"], "readiness authorization ref"
    )
    context_path, context_hash = _path_ref(value["execution_context"], "execution context ref")
    for artifact_path, artifact_hash, label in (
        (batch_path, batch_hash, "batch manifest"),
        (readiness_path, readiness_hash, "readiness authorization"),
        (context_path, context_hash, "execution context"),
    ):
        try:
            artifact_raw = _read_pinned(artifact_path, label)
        except GateBLedgerError as exc:
            raise GateBLoaderError(f"{label} physical verification failed") from exc
        if sha256_bytes(artifact_raw) != artifact_hash:
            _fail(f"{label} stored-byte hash mismatch")
    if readiness_hash != expected_readiness_authorization_sha256:
        _fail("request readiness hash differs from its caller trust anchor")
    readiness = load_gate_b_readiness_authorization(
        readiness_path,
        expected_sha256=expected_readiness_authorization_sha256,
        expected_approval_record_sha256=expected_readiness_approval_record_sha256,
        expected_signature_record_sha256=expected_readiness_signature_record_sha256,
    )
    batch = load_gate_b_batch_manifest(batch_path, expected_sha256=batch_hash)
    context = load_gate_b_execution_context(context_path, expected_sha256=context_hash)

    roots_value = _closed(
        value["roots"], {"ledger_base", "quarantine_base", "test_root"}, "loader roots"
    )
    roots: dict[str, dict[str, Any]] = {}
    paths = {}
    for role in ("ledger_base", "quarantine_base", "test_root"):
        ref, root_path = _validate_root_ref(roots_value[role], role)
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
    for role in ("ledger_base", "quarantine_base"):
        anchor_path = paths[role] / roots[role]["anchor_relative_path"]
        try:
            anchor_raw = _read_pinned(anchor_path, f"{role} root anchor")
        except GateBLedgerError as exc:
            raise GateBLoaderError(f"{role} root anchor physical verification failed") from exc
        if sha256_bytes(anchor_raw) != roots[role]["anchor_sha256"]:
            _fail(f"{role} root anchor stored-byte hash mismatch")
        anchor = load_gate_b_root_anchor(
            anchor_path,
            expected_sha256=roots[role]["anchor_sha256"],
            expected_root_role=role,
            expected_approval_record_sha256=approval_hash,
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
    roots_hash = sha256_bytes(canonical_json_bytes(_plain(roots_value)))
    if roots_hash != readiness.payload["approved_roots_sha256"]:
        _fail("complete root-reference hash mismatch")
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
        expected_sha256,
        batch,
        readiness,
        context,
        _freeze(roots),
        actor_id,
        actor["actor_role"],
        attempt_ordinal,
        _freeze(value),
        request_path.resolve(),
    )


@dataclass(frozen=True, slots=True)
class GateBExecutionEvidence:
    """Path-free immutable evidence digests from the complete hard gate."""

    execution_context_sha256: str
    implementation_commit: str
    active_module_sources_sha256: str
    dependency_lock_sha256: str
    runtime_fingerprint_sha256: str


def _execution_evidence_sha256(evidence: GateBExecutionEvidence) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "execution_context_sha256": evidence.execution_context_sha256,
                "implementation_commit": evidence.implementation_commit,
                "active_module_sources_sha256": evidence.active_module_sources_sha256,
                "dependency_lock_sha256": evidence.dependency_lock_sha256,
                "runtime_fingerprint_sha256": evidence.runtime_fingerprint_sha256,
            }
        )
    )


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
    values = []
    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise GateBExecutionEnvironmentFailure("installed distribution lacks a name")
        name = _normalize_distribution_name(raw_name)
        if name != local_name:
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


def _verify_dependency_lock_unchecked(root: Path, context: GateBExecutionContext) -> str:
    lock_ref = context.payload["dependency_lock"]
    path = Path(lock_ref["absolute_path"])
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
    try:
        installed_version = importlib.metadata.version(project["name"])
    except importlib.metadata.PackageNotFoundError as exc:
        raise GateBExecutionEnvironmentFailure("locked project is not installed") from exc
    if installed_version != project["version"]:
        raise GateBExecutionEnvironmentFailure("locked project version mismatch")
    distributions = lock["distributions"]
    if not isinstance(distributions, list):
        raise GateBExecutionEnvironmentFailure("locked distribution inventory is invalid")
    for entry in distributions:
        _closed(entry, {"name", "version"}, "locked distribution")
        _ascii(entry["name"], "locked distribution name")
        _ascii(entry["version"], "locked distribution version")
    if distributions != _installed_distributions(project["name"]):
        raise GateBExecutionEnvironmentFailure("installed distribution inventory drifted")
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
    relative_fields = ("pyvenv_cfg_path", "site_packages_path", "venv_executable_path")
    resolved = {}
    for name in relative_fields:
        relative = _canonical_repository_relative_path(python[name], f"locked {name}")
        target = (root / relative).resolve()
        if root not in target.parents:
            raise GateBExecutionEnvironmentFailure("locked path escapes repository")
        resolved[name] = target
    base_executable_text = python["base_executable_path"]
    if not isinstance(base_executable_text, str) or not base_executable_text:
        raise GateBExecutionEnvironmentFailure("locked base executable path is invalid")
    locked_base_executable = Path(base_executable_text)
    if (
        not locked_base_executable.is_absolute()
        or str(locked_base_executable.resolve()) != base_executable_text
    ):
        raise GateBExecutionEnvironmentFailure("locked base executable path is not canonical")
    executable = Path(sys.executable).resolve()
    base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    purelib = Path(sysconfig.get_path("purelib")).resolve()
    pyvenv = (Path(sys.prefix) / "pyvenv.cfg").resolve()
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
        executable != resolved["venv_executable_path"]
        or purelib != resolved["site_packages_path"]
        or pyvenv != resolved["pyvenv_cfg_path"]
        or base_executable != locked_base_executable
        or executable_hash != python["venv_executable_sha256"]
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
    return store.append_started(request, reservation)


@_sanitized_api
def reserve_gate_b_attempt(
    request: GateBLoaderRequest, *, expected_latest_record_sha256: str | None
) -> GateBAttemptReservation:
    """Create the one durable reservation path before any Test-child open."""
    return _reserve_attempt(request, expected_latest_record_sha256=expected_latest_record_sha256)


@dataclass(slots=True)
class PreparedGateBTestOpen:
    """Opaque single-use lock-held preparation with no Test-child side effect."""

    request: GateBLoaderRequest = field(repr=False)
    reservation: GateBAttemptReservation = field(repr=False)
    _store: GateBLedgerStore = field(repr=False)
    _lock: Any = field(repr=False)
    _root_descriptors: dict[str, int] = field(repr=False)
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
    try:
        for role in ("ledger_base", "quarantine_base", "test_root"):
            _ref, root = _validate_root_ref(_plain(request.roots[role]), role)
            descriptor = _open_directory_descriptor(root)
            metadata = os.fstat(descriptor)
            if (
                format(metadata.st_ino, "x") != request.roots[role]["file_id_hex"]
                or format(metadata.st_dev, "x") != request.roots[role]["volume_id_hex"]
            ):
                os.close(descriptor)
                _fail("prepared root handle identity mismatch")
            root_descriptors[role] = descriptor
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
    return PreparedGateBTestOpen(request, reservation, store, lock, root_descriptors)


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


@_sanitized_api
def open_gate_b_test_input(
    prepared: PreparedGateBTestOpen, *, executor: GateBApprovedExecutor
) -> GateBExecutionReceipt:
    """Run one approved callback and return only a sanitized sealed receipt."""
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
            evidence = verify_gate_b_execution_environment(request, request.execution_context)
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
            test_root = Path(request.roots["test_root"]["absolute_path"])
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
            test_root = Path(request.roots["test_root"]["absolute_path"])
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
