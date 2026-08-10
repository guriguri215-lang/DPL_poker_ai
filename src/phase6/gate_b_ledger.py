"""Durable Gate B attempt ledger and quarantine topology.

The implementation is a fail-closed research governance boundary, not a
security sandbox against a host administrator or malicious in-process code.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import stat
import threading
import weakref
from collections.abc import Mapping
from contextlib import AbstractContextManager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol

from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACCESS_LOG_ENTRY_SCHEMA_VERSION,
    ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION,
    QUARANTINE_MANIFEST_SCHEMA_VERSION,
    QUARANTINE_OUTPUT_NAMES,
    ROOT_ANCHOR_SCHEMA_VERSION,
    ZERO_SHA256,
    GateBBatchManifest,
    GateBReadinessAuthorization,
    is_gate_b_v2_compatibility_object,
    load_gate_b_release_authorization,
    load_gate_b_retry_authorization,
)

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_ATOM_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_HEX_RE = re.compile(r"(?:0|[1-9a-f][0-9a-f]*)\Z")
_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_RECORD_RE = re.compile(r"record-(\d{6})\.json\Z")
_WINDOWS_VOLUME_GUID_RE = re.compile(r"\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\")
_PINNED_ARTIFACT_LOADER_TOKEN = object()
_OUTPUT_PATHS = MappingProxyType(
    {
        "stdout": "stdout.txt",
        "stderr": "stderr.txt",
        "progress": "progress.jsonl",
        "metrics": "metrics.json",
        "log": "log.jsonl",
        "result": "result.json",
        "access_log": "access-log.jsonl",
    }
)
_WRITABLE_OUTPUTS = ("stdout", "stderr", "progress", "metrics", "log", "result")
_ACCESS_EVENTS = {
    "environment_verified",
    "environment_verification_failed",
    "test_input_prestart_failed",
    "started_appended",
    "started_append_failed",
    "test_input_verified",
    "test_input_poststart_failed",
    "input_read",
    "input_eof",
    "output_write",
    "capabilities_closed",
    "executor_returned",
    "executor_failed",
    "seal_started",
    "failure_seal_started",
}
_FAILURE_EVENT_BINDINGS = {
    "environment_verification_failed": ("execution_environment_failure", "RESERVED"),
    "test_input_prestart_failed": ("test_input_prestart_failure", "RESERVED"),
    "started_append_failed": ("started_append_failure", "RESERVED"),
    "test_input_poststart_failed": ("test_input_poststart_failure", "STARTED"),
    "executor_failed": ("executor_callback_failure", "STARTED"),
}


class GateBLedgerError(RuntimeError):
    """Sanitized failure for ledger, quarantine, or topology rejection."""


def _reject_v2_request(request: object) -> None:
    if is_gate_b_v2_compatibility_object(request):
        _fail("legacy Gate B consumer rejects v2 compatibility objects")


def _sanitized_api(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        error_message: str | None = None
        try:
            for value in (*args, *kwargs.values()):
                _reject_v2_request(value)
            return function(*args, **kwargs)
        except GateBLedgerError as exc:
            error_message = str(exc)
        except Exception:
            error_message = "Gate B ledger operation failed closed"
        error = GateBLedgerError(error_message)
        error.__cause__ = None
        error.__context__ = None
        error.__traceback__ = None
        raise error

    return wrapped


class GateBRequestLike(Protocol):
    batch: GateBBatchManifest
    readiness: GateBReadinessAuthorization
    roots: Mapping[str, Mapping[str, Any]]
    actor_id: str
    attempt_ordinal: int


def _fail(message: str) -> None:
    raise GateBLedgerError(message)


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
        raise GateBLedgerError(f"{label} is not strict canonical JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise GateBLedgerError(f"{label} is not canonical JSON") from exc
    if canonical != raw:
        _fail(f"{label} bytes are not canonical")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _atom(value: object, label: str) -> str:
    if not isinstance(value, str) or _ATOM_RE.fullmatch(value) is None:
        _fail(f"{label} is not a canonical identifier")
    return value


def _canonical_reason_detail_sha256(reason_id: str) -> str:
    return sha256_bytes(canonical_json_bytes({"reason_id": _atom(reason_id, "reason ID")}))


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < (1 << 63):
        _fail(f"{label} must be a positive integer")
    return value


def _six_digit_positive(value: object, label: str) -> int:
    result = _positive(value, label)
    if result > 999999:
        _fail(f"{label} exceeds the six-digit physical namespace")
    return result


def _closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} fields are not closed-world")
    return value


def _now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        _fail(f"{label} timestamp is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GateBLedgerError(f"{label} timestamp is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} timestamp is not canonical")
    return value


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


@dataclass(frozen=True, slots=True)
class _PlatformContract:
    name: str
    regular_open_primitive: str
    directory_open_primitive: str
    lock_primitive: str
    file_flush_primitive: str
    parent_durability_primitive: str


def _platform_contract(name: str) -> _PlatformContract:
    if name == "posix":
        return _PlatformContract(
            "posix",
            "openat+O_NOFOLLOW",
            "openat+O_DIRECTORY+O_NOFOLLOW",
            "flock(LOCK_EX)",
            "fsync(file)",
            "fsync(parent-directory)",
        )
    if name == "nt":
        return _PlatformContract(
            "windows",
            "CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)",
            ("CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS)"),
            "LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)",
            "FlushFileBuffers",
            "pinned-parent-name-identity-verification",
        )
    raise GateBLedgerError("unsupported platform primitives fail closed")


def _capability_result(*, applicable: bool, supported: bool, privileged: bool) -> str:
    if not applicable:
        return "platform_not_applicable"
    if not supported:
        return "unsupported_by_host_fs"
    if not privileged:
        return "insufficient_privilege"
    return "available"


def _required_posix_flag(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"required POSIX {name} is unavailable")
    return value


def _required_posix_nofollow(value: object) -> int:
    return _required_posix_flag(value, "O_NOFOLLOW")


def _posix_openat_adapter(
    open_function,
    name: str,
    flags: int,
    mode: int,
    parent_descriptor: int,
    *,
    nofollow_flag: int | None = None,
) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None) if nofollow_flag is None else nofollow_flag
    nofollow = _required_posix_nofollow(nofollow)
    return open_function(
        name,
        flags | nofollow,
        mode,
        dir_fd=parent_descriptor,
    )


def _posix_open_directory(path: Path) -> int:
    contract = _platform_contract("posix")
    del contract
    directory_flag = _required_posix_flag(
        getattr(os, "O_DIRECTORY", None),
        "O_DIRECTORY",
    )
    nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
    if os.open not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX openat primitive is unavailable")
    parts = path.parts
    if not path.is_absolute() or not parts:
        _fail("POSIX pinned directory path must be absolute")
    descriptor = os.open(path.anchor, os.O_RDONLY | directory_flag)
    try:
        for part in parts[1:]:
            child = _posix_openat_adapter(
                os.open,
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


def _posix_open_direct(path: Path, flags: int, mode: int = 0o600) -> int:
    _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
    if os.open not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX openat primitive is unavailable")
    parent = _posix_open_directory(path.parent)
    try:
        return _posix_openat_adapter(os.open, path.name, flags, mode, parent)
    finally:
        os.close(parent)


def _mkdir_direct(path: Path) -> None:
    if os.name == "nt":
        os.mkdir(path)
        _windows_probe_directory(path)
        return
    if os.mkdir not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX mkdirat primitive is unavailable")
    parent = _posix_open_directory(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _mkdir_at(
    parent_descriptor: int,
    parent_path: Path,
    name: str,
) -> Path:
    name = _direct_child_name(name, "exclusive directory")
    path = parent_path / name
    if os.name == "nt":
        os.mkdir(path)
        _windows_probe_directory(path)
        return path
    if os.mkdir not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX mkdirat primitive is unavailable")
    os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)
    return path


def _windows_create_file_descriptor(
    path: Path,
    *,
    access: int,
    creation: int,
    share: int,
    directory: bool = False,
    _kernel32=None,
    _open_osfhandle=None,
) -> int:
    _platform_contract("nt")
    if _kernel32 is None or _open_osfhandle is None:
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_osfhandle = msvcrt.open_osfhandle
    else:
        kernel32 = _kernel32
        open_osfhandle = _open_osfhandle
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
    attributes = 0x00200000
    if directory:
        attributes |= 0x02000000
    else:
        attributes |= 0x00000080
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
    flags |= os.O_RDONLY if access in {0, 0x80000000} else os.O_RDWR
    try:
        return open_osfhandle(handle, flags)
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
    _platform_contract("posix")
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


def _open_new_descriptor(path: Path) -> int:
    if os.name == "nt":
        return _windows_create_file_descriptor(
            path,
            access=0xC0000000,
            creation=1,
            share=0,
        )
    _platform_contract("posix")
    return _posix_open_direct(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)


def _create_lock_descriptor(path: Path) -> int:
    if os.name == "nt":
        return _windows_create_file_descriptor(
            path,
            access=0xC0000000,
            creation=1,
            share=0,
        )
    _platform_contract("posix")
    return _posix_open_direct(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)


def _open_lock_descriptor(path: Path) -> int:
    if os.name == "nt":
        return _windows_create_file_descriptor(
            path,
            access=0xC0000000,
            creation=3,
            share=3,
        )
    _platform_contract("posix")
    return _posix_open_direct(path, os.O_RDWR)


def _windows_probe_directory(path: Path) -> os.stat_result:
    descriptor = _windows_create_file_descriptor(
        path,
        access=0x80000000,
        creation=3,
        share=7,
        directory=True,
    )
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def _verify_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = _lstat(path)
    except OSError as exc:
        raise GateBLedgerError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
        _fail(f"{label} must be a physical directory")
    if os.name == "nt":
        try:
            opened = _windows_probe_directory(path)
        except OSError as exc:
            raise GateBLedgerError(f"{label} cannot be handle-pinned") from exc
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _reparse(opened)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            _fail(f"{label} handle identity or reparse state mismatch")
    return metadata


def _windows_stream_names(
    path: Path,
    *,
    _kernel32=None,
    _get_last_error=None,
) -> tuple[str, ...]:
    if os.name != "nt" and _kernel32 is None:
        return ("::$DATA",)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if _kernel32 is None else _kernel32
    get_last_error = ctypes.get_last_error if _get_last_error is None else _get_last_error

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
        error = get_last_error()
        if error not in {0, 38}:
            raise GateBLedgerError("required stream enumeration failed closed")
    finally:
        find_close(handle)
    return tuple(names)


def _verify_regular(path: Path, label: str, *, expected_size: int | None = None) -> os.stat_result:
    try:
        metadata = _lstat(path)
    except OSError as exc:
        raise GateBLedgerError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
        or metadata.st_nlink != 1
    ):
        _fail(f"{label} must be a single-link physical regular file")
    if expected_size is not None and metadata.st_size != expected_size:
        _fail(f"{label} size mismatch")
    if _windows_stream_names(path) != ("::$DATA",):
        _fail(f"{label} has an alternate data stream")
    return metadata


def _read_pinned(path: Path, label: str) -> bytes:
    before = _verify_regular(path, label)
    try:
        descriptor = _open_existing_descriptor(path)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                _fail(f"{label} identity changed before read")
            chunks = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
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
        _fail(f"{label} identity changed while reading")
    return b"".join(chunks)


def _direct_child_name(name: str, label: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or not name.isascii()
        or any(not 0x20 <= ord(character) <= 0x7E for character in name)
        or "/" in name
        or "\\" in name
        or ":" in name
        or name in {".", ".."}
    ):
        _fail(f"{label} is not a canonical direct-child name")
    return name


def _read_pinned_at(
    directory_descriptor: int,
    directory_path: Path,
    name: str,
    label: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> bytes:
    name = _direct_child_name(name, label)
    path = directory_path / name
    if os.name == "nt":
        before = _verify_regular(path, label)
        descriptor = _open_existing_descriptor(path)
    else:
        nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
        if os.open not in getattr(os, "supports_dir_fd", set()) or os.stat not in getattr(
            os, "supports_dir_fd", set()
        ):
            _fail("required POSIX pinned-child primitive is unavailable")
        before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
            _fail(f"{label} must be a single-link physical regular file")
        if expected_identity is not None and (before.st_dev, before.st_ino) != expected_identity:
            _fail(f"{label} stored identity changed before reopen")
        descriptor = os.open(
            name,
            os.O_RDONLY | nofollow,
            dir_fd=directory_descriptor,
        )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_nlink != 1
            or _reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (
                expected_identity is not None
                and (opened.st_dev, opened.st_ino) != expected_identity
            )
        ):
            _fail(f"{label} identity changed before read")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    if os.name == "nt":
        after = _verify_regular(path, label)
    else:
        after = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(after.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or after.st_nlink != 1
            or _reparse(after)
        ):
            _fail(f"{label} topology changed while reading")
    if (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        _fail(f"{label} identity changed while reading")
    if expected_identity is not None and (after.st_dev, after.st_ino) != expected_identity:
        _fail(f"{label} stored identity changed while reading")
    return b"".join(chunks)


def _directory_names_at(directory_descriptor: int, directory_path: Path) -> set[str]:
    if os.name == "nt":
        return {entry.name for entry in directory_path.iterdir()}
    return set(os.listdir(directory_descriptor))


def _open_pinned_directory(
    path: Path,
    expected_identity: tuple[int, int],
    label: str,
) -> int:
    before = _verify_directory(path, label)
    if (before.st_dev, before.st_ino) != expected_identity:
        _fail(f"{label} identity changed")
    descriptor = _open_directory_descriptor(path)
    try:
        opened = os.fstat(descriptor)
        after = _verify_directory(path, label)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _reparse(opened)
            or (opened.st_dev, opened.st_ino) != expected_identity
            or (after.st_dev, after.st_ino) != expected_identity
        ):
            _fail(f"{label} pinned identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_at(
    parent_descriptor: int,
    parent_path: Path,
    name: str,
    label: str,
) -> int:
    name = _direct_child_name(name, label)
    path = parent_path / name
    try:
        if os.name == "nt":
            descriptor = _open_directory_descriptor(path)
        else:
            directory_flag = _required_posix_flag(
                getattr(os, "O_DIRECTORY", None),
                "O_DIRECTORY",
            )
            descriptor = _posix_openat_adapter(
                os.open,
                name,
                os.O_RDONLY | directory_flag,
                0o600,
                parent_descriptor,
            )
    except OSError as exc:
        raise GateBLedgerError(f"{label} is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(opened.st_mode) or _reparse(opened):
            _fail(f"{label} must be a physical directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_directory_entry_identity(
    parent_descriptor: int,
    parent_path: Path,
    name: str,
    expected_identity: tuple[int, int],
    label: str,
) -> None:
    descriptor = _open_directory_at(parent_descriptor, parent_path, name, label)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != expected_identity:
            _fail(f"{label} identity changed")
    finally:
        os.close(descriptor)


def _verify_pinned_root_descriptor(
    ref: Mapping[str, Any],
    expected_role: str,
    descriptor: int,
) -> tuple[Path, tuple[int, int]]:
    path = _verify_root_ref(ref, expected_role)
    expected_identity = (
        int(ref["volume_id_hex"], 16),
        int(ref["file_id_hex"], 16),
    )
    opened = os.fstat(descriptor)
    named = _verify_directory(path, f"{expected_role} root")
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(opened.st_mode)
        or _reparse(opened)
        or (opened.st_dev, opened.st_ino) != expected_identity
        or (named.st_dev, named.st_ino) != expected_identity
    ):
        _fail(f"{expected_role} pinned root identity changed")
    return path, expected_identity


def _regular_metadata_at(
    directory_descriptor: int,
    directory_path: Path,
    name: str,
    label: str,
) -> os.stat_result:
    name = _direct_child_name(name, label)
    if os.name == "nt":
        return _verify_regular(directory_path / name, label)
    if os.stat not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX pinned-child stat primitive is unavailable")
    metadata = os.stat(
        name,
        dir_fd=directory_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or _reparse(metadata)
    ):
        _fail(f"{label} must be a single-link physical regular file")
    return metadata


def _open_new_at(directory_descriptor: int, directory_path: Path, name: str) -> int:
    name = _direct_child_name(name, "exclusive artifact")
    if os.name == "nt":
        return _open_new_descriptor(directory_path / name)
    nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
    if os.open not in getattr(os, "supports_dir_fd", set()):
        _fail("required POSIX exclusive openat primitive is unavailable")
    return os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
        0o600,
        dir_fd=directory_descriptor,
    )


def _durable_descriptor_write(
    descriptor: int,
    raw: bytes,
    *,
    write_all_function=None,
    flush_function=None,
) -> None:
    writer = _write_all if write_all_function is None else write_all_function
    flusher = os.fsync if flush_function is None else flush_function
    writer(descriptor, raw)
    flusher(descriptor)


def _write_exclusive_at(
    directory_descriptor: int,
    directory_path: Path,
    name: str,
    raw: bytes,
) -> Path:
    descriptor = _open_new_at(directory_descriptor, directory_path, name)
    try:
        _durable_descriptor_write(descriptor, raw)
    finally:
        os.close(descriptor)
    if os.name == "nt":
        directory_after = _verify_directory(directory_path, "durable artifact parent")
        opened = os.fstat(directory_descriptor)
        if (directory_after.st_dev, directory_after.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            _fail("durable artifact parent identity changed")
    else:
        os.fsync(directory_descriptor)
    reread = _read_pinned_at(
        directory_descriptor,
        directory_path,
        name,
        "durable artifact",
    )
    if reread != raw:
        _fail("durable artifact bytes changed after creation")
    return directory_path / name


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        _verify_directory(path.parent, "pinned parent")
        return
    descriptor = _posix_open_directory(path.parent)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            _fail("durable write did not make progress")
        view = view[written:]


def _pinned_child_name(name: object) -> str:
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 255
        or not name.isascii()
        or any(not 0x20 <= ord(character) <= 0x7E for character in name)
        or any(character in '/\\:*?<>|"' for character in name)
        or name in {".", ".."}
        or name.endswith((".", " "))
    ):
        _fail("pinned artifact name is not a canonical direct-child name")
    stem = name.split(".", 1)[0].upper()
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update(f"COM{index}" for index in range(1, 10))
    reserved.update(f"LPT{index}" for index in range(1, 10))
    if stem in reserved:
        _fail("pinned artifact name uses a reserved device stem")
    return name


def _pinned_hex_identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        _fail(f"{label} must be lowercase unprefixed hexadecimal")
    return value


def _pinned_size(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 63):
        _fail(f"{label} must be a nonnegative integer")
    return value


def _regular_pinned_metadata(metadata: os.stat_result, label: str) -> os.stat_result:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
        or metadata.st_nlink != 1
    ):
        _fail(f"{label} must be a single-link physical regular file")
    return metadata


def _directory_pinned_metadata(metadata: os.stat_result, label: str) -> os.stat_result:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
        _fail(f"{label} must be a physical non-reparse directory")
    return metadata


def _read_all_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _windows_final_path_from_descriptor(
    descriptor: int,
    *,
    _kernel32=None,
    _get_osfhandle=None,
) -> str:
    if os.name != "nt" and (_kernel32 is None or _get_osfhandle is None):
        _fail("Windows final-path primitive is unavailable")
    if _kernel32 is None or _get_osfhandle is None:
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_osfhandle = msvcrt.get_osfhandle
    else:
        kernel32 = _kernel32
        get_osfhandle = _get_osfhandle
    function = kernel32.GetFinalPathNameByHandleW
    function.argtypes = (
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    function.restype = ctypes.c_uint32
    handle = get_osfhandle(descriptor)
    flags = 0x00000001
    required = function(ctypes.c_void_p(handle), None, 0, flags)
    if required == 0:
        raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = function(ctypes.c_void_p(handle), buffer, len(buffer), flags)
    if written == 0 or written >= len(buffer):
        raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
    final_path = buffer.value
    if (
        _WINDOWS_VOLUME_GUID_RE.match(final_path) is None
        or final_path.startswith("\\\\?\\UNC\\")
        or final_path.startswith("\\\\.\\")
        or "GLOBALROOT" in final_path.upper()
    ):
        _fail("stable Windows Volume-GUID namespace is unavailable")
    return final_path


def _windows_v2_identity_from_descriptor(
    descriptor: int,
    *,
    _kernel32=None,
    _get_osfhandle=None,
) -> tuple[int, int]:
    """Read the native 32-bit volume serial and 64-bit file ID from a handle."""
    if os.name != "nt" and (_kernel32 is None or _get_osfhandle is None):
        _fail("v2 Windows identity primitive is unavailable")
    if _kernel32 is None or _get_osfhandle is None:
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_osfhandle = msvcrt.get_osfhandle
    else:
        kernel32 = _kernel32
        get_osfhandle = _get_osfhandle

    class FileTime(ctypes.Structure):
        _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("file_attributes", ctypes.c_uint32),
            ("creation_time", FileTime),
            ("last_access_time", FileTime),
            ("last_write_time", FileTime),
            ("volume_serial_number", ctypes.c_uint32),
            ("file_size_high", ctypes.c_uint32),
            ("file_size_low", ctypes.c_uint32),
            ("number_of_links", ctypes.c_uint32),
            ("file_index_high", ctypes.c_uint32),
            ("file_index_low", ctypes.c_uint32),
        )

    function = kernel32.GetFileInformationByHandle
    function.argtypes = (ctypes.c_void_p, ctypes.POINTER(ByHandleFileInformation))
    function.restype = ctypes.c_int
    information = ByHandleFileInformation()
    handle = get_osfhandle(descriptor)
    if not function(ctypes.c_void_p(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    identity = (
        int(information.volume_serial_number),
        (int(information.file_index_high) << 32) | int(information.file_index_low),
    )
    if identity[0] == 0 or identity[1] == 0:
        _fail("v2 Windows retained identity is zero")
    return identity


def _windows_volume_guid_root(final_path: str) -> str:
    match = _WINDOWS_VOLUME_GUID_RE.match(final_path)
    if match is None:
        _fail("stable Windows Volume-GUID namespace is unavailable")
    return match.group(0)


def _windows_reject_network_volume(volume_root: str, *, _kernel32=None) -> None:
    if os.name != "nt" and _kernel32 is None:
        _fail("Windows volume classification primitive is unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if _kernel32 is None else _kernel32
    function = kernel32.GetDriveTypeW
    function.argtypes = (ctypes.c_wchar_p,)
    function.restype = ctypes.c_uint32
    drive_type = function(volume_root)
    if drive_type in {0, 1, 4, 5}:
        _fail("network or unsupported Windows volume is not permitted")


@dataclass(frozen=True, slots=True)
class _PinnedWindowsDirectoryHandle:
    descriptor: int
    physical_identity: tuple[int, int]
    final_path: str


def _open_windows_pinned_chain(
    path: Path,
    expected_identity: tuple[int, int],
) -> tuple[_PinnedWindowsDirectoryHandle, ...]:
    text = str(path)
    if (
        not path.is_absolute()
        or path.drive == ""
        or path.drive.startswith("\\")
        or text.startswith(("\\\\", "\\\\?\\", "\\\\.\\"))
    ):
        _fail("Windows pinned directory requires a canonical local DOS-drive path")
    parts = path.parts
    if not parts:
        _fail("Windows pinned directory path is invalid")
    cumulative = Path(parts[0])
    opened: list[_PinnedWindowsDirectoryHandle] = []
    try:
        for part in (None, *parts[1:]):
            if part is not None:
                cumulative = cumulative / part
            descriptor = _windows_create_file_descriptor(
                cumulative,
                access=0,
                creation=3,
                share=3,
                directory=True,
            )
            try:
                metadata = _directory_pinned_metadata(
                    os.fstat(descriptor), "Windows pinned directory component"
                )
                final_path = _windows_final_path_from_descriptor(descriptor)
                identity = (metadata.st_dev, metadata.st_ino)
                if opened:
                    parent_prefix = opened[-1].final_path.rstrip("\\") + "\\"
                    if not final_path.casefold().startswith(parent_prefix.casefold()):
                        _fail("Windows pinned ancestor chain is inconsistent")
                opened.append(
                    _PinnedWindowsDirectoryHandle(
                        descriptor=descriptor,
                        physical_identity=identity,
                        final_path=final_path,
                    )
                )
            except BaseException:
                os.close(descriptor)
                raise
        target = opened[-1]
        if target.physical_identity != expected_identity:
            _fail("Windows pinned target identity mismatch")
        _windows_reject_network_volume(_windows_volume_guid_root(target.final_path))
        return tuple(opened)
    except BaseException:
        for item in reversed(opened):
            with suppress(OSError):
                os.close(item.descriptor)
        raise


def _verify_windows_pinned_chain(
    chain: tuple[_PinnedWindowsDirectoryHandle, ...],
) -> None:
    if not chain:
        _fail("Windows pinned ancestor chain is unavailable")
    for index, retained in enumerate(chain):
        metadata = _directory_pinned_metadata(
            os.fstat(retained.descriptor), "Windows retained directory"
        )
        if (metadata.st_dev, metadata.st_ino) != retained.physical_identity:
            _fail("Windows retained directory identity changed")
        if (
            _windows_final_path_from_descriptor(retained.descriptor).casefold()
            != retained.final_path.casefold()
        ):
            _fail("Windows retained directory final path changed")
        descriptor = _windows_create_file_descriptor(
            Path(retained.final_path),
            access=0,
            creation=3,
            share=3,
            directory=True,
        )
        try:
            reopened = _directory_pinned_metadata(
                os.fstat(descriptor), "Windows named retained directory"
            )
            if (reopened.st_dev, reopened.st_ino) != retained.physical_identity:
                _fail("Windows named retained directory identity changed")
            reopened_final = _windows_final_path_from_descriptor(descriptor)
            if reopened_final.casefold() != retained.final_path.casefold():
                _fail("Windows named retained directory final path changed")
        finally:
            os.close(descriptor)
        if index:
            parent_prefix = chain[index - 1].final_path.rstrip("\\") + "\\"
            if not retained.final_path.casefold().startswith(parent_prefix.casefold()):
                _fail("Windows retained ancestor topology changed")


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class GateBPinnedArtifact:
    """Immutable bytes and physical identity from a pinned child operation."""

    _raw: bytes = field(repr=False)
    _sha256: str
    _size_bytes: int
    _volume_id_hex: str
    _file_id_hex: str
    _loader_token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBPinnedArtifact:
        if _token is not _PINNED_ARTIFACT_LOADER_TOKEN:
            raise TypeError("pinned artifact construction is private")
        return object.__new__(cls)

    @property
    def raw(self) -> bytes:
        return _validated_pinned_artifact_snapshot(self)[0]

    @property
    def sha256(self) -> str:
        return _validated_pinned_artifact_snapshot(self)[1]

    @property
    def size_bytes(self) -> int:
        return _validated_pinned_artifact_snapshot(self)[2]

    @property
    def volume_id_hex(self) -> str:
        return _validated_pinned_artifact_snapshot(self)[3]

    @property
    def file_id_hex(self) -> str:
        return _validated_pinned_artifact_snapshot(self)[4]

    @property
    def physical_identity(self) -> tuple[str, str]:
        snapshot = _validated_pinned_artifact_snapshot(self)
        return snapshot[3], snapshot[4]

    def __eq__(self, other: object) -> bool:
        if type(other) is not GateBPinnedArtifact:
            return NotImplemented
        return _validated_pinned_artifact_snapshot(self) == _validated_pinned_artifact_snapshot(
            other
        )


_PinnedArtifactSnapshot = tuple[bytes, str, int, str, str]
_PINNED_ARTIFACT_REGISTRY: dict[
    int,
    tuple[weakref.ReferenceType[GateBPinnedArtifact], _PinnedArtifactSnapshot],
] = {}
_PINNED_ARTIFACT_REGISTRY_LOCK = threading.Lock()


def _drop_pinned_artifact_registration(
    artifact_id: int,
    reference: weakref.ReferenceType[GateBPinnedArtifact],
) -> None:
    with _PINNED_ARTIFACT_REGISTRY_LOCK:
        registered = _PINNED_ARTIFACT_REGISTRY.get(artifact_id)
        if registered is not None and registered[0] is reference:
            _PINNED_ARTIFACT_REGISTRY.pop(artifact_id, None)


def _validated_pinned_artifact_snapshot(
    artifact: GateBPinnedArtifact,
) -> tuple[bytes, str, int, str, str]:
    with _PINNED_ARTIFACT_REGISTRY_LOCK:
        registered = _PINNED_ARTIFACT_REGISTRY.get(id(artifact))
    try:
        current = (
            object.__getattribute__(artifact, "_raw"),
            object.__getattribute__(artifact, "_sha256"),
            object.__getattribute__(artifact, "_size_bytes"),
            object.__getattribute__(artifact, "_volume_id_hex"),
            object.__getattribute__(artifact, "_file_id_hex"),
        )
        loader_token = object.__getattribute__(artifact, "_loader_token")
    except (AttributeError, TypeError):
        _fail("pinned artifact loader provenance mismatch")
    if (
        registered is None
        or registered[0]() is not artifact
        or loader_token is not _PINNED_ARTIFACT_LOADER_TOKEN
        or type(current[0]) is not bytes
        or type(current[1]) is not str
        or type(current[2]) is not int
        or type(current[3]) is not str
        or type(current[4]) is not str
        or sha256_bytes(current[0]) != current[1]
        or len(current[0]) != current[2]
        or _HEX_RE.fullmatch(current[3]) is None
        or _HEX_RE.fullmatch(current[4]) is None
        or current != registered[1]
    ):
        _fail("pinned artifact loader provenance mismatch")
    return current


def _new_pinned_artifact(raw: bytes, metadata: os.stat_result) -> GateBPinnedArtifact:
    artifact = object.__new__(GateBPinnedArtifact)
    digest = sha256_bytes(raw)
    volume_id = format(metadata.st_dev, "x")
    file_id = format(metadata.st_ino, "x")
    object.__setattr__(artifact, "_raw", bytes(raw))
    object.__setattr__(artifact, "_sha256", digest)
    object.__setattr__(artifact, "_size_bytes", len(raw))
    object.__setattr__(artifact, "_volume_id_hex", volume_id)
    object.__setattr__(artifact, "_file_id_hex", file_id)
    object.__setattr__(artifact, "_loader_token", _PINNED_ARTIFACT_LOADER_TOKEN)
    artifact_id = id(artifact)
    snapshot = (memoryview(raw).tobytes(), digest, len(raw), volume_id, file_id)
    reference = weakref.ref(
        artifact,
        lambda observed: _drop_pinned_artifact_registration(artifact_id, observed),
    )
    with _PINNED_ARTIFACT_REGISTRY_LOCK:
        if artifact_id in _PINNED_ARTIFACT_REGISTRY:
            _fail("pinned artifact loader provenance identity collision")
        _PINNED_ARTIFACT_REGISTRY[artifact_id] = (reference, snapshot)
    return artifact


class GateBPinnedDirectory:
    """Retained-parent direct-child I/O with fail-closed physical identity."""

    __slots__ = (
        "_path",
        "_stable_path",
        "_descriptor",
        "_expected_identity",
        "_windows_chain",
        "_closed",
    )

    def __init__(
        self,
        path: Path,
        stable_path: Path,
        descriptor: int,
        expected_identity: tuple[int, int],
        windows_chain: tuple[_PinnedWindowsDirectoryHandle, ...],
        *,
        _token: object,
    ) -> None:
        if _token is not _PINNED_ARTIFACT_LOADER_TOKEN:
            _fail("pinned directory construction is private")
        self._path = path
        self._stable_path = stable_path
        self._descriptor = descriptor
        self._expected_identity = expected_identity
        self._windows_chain = windows_chain
        self._closed = False

    @classmethod
    @_sanitized_api
    def open(
        cls,
        absolute_path: Path | str,
        *,
        expected_volume_id_hex: str,
        expected_file_id_hex: str,
    ) -> GateBPinnedDirectory:
        volume_id = _pinned_hex_identity(expected_volume_id_hex, "pinned target volume ID")
        file_id = _pinned_hex_identity(expected_file_id_hex, "pinned target file ID")
        expected_identity = (int(volume_id, 16), int(file_id, 16))
        path = Path(absolute_path)
        if not path.is_absolute():
            _fail("pinned directory path must be absolute")
        if os.name == "nt":
            chain = _open_windows_pinned_chain(path, expected_identity)
            target = chain[-1]
            instance = cls(
                path,
                Path(target.final_path),
                target.descriptor,
                expected_identity,
                chain,
                _token=_PINNED_ARTIFACT_LOADER_TOKEN,
            )
        elif os.name == "posix":
            descriptor = _posix_open_directory(path)
            try:
                metadata = _directory_pinned_metadata(
                    os.fstat(descriptor), "POSIX pinned directory"
                )
                if (metadata.st_dev, metadata.st_ino) != expected_identity:
                    _fail("POSIX pinned target identity mismatch")
                instance = cls(
                    path,
                    path,
                    descriptor,
                    expected_identity,
                    (),
                    _token=_PINNED_ARTIFACT_LOADER_TOKEN,
                )
            except BaseException:
                os.close(descriptor)
                raise
        else:
            _fail("unsupported pinned-directory platform")
        try:
            instance.verify_identity()
        except BaseException:
            with suppress(GateBLedgerError):
                instance.close()
            raise
        return instance

    def _ensure_open(self) -> None:
        if self._closed:
            _fail("pinned directory is closed")

    def _verify_identity_unwrapped(self) -> None:
        self._ensure_open()
        if os.name == "nt":
            _verify_windows_pinned_chain(self._windows_chain)
            if self._windows_chain[-1].physical_identity != self._expected_identity:
                _fail("Windows pinned target identity changed")
        else:
            metadata = _directory_pinned_metadata(
                os.fstat(self._descriptor), "POSIX pinned directory"
            )
            if (metadata.st_dev, metadata.st_ino) != self._expected_identity:
                _fail("POSIX pinned target identity changed")

    def _open_existing_child(self, name: str) -> int:
        if os.name == "nt":
            return _windows_create_file_descriptor(
                self._stable_path / name,
                access=0x80000000,
                creation=3,
                share=1,
            )
        nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
        if os.open not in getattr(os, "supports_dir_fd", set()):
            _fail("required POSIX pinned-child primitive is unavailable")
        return os.open(
            name,
            os.O_RDONLY | nofollow,
            dir_fd=self._descriptor,
        )

    def _open_new_child(self, name: str) -> int:
        if os.name == "nt":
            return _windows_create_file_descriptor(
                self._stable_path / name,
                access=0xC0000000,
                creation=1,
                share=0,
            )
        nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
        if os.open not in getattr(os, "supports_dir_fd", set()):
            _fail("required POSIX exclusive openat primitive is unavailable")
        return os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=self._descriptor,
        )

    def _verify_child_streams(self, name: str) -> None:
        if os.name == "nt" and _windows_stream_names(self._stable_path / name) != ("::$DATA",):
            _fail("pinned artifact has an alternate data stream")

    @_sanitized_api
    def read_regular(
        self,
        direct_child_name: str,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> GateBPinnedArtifact:
        self._ensure_open()
        name = _pinned_child_name(direct_child_name)
        expected_hash = _sha(expected_sha256, "pinned artifact expected hash")
        expected_size = _pinned_size(expected_size_bytes, "pinned artifact expected size")
        self._verify_identity_unwrapped()
        descriptor = self._open_existing_child(name)
        second: int | None = None
        try:
            before = _regular_pinned_metadata(os.fstat(descriptor), "pinned artifact")
            self._verify_child_streams(name)
            raw = _read_all_descriptor(descriptor)
            after = _regular_pinned_metadata(os.fstat(descriptor), "pinned artifact")
            if (
                (after.st_dev, after.st_ino, after.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
                or len(raw) != expected_size
                or before.st_size != expected_size
                or sha256_bytes(raw) != expected_hash
            ):
                _fail("pinned artifact size, hash, or identity mismatch")
            self._verify_identity_unwrapped()
            second = self._open_existing_child(name)
            reopened = _regular_pinned_metadata(os.fstat(second), "reopened pinned artifact")
            reread = _read_all_descriptor(second)
            if (
                (reopened.st_dev, reopened.st_ino) != (before.st_dev, before.st_ino)
                or reread != raw
                or sha256_bytes(reread) != expected_hash
            ):
                _fail("pinned artifact changed during reopen and rehash")
            self._verify_child_streams(name)
            self._verify_identity_unwrapped()
            return _new_pinned_artifact(raw, before)
        finally:
            if second is not None:
                os.close(second)
            os.close(descriptor)

    @_sanitized_api
    def create_regular(
        self,
        direct_child_name: str,
        raw: bytes,
    ) -> GateBPinnedArtifact:
        self._ensure_open()
        name = _pinned_child_name(direct_child_name)
        if type(raw) is not bytes:
            _fail("pinned artifact content must be bytes")
        self._verify_identity_unwrapped()
        descriptor = self._open_new_child(name)
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
            created = _regular_pinned_metadata(os.fstat(descriptor), "created pinned artifact")
            if created.st_size != len(raw):
                _fail("created pinned artifact size mismatch")
            self._verify_child_streams(name)
            self._verify_identity_unwrapped()
        finally:
            os.close(descriptor)
        if os.name == "posix":
            try:
                os.fsync(self._descriptor)
            except OSError as exc:
                raise GateBLedgerError("required POSIX parent-directory fsync failed") from exc
        else:
            self._verify_identity_unwrapped()
        reopened = self._open_existing_child(name)
        try:
            metadata = _regular_pinned_metadata(
                os.fstat(reopened), "reopened created pinned artifact"
            )
            reread = _read_all_descriptor(reopened)
            if (
                (metadata.st_dev, metadata.st_ino) != (created.st_dev, created.st_ino)
                or reread != raw
                or sha256_bytes(reread) != sha256_bytes(raw)
            ):
                _fail("created pinned artifact changed during durable reopen")
            self._verify_child_streams(name)
            self._verify_identity_unwrapped()
            return _new_pinned_artifact(raw, created)
        finally:
            os.close(reopened)

    @_sanitized_api
    def direct_child_names(self) -> tuple[str, ...]:
        self._ensure_open()
        self._verify_identity_unwrapped()
        try:
            if os.name == "nt":
                with os.scandir(self._stable_path) as entries:
                    names = [entry.name for entry in entries]
            else:
                names = list(os.listdir(self._descriptor))
        except OSError as exc:
            raise GateBLedgerError("pinned directory enumeration failed") from exc
        validated = tuple(sorted(_pinned_child_name(name) for name in names))
        self._verify_identity_unwrapped()
        return validated

    @_sanitized_api
    def verify_identity(self) -> None:
        self._verify_identity_unwrapped()

    @_sanitized_api
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[OSError] = []
        descriptors = (
            [item.descriptor for item in reversed(self._windows_chain)]
            if self._windows_chain
            else [self._descriptor]
        )
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise GateBLedgerError("pinned directory close failed") from errors[0]

    def __enter__(self) -> GateBPinnedDirectory:
        self._ensure_open()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> bool:
        self.close()
        return False


@_sanitized_api
def open_gate_b_v2_pinned_directory(
    absolute_path: Path | str,
    *,
    serialization_profile: str,
    expected_volume_id_hex: str,
    expected_file_id_hex: str,
) -> GateBPinnedDirectory:
    """Open one Windows root using the sole exact fixed-width v2 profile."""
    if serialization_profile != "windows-volume8-file16-lowerhex-v1":
        _fail("v2 pinned directory serialization profile mismatch")
    if (
        type(expected_volume_id_hex) is not str
        or re.fullmatch(r"[0-9a-f]{8}", expected_volume_id_hex) is None
        or int(expected_volume_id_hex, 16) == 0
        or type(expected_file_id_hex) is not str
        or re.fullmatch(r"[0-9a-f]{16}", expected_file_id_hex) is None
        or int(expected_file_id_hex, 16) == 0
    ):
        _fail("v2 pinned directory fixed-width identity mismatch")
    if os.name != "nt":
        _fail("v2 Windows pinned directory profile is unavailable")
    path = Path(absolute_path)
    if not path.is_absolute() or ".." in path.parts or str(path) != str(absolute_path):
        _fail("v2 pinned directory path must be canonical and absolute")
    named = _verify_directory(path, "v2 retained directory")
    retained_identity = (named.st_dev, named.st_ino)
    chain = _open_windows_pinned_chain(path, retained_identity)
    target = chain[-1]
    instance = GateBPinnedDirectory(
        path,
        Path(target.final_path),
        target.descriptor,
        retained_identity,
        chain,
        _token=_PINNED_ARTIFACT_LOADER_TOKEN,
    )
    try:
        verify_gate_b_v2_pinned_directory(
            instance,
            serialization_profile=serialization_profile,
            expected_volume_id_hex=expected_volume_id_hex,
            expected_file_id_hex=expected_file_id_hex,
        )
        return instance
    except BaseException:
        with suppress(Exception):
            instance.close()
        raise


@_sanitized_api
def verify_gate_b_v2_pinned_directory(
    directory: GateBPinnedDirectory,
    *,
    serialization_profile: str,
    expected_volume_id_hex: str,
    expected_file_id_hex: str,
) -> None:
    """Recheck one retained handle and exact-reserialize its native v2 identity."""
    if type(directory) is not GateBPinnedDirectory:
        _fail("v2 retained directory nominal type mismatch")
    if serialization_profile != "windows-volume8-file16-lowerhex-v1":
        _fail("v2 retained directory serialization profile mismatch")
    if (
        type(expected_volume_id_hex) is not str
        or re.fullmatch(r"[0-9a-f]{8}", expected_volume_id_hex) is None
        or int(expected_volume_id_hex, 16) == 0
        or type(expected_file_id_hex) is not str
        or re.fullmatch(r"[0-9a-f]{16}", expected_file_id_hex) is None
        or int(expected_file_id_hex, 16) == 0
    ):
        _fail("v2 retained directory fixed-width identity mismatch")
    directory.verify_identity()
    observed = _windows_v2_identity_from_descriptor(directory._descriptor)
    expected = (int(expected_volume_id_hex, 16), int(expected_file_id_hex, 16))
    if observed != expected:
        _fail("v2 retained directory numeric identity mismatch")
    if (
        format(observed[0], "08x") != expected_volume_id_hex
        or format(observed[1], "016x") != expected_file_id_hex
    ):
        _fail("v2 retained directory same-profile reserialization mismatch")


@_sanitized_api
def verify_gate_b_v2_retained_root_topology(
    directories: Mapping[str, GateBPinnedDirectory],
) -> None:
    """Reject physical aliases and nesting across the three retained v2 roots."""
    roles = ("ledger_base", "quarantine_base", "test_root")
    if os.name != "nt":
        _fail("v2 retained root topology requires Windows")
    if not isinstance(directories, Mapping) or set(directories) != set(roles):
        _fail("v2 retained root topology fields are not closed-world")
    stable_parts: dict[str, tuple[str, ...]] = {}
    native_identities: dict[str, tuple[int, int]] = {}
    for role in roles:
        directory = directories[role]
        if type(directory) is not GateBPinnedDirectory:
            _fail("v2 retained root topology nominal type mismatch")
        directory.verify_identity()
        fresh_final_path = _windows_final_path_from_descriptor(directory._descriptor)
        if fresh_final_path.casefold() != str(directory._stable_path).casefold():
            _fail("v2 retained root stable path changed")
        stable_parts[role] = tuple(
            part.casefold() for part in PureWindowsPath(fresh_final_path).parts
        )
        native_identities[role] = _windows_v2_identity_from_descriptor(directory._descriptor)
    if len(set(native_identities.values())) != len(roles):
        _fail("v2 retained roots must be physically distinct")
    for index, left_role in enumerate(roles):
        left = stable_parts[left_role]
        for right_role in roles[index + 1 :]:
            right = stable_parts[right_role]
            if (
                left == right
                or (len(left) < len(right) and right[: len(left)] == left)
                or (len(right) < len(left) and left[: len(right)] == right)
            ):
                _fail("v2 retained roots must not be physically nested")


def _write_exclusive(path: Path, raw: bytes) -> None:
    parent_before = _verify_directory(path.parent, "durable artifact parent")
    descriptor = _open_new_descriptor(path)
    try:
        _durable_descriptor_write(descriptor, raw)
    finally:
        os.close(descriptor)
    _fsync_parent(path)
    parent_after = _verify_directory(path.parent, "durable artifact parent")
    if (parent_before.st_dev, parent_before.st_ino) != (
        parent_after.st_dev,
        parent_after.st_ino,
    ):
        _fail("durable artifact parent identity changed")
    reread = _read_pinned(path, "durable artifact")
    if reread != raw:
        _fail("durable artifact bytes changed after creation")


def _verify_root_ref(ref: Mapping[str, Any], expected_role: str) -> Path:
    # Import at the call boundary to avoid a module cycle.  Only the exact
    # provenance-registered executable adapter may reuse a published v2 anchor;
    # ordinary mappings stay on the unchanged v1 contract below.
    from phase6.gate_b_v2_route import (
        GateBV2RuntimeRootReference,
        validate_gate_b_v2_runtime_root_reference,
    )

    executable_v2 = type(ref) is GateBV2RuntimeRootReference
    if executable_v2:
        validate_gate_b_v2_runtime_root_reference(ref, expected_role)
    required = {
        "absolute_path",
        "anchor_relative_path",
        "anchor_sha256",
        "file_id_hex",
        "identity_scheme",
        "root_role",
        "volume_id_hex",
    }
    if set(ref) != required or ref["root_role"] != expected_role:
        _fail("root reference is not closed-world")
    path = Path(ref["absolute_path"])
    if not path.is_absolute() or str(path.resolve()) != ref["absolute_path"]:
        _fail("root path is not canonical absolute")
    metadata = _verify_directory(path, f"{expected_role} root")
    if (
        format(metadata.st_ino, "x") != ref["file_id_hex"]
        or format(metadata.st_dev, "x") != ref["volume_id_hex"]
    ):
        _fail("root physical identity mismatch")
    expected_scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    if ref["identity_scheme"] != expected_scheme:
        _fail("root identity scheme mismatch")
    if expected_role in {"ledger_base", "quarantine_base"}:
        if (
            ref["anchor_relative_path"] != ".gate-b-root-anchor.json"
            or _sha(ref["anchor_sha256"], "root anchor hash") != ref["anchor_sha256"]
        ):
            _fail("writable root anchor reference mismatch")
        anchor_raw = _read_pinned(path / ".gate-b-root-anchor.json", "writable root anchor")
        if sha256_bytes(anchor_raw) != ref["anchor_sha256"]:
            _fail("writable root anchor bytes changed")
        if executable_v2:
            validate_gate_b_v2_runtime_root_reference(
                ref,
                expected_role,
                anchor_raw=anchor_raw,
            )
            return path
        anchor = _strict_canonical_object(anchor_raw, "writable root anchor")
        _closed(
            anchor,
            {
                "schema_version",
                "artifact_type",
                "root_role",
                "anchor_id",
                "created_at_utc",
                "approval_record_sha256",
            },
            "writable root anchor",
        )
        if (
            anchor["schema_version"] != ROOT_ANCHOR_SCHEMA_VERSION
            or anchor["artifact_type"] != "gate_b_root_anchor"
            or anchor["root_role"] != expected_role
        ):
            _fail("writable root anchor identity mismatch")
        _atom(anchor["anchor_id"], "root anchor ID")
        _sha(anchor["approval_record_sha256"], "anchor approval hash")
        _timestamp(anchor["created_at_utc"], "root anchor")
    else:
        if ref["anchor_relative_path"] is not None or ref["anchor_sha256"] is not None:
            _fail("Test root anchor fields must be null")
        if executable_v2:
            validate_gate_b_v2_runtime_root_reference(ref, expected_role, anchor_raw=None)
    return path


def _namespace_claim_path(
    base: Path,
    kind: str,
    test_batch_hash: str,
    attempt_ordinal: int | None = None,
) -> Path:
    digest = _sha(test_batch_hash, "namespace claim batch hash")
    if kind == "ledger" and attempt_ordinal is None:
        name = f".gate-b-ledger-namespace-{digest}.identity"
    elif kind == "quarantine_batch" and attempt_ordinal is None:
        name = f".gate-b-quarantine-{digest}.identity"
    elif kind == "quarantine_attempt" and attempt_ordinal is not None:
        ordinal = _six_digit_positive(attempt_ordinal, "namespace claim attempt ordinal")
        name = f".gate-b-quarantine-{digest}-attempt-{ordinal:06d}.identity"
    else:
        _fail("namespace claim kind is invalid")
    return base / _direct_child_name(name, "namespace claim")


def _namespace_claim_exists(path: Path, *, base_descriptor: int | None = None) -> bool:
    try:
        if base_descriptor is None or os.name == "nt":
            _lstat(path)
        else:
            _regular_metadata_at(
                base_descriptor,
                path.parent,
                path.name,
                "namespace identity claim",
            )
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GateBLedgerError("namespace identity claim is unavailable") from exc
    return True


def _write_namespace_claim(
    base: Path,
    *,
    kind: str,
    test_batch_hash: str,
    attempt_ordinal: int | None,
    namespace_metadata: os.stat_result,
    authorization_metadata: os.stat_result | None = None,
    lock_metadata: os.stat_result | None = None,
    base_descriptor: int | None = None,
) -> Path:
    path = _namespace_claim_path(base, kind, test_batch_hash, attempt_ordinal)
    payload = {
        "kind": kind,
        "test_batch_hash": test_batch_hash,
        "attempt_ordinal": attempt_ordinal,
        "volume_id_hex": format(namespace_metadata.st_dev, "x"),
        "file_id_hex": format(namespace_metadata.st_ino, "x"),
    }
    if kind == "ledger":
        if authorization_metadata is None or lock_metadata is None:
            _fail("ledger namespace claim evidence is incomplete")
        payload.update(
            {
                "authorization_volume_id_hex": format(authorization_metadata.st_dev, "x"),
                "authorization_file_id_hex": format(authorization_metadata.st_ino, "x"),
                "lock_volume_id_hex": format(lock_metadata.st_dev, "x"),
                "lock_file_id_hex": format(lock_metadata.st_ino, "x"),
            }
        )
    elif authorization_metadata is not None or lock_metadata is not None:
        _fail("non-ledger namespace claim has unexpected evidence")
    raw = canonical_json_bytes(payload)
    if base_descriptor is None:
        _write_exclusive(path, raw)
    else:
        _write_exclusive_at(
            base_descriptor,
            base,
            path.name,
            raw,
        )
    return path


def _verify_namespace_claim(
    base: Path,
    namespace: Path,
    *,
    kind: str,
    test_batch_hash: str,
    attempt_ordinal: int | None,
    authorization_directory: Path | None = None,
    lock_path: Path | None = None,
    base_descriptor: int | None = None,
    namespace_descriptor: int | None = None,
) -> tuple[tuple[int, int], tuple[int, int]]:
    if (base_descriptor is None) != (namespace_descriptor is None):
        _fail("namespace claim descriptor evidence is incomplete")
    path = _namespace_claim_path(base, kind, test_batch_hash, attempt_ordinal)
    if base_descriptor is None:
        raw = _read_pinned(path, "namespace identity claim")
    else:
        raw = _read_pinned_at(
            base_descriptor,
            base,
            path.name,
            "namespace identity claim",
        )
    value = _strict_canonical_object(raw, "namespace identity claim")
    fields = {
        "kind",
        "test_batch_hash",
        "attempt_ordinal",
        "volume_id_hex",
        "file_id_hex",
    }
    if kind == "ledger":
        fields.update(
            {
                "authorization_volume_id_hex",
                "authorization_file_id_hex",
                "lock_volume_id_hex",
                "lock_file_id_hex",
            }
        )
    _closed(value, fields, "namespace identity claim")
    _sha(value["test_batch_hash"], "namespace claim batch hash")
    if kind == "ledger":
        if value["attempt_ordinal"] is not None:
            _fail("ledger namespace claim attempt must be null")
        if authorization_directory is None or lock_path is None:
            _fail("ledger namespace claim verification evidence is incomplete")
    elif kind == "quarantine_batch":
        if value["attempt_ordinal"] is not None:
            _fail("quarantine batch claim attempt must be null")
    else:
        _six_digit_positive(
            value["attempt_ordinal"],
            "quarantine namespace claim attempt ordinal",
        )
    if (
        value["kind"] != kind
        or value["test_batch_hash"] != test_batch_hash
        or value["attempt_ordinal"] != attempt_ordinal
    ):
        _fail("namespace identity claim binding mismatch")
    identity_fields = {"volume_id_hex", "file_id_hex"}
    if kind == "ledger":
        identity_fields.update(
            {
                "authorization_volume_id_hex",
                "authorization_file_id_hex",
                "lock_volume_id_hex",
                "lock_file_id_hex",
            }
        )
    for name in identity_fields:
        if not isinstance(value[name], str) or _HEX_RE.fullmatch(value[name]) is None:
            _fail("namespace identity claim physical ID is invalid")
    if namespace_descriptor is None:
        namespace_metadata = _verify_directory(namespace, "claimed Gate B namespace")
    else:
        namespace_metadata = os.fstat(namespace_descriptor)
        if (
            not stat.S_ISDIR(namespace_metadata.st_mode)
            or stat.S_ISLNK(namespace_metadata.st_mode)
            or _reparse(namespace_metadata)
        ):
            _fail("claimed Gate B namespace must be a physical directory")
    if value["volume_id_hex"] != format(namespace_metadata.st_dev, "x") or value[
        "file_id_hex"
    ] != format(namespace_metadata.st_ino, "x"):
        _fail("claimed Gate B namespace identity changed")
    if kind == "ledger":
        authorization_metadata = _verify_directory(
            authorization_directory,
            "claimed Gate B authorization namespace",
        )
        lock_metadata = _verify_regular(
            lock_path,
            "claimed Gate B namespace lock",
            expected_size=0,
        )
        if (
            value["authorization_volume_id_hex"] != format(authorization_metadata.st_dev, "x")
            or value["authorization_file_id_hex"] != format(authorization_metadata.st_ino, "x")
            or value["lock_volume_id_hex"] != format(lock_metadata.st_dev, "x")
            or value["lock_file_id_hex"] != format(lock_metadata.st_ino, "x")
        ):
            _fail("claimed Gate B ledger child identity changed")
    if base_descriptor is None:
        claim_metadata = _verify_regular(path, "namespace identity claim")
    else:
        claim_metadata = _regular_metadata_at(
            base_descriptor,
            base,
            path.name,
            "namespace identity claim",
        )
    return (
        (namespace_metadata.st_dev, namespace_metadata.st_ino),
        (claim_metadata.st_dev, claim_metadata.st_ino),
    )


@dataclass(frozen=True, slots=True)
class GateBLedgerRecord:
    """One immutable, hash-chained ledger record."""

    record_sha256: str
    record_sequence: int
    attempt_ordinal: int
    from_state: str
    to_state: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload


@dataclass(frozen=True, slots=True)
class GateBAttemptReservation:
    """Sanitized durable reservation returned before any Test-child open."""

    test_batch_hash: str
    attempt_ordinal: int
    reserved_record_sha256: str
    state: str
    record: GateBLedgerRecord = field(repr=False)
    _ledger_directory: Path = field(repr=False)

    def __repr__(self) -> str:
        return (
            "GateBAttemptReservation("
            f"test_batch_hash={self.test_batch_hash!r}, "
            f"attempt_ordinal={self.attempt_ordinal!r}, state='RESERVED')"
        )


def _windows_lock_adapter(lock_function, handle: int, overlapped_pointer) -> bool:
    return bool(
        lock_function(
            ctypes.c_void_p(handle),
            0x00000002,
            0,
            1,
            0,
            overlapped_pointer,
        )
    )


def _windows_unlock_adapter(unlock_function, handle: int, overlapped_pointer) -> bool:
    return bool(
        unlock_function(
            ctypes.c_void_p(handle),
            0,
            1,
            0,
            overlapped_pointer,
        )
    )


def _posix_flock_adapter(flock_function, descriptor: int, operation: int) -> None:
    flock_function(descriptor, operation)


def _record_fields() -> set[str]:
    return {
        "schema_version",
        "artifact_type",
        "test_batch_hash",
        "record_sequence",
        "attempt_ordinal",
        "from_state",
        "to_state",
        "previous_record_sha256",
        "actor_id",
        "actor_role",
        "timestamp_utc",
        "reason_id",
        "reason_detail_sha256",
        "quarantine_manifest_sha256",
        "authorization_record_sha256",
        "next_attempt_ordinal",
    }


def _retry_catalog(batch: GateBBatchManifest) -> dict[str, tuple[str, ...]]:
    try:
        reasons = batch.payload["governance"]["technical_retry_reasons"]
    except (KeyError, TypeError) as exc:
        raise GateBLedgerError("technical retry catalog is unavailable") from exc
    if not isinstance(reasons, list | tuple) or not reasons:
        _fail("technical retry catalog is invalid")
    catalog: dict[str, tuple[str, ...]] = {}
    for item in reasons:
        if not isinstance(item, Mapping) or set(item) != {
            "eligible_from_states",
            "reason_id",
        }:
            _fail("technical retry catalog entry is invalid")
        reason_id = _atom(item["reason_id"], "technical retry reason")
        states = item["eligible_from_states"]
        if (
            not isinstance(states, list | tuple)
            or not states
            or tuple(states) != tuple(state for state in ("RESERVED", "STARTED") if state in states)
        ):
            _fail("technical retry reason eligibility is invalid")
        if reason_id in catalog:
            _fail("technical retry reason is duplicated")
        catalog[reason_id] = tuple(states)
    return catalog


def _require_reason_eligible(
    reason_id: object,
    from_state: str,
    retry_catalog: Mapping[str, tuple[str, ...]],
) -> None:
    reason = _atom(reason_id, "technical retry reason")
    if reason not in retry_catalog or from_state not in retry_catalog[reason]:
        _fail("technical retry reason is unknown or ineligible for the failed state")


def _validate_record_payload(
    value: dict[str, Any],
    *,
    previous: GateBLedgerRecord | None,
    expected_sequence: int,
    expected_initial_authorization_sha256: str,
    retry_catalog: Mapping[str, tuple[str, ...]],
) -> None:
    _closed(value, _record_fields(), "ledger record")
    if (
        value["schema_version"] != ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_test_attempt_ledger_record"
    ):
        _fail("ledger record schema identity mismatch")
    _six_digit_positive(value["record_sequence"], "record sequence")
    if value["record_sequence"] != expected_sequence:
        _fail("ledger record sequence mismatch")
    _six_digit_positive(value["attempt_ordinal"], "attempt ordinal")
    _sha(value["test_batch_hash"], "ledger batch hash")
    _atom(value["actor_id"], "ledger actor ID")
    if value["actor_role"] not in {
        "ledger_manager",
        "test_runner",
        "release_approver",
        "retry_approver",
    }:
        _fail("ledger actor role mismatch")
    _timestamp(value["timestamp_utc"], "ledger")

    if previous is None:
        if (
            value["previous_record_sha256"] != ZERO_SHA256
            or value["from_state"] != "UNSEEN"
            or value["to_state"] != "RESERVED"
            or value["record_sequence"] != 1
            or value["attempt_ordinal"] != 1
            or value["authorization_record_sha256"]
            != _sha(
                expected_initial_authorization_sha256,
                "initial readiness authorization hash",
            )
        ):
            _fail("initial ledger record invariants failed")
    else:
        if (
            value["previous_record_sha256"] != previous.record_sha256
            or value["test_batch_hash"] != previous.payload["test_batch_hash"]
        ):
            _fail("ledger previous-record hash mismatch")

    transition = (value["from_state"], value["to_state"])
    allowed = {
        ("UNSEEN", "RESERVED"),
        ("RESERVED", "STARTED"),
        ("STARTED", "SEALED"),
        ("SEALED", "RELEASED"),
        ("RESERVED", "FAILED_CLOSED"),
        ("STARTED", "FAILED_CLOSED"),
        ("FAILED_CLOSED", "RETRY_AUTHORIZED"),
        ("RETRY_AUTHORIZED", "RESERVED"),
    }
    if transition not in allowed:
        _fail("illegal Gate B ledger transition")
    if previous is not None and value["from_state"] != previous.to_state:
        _fail("ledger transition does not follow the latest state")

    null = None
    expected_role: str
    if transition == ("UNSEEN", "RESERVED"):
        expected_role = "ledger_manager"
        expected = (null, null, null, "hash", null)
    elif transition == ("RETRY_AUTHORIZED", "RESERVED"):
        expected_role = "ledger_manager"
        expected = (null, null, "hash", "hash", null)
        if previous is None or value["attempt_ordinal"] != previous.payload["next_attempt_ordinal"]:
            _fail("retry reservation ordinal mismatch")
    elif transition == ("RESERVED", "STARTED"):
        expected_role = "test_runner"
        expected = (null, null, null, null, null)
        if previous is None or value["attempt_ordinal"] != previous.attempt_ordinal:
            _fail("STARTED attempt ordinal mismatch")
    elif transition == ("STARTED", "SEALED"):
        expected_role = "test_runner"
        expected = (null, null, "hash", null, null)
    elif transition in {("RESERVED", "FAILED_CLOSED"), ("STARTED", "FAILED_CLOSED")}:
        expected_role = "test_runner"
        expected = ("atom", "hash", "hash", null, null)
    elif transition == ("SEALED", "RELEASED"):
        expected_role = "release_approver"
        expected = (null, null, "hash", "hash", null)
    else:
        expected_role = "retry_approver"
        expected = ("atom", null, "hash", "hash", "positive")

    actual_fields = (
        "reason_id",
        "reason_detail_sha256",
        "quarantine_manifest_sha256",
        "authorization_record_sha256",
        "next_attempt_ordinal",
    )
    for name, kind in zip(actual_fields, expected, strict=True):
        item = value[name]
        if kind is None and item is not None:
            _fail(f"{name} must be null for this transition")
        if kind == "hash":
            _sha(item, name)
        if kind == "atom":
            _atom(item, name)
        if kind == "positive":
            _six_digit_positive(item, name)
    if value["actor_role"] != expected_role:
        _fail("ledger transition actor role mismatch")
    if previous is not None:
        same_attempt = {
            ("RESERVED", "STARTED"),
            ("STARTED", "SEALED"),
            ("RESERVED", "FAILED_CLOSED"),
            ("STARTED", "FAILED_CLOSED"),
            ("SEALED", "RELEASED"),
            ("FAILED_CLOSED", "RETRY_AUTHORIZED"),
        }
        if transition in same_attempt and value["attempt_ordinal"] != previous.attempt_ordinal:
            _fail("ledger transition changed attempt ordinal")
        if transition == ("RETRY_AUTHORIZED", "RESERVED"):
            if (
                value["quarantine_manifest_sha256"]
                != previous.payload["quarantine_manifest_sha256"]
                or value["authorization_record_sha256"]
                != previous.payload["authorization_record_sha256"]
            ):
                _fail("later reservation lost retry evidence binding")
        elif transition == ("SEALED", "RELEASED"):
            if (
                value["quarantine_manifest_sha256"]
                != previous.payload["quarantine_manifest_sha256"]
            ):
                _fail("release changed sealed quarantine binding")
        elif transition == ("FAILED_CLOSED", "RETRY_AUTHORIZED") and (
            value["reason_id"] != previous.payload["reason_id"]
            or value["quarantine_manifest_sha256"] != previous.payload["quarantine_manifest_sha256"]
        ):
            _fail("retry changed failed evidence binding")
    if transition in {("RESERVED", "FAILED_CLOSED"), ("STARTED", "FAILED_CLOSED")} and value[
        "reason_detail_sha256"
    ] != _canonical_reason_detail_sha256(value["reason_id"]):
        _fail("FAILED_CLOSED reason detail digest mismatch")
    if transition in {
        ("RESERVED", "FAILED_CLOSED"),
        ("STARTED", "FAILED_CLOSED"),
        ("FAILED_CLOSED", "RETRY_AUTHORIZED"),
    }:
        failed_from_state = (
            value["from_state"] if transition[1] == "FAILED_CLOSED" else previous.from_state
        )
        _require_reason_eligible(value["reason_id"], failed_from_state, retry_catalog)
    if (
        transition == ("FAILED_CLOSED", "RETRY_AUTHORIZED")
        and value["next_attempt_ordinal"] != value["attempt_ordinal"] + 1
    ):
        _fail("retry authorization ordinal mismatch")


def _record_from(
    path: Path,
    raw: bytes,
    previous: GateBLedgerRecord | None,
    sequence: int,
    expected_initial_authorization_sha256: str,
    retry_catalog: Mapping[str, tuple[str, ...]],
) -> GateBLedgerRecord:
    payload = _strict_canonical_object(raw, "Gate B ledger record")
    _validate_record_payload(
        payload,
        previous=previous,
        expected_sequence=sequence,
        expected_initial_authorization_sha256=expected_initial_authorization_sha256,
        retry_catalog=retry_catalog,
    )
    return GateBLedgerRecord(
        sha256_bytes(raw),
        payload["record_sequence"],
        payload["attempt_ordinal"],
        payload["from_state"],
        payload["to_state"],
        MappingProxyType(payload),
        raw,
        path,
    )


class GateBNamespaceLock(AbstractContextManager["GateBNamespaceLock"]):
    """Cross-process exclusive lock on one persistent zero-byte lock file."""

    def __init__(self, path: Path, expected_identity: tuple[int, int]) -> None:
        self._path = path
        self._expected_identity = expected_identity
        self._descriptor: int | None = None
        self._overlapped: Any = None
        self._locked = False

    def verify_identity(self) -> None:
        if self._descriptor is None:
            _fail("Gate B namespace lock is not held")
        named = _verify_regular(self._path, "Gate B namespace lock", expected_size=0)
        opened = os.fstat(self._descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or _reparse(opened)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or (named.st_dev, named.st_ino) != self._expected_identity
            or (opened.st_dev, opened.st_ino) != self._expected_identity
        ):
            _fail("Gate B namespace lock descriptor/path identity mismatch")

    def __enter__(self) -> GateBNamespaceLock:
        named = _verify_regular(self._path, "Gate B namespace lock", expected_size=0)
        if (named.st_dev, named.st_ino) != self._expected_identity:
            _fail("Gate B namespace lock identity changed before acquisition")
        self._descriptor = _open_lock_descriptor(self._path)
        try:
            self.verify_identity()
        except BaseException:
            self.close()
            raise
        if os.name == "nt":
            import msvcrt

            class Overlapped(ctypes.Structure):
                _fields_ = [
                    ("Internal", ctypes.c_size_t),
                    ("InternalHigh", ctypes.c_size_t),
                    ("Offset", ctypes.c_uint32),
                    ("OffsetHigh", ctypes.c_uint32),
                    ("hEvent", ctypes.c_void_p),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            lock_file = kernel32.LockFileEx
            lock_file.argtypes = (
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(Overlapped),
            )
            lock_file.restype = ctypes.c_int
            self._overlapped = Overlapped()
            handle = msvcrt.get_osfhandle(self._descriptor)
            if not _windows_lock_adapter(
                lock_file,
                handle,
                ctypes.byref(self._overlapped),
            ):
                self.close()
                raise GateBLedgerError("required cross-process lock failed closed")
            self._locked = True
        else:
            try:
                import fcntl
            except ImportError as exc:
                self.close()
                raise GateBLedgerError("required cross-process lock is unavailable") from exc
            _posix_flock_adapter(fcntl.flock, self._descriptor, fcntl.LOCK_EX)
            self._locked = True
        try:
            self.verify_identity()
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._descriptor is None:
            return
        if os.name == "nt" and self._locked and self._overlapped is not None:
            import msvcrt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            unlock = kernel32.UnlockFileEx
            unlock.argtypes = (
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(type(self._overlapped)),
            )
            unlock.restype = ctypes.c_int
            handle = msvcrt.get_osfhandle(self._descriptor)
            _windows_unlock_adapter(
                unlock,
                handle,
                ctypes.byref(self._overlapped),
            )
        elif os.name != "nt" and self._locked:
            import fcntl

            _posix_flock_adapter(fcntl.flock, self._descriptor, fcntl.LOCK_UN)
        os.close(self._descriptor)
        self._descriptor = None
        self._overlapped = None
        self._locked = False

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class GateBLedgerStore:
    """Pinned namespace facade for complete chain reload and durable append."""

    def __init__(self, request: GateBRequestLike) -> None:
        _reject_v2_request(request)
        self.request = request
        _six_digit_positive(request.attempt_ordinal, "request attempt ordinal")
        self._retry_catalog = _retry_catalog(request.batch)
        base = _verify_root_ref(request.roots["ledger_base"], "ledger_base")
        self.directory = base / request.batch.test_batch_hash
        self.authorization_directory = self.directory / "authorizations"
        self.lock_path = self.directory / ".gate-b.lock"
        self._claim_path = _namespace_claim_path(
            base,
            "ledger",
            request.batch.test_batch_hash,
        )
        if not _namespace_claim_exists(self._claim_path):
            try:
                _mkdir_direct(self.directory)
                _fsync_parent(self.directory)
            except FileExistsError:
                _fail("unclaimed Gate B ledger namespace already exists")
            directory_metadata = _verify_directory(self.directory, "Gate B ledger namespace")
            try:
                _mkdir_direct(self.authorization_directory)
                _fsync_parent(self.authorization_directory)
            except FileExistsError:
                _fail("new Gate B authorization namespace already exists")
            authorization_metadata = _verify_directory(
                self.authorization_directory,
                "Gate B authorization namespace",
            )
            try:
                descriptor = _create_lock_descriptor(self.lock_path)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_parent(self.lock_path)
            except FileExistsError:
                _fail("new Gate B namespace lock already exists")
            lock_metadata = _verify_regular(
                self.lock_path,
                "Gate B namespace lock",
                expected_size=0,
            )
            try:
                _write_namespace_claim(
                    base,
                    kind="ledger",
                    test_batch_hash=request.batch.test_batch_hash,
                    attempt_ordinal=None,
                    namespace_metadata=directory_metadata,
                    authorization_metadata=authorization_metadata,
                    lock_metadata=lock_metadata,
                )
            except FileExistsError:
                _fail("Gate B ledger namespace claim raced")
        self._directory_identity, self._claim_identity = _verify_namespace_claim(
            base,
            self.directory,
            kind="ledger",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=None,
            authorization_directory=self.authorization_directory,
            lock_path=self.lock_path,
        )
        authorization_metadata = _verify_directory(
            self.authorization_directory, "Gate B authorization namespace"
        )
        self._authorization_identity = (
            authorization_metadata.st_dev,
            authorization_metadata.st_ino,
        )
        lock_metadata = _verify_regular(self.lock_path, "Gate B namespace lock", expected_size=0)
        self._lock_identity = (lock_metadata.st_dev, lock_metadata.st_ino)

    def lock(self) -> GateBNamespaceLock:
        return GateBNamespaceLock(self.lock_path, self._lock_identity)

    @staticmethod
    def reserve_attempt(
        request: GateBRequestLike, *, expected_latest_record_sha256: str | None
    ) -> GateBAttemptReservation:
        # This is a public reservation entry point in its own right.  Keep the
        # v2 one-shot capability check here so callers cannot bypass the
        # loader facade by invoking the store directly.
        from phase6.gate_b_v2_route import (
            GateBV2RouteError,
            claim_gate_b_v2_reservation_authorization,
            is_gate_b_v2_runtime_request,
        )

        if is_gate_b_v2_runtime_request(request):
            try:
                return claim_gate_b_v2_reservation_authorization(
                    request,
                    lambda: _reserve_attempt(
                        request,
                        expected_latest_record_sha256=expected_latest_record_sha256,
                    ),
                )
            except GateBV2RouteError:
                _fail("v2 reservation is not authorized by a consumed route")
        return _reserve_attempt(
            request,
            expected_latest_record_sha256=expected_latest_record_sha256,
        )

    def append_started(
        self,
        request: GateBRequestLike,
        reservation: GateBAttemptReservation,
    ) -> GateBLedgerRecord:
        return _append_started(request, reservation, store=self)

    def _verify_namespace(self) -> None:
        base = _verify_root_ref(self.request.roots["ledger_base"], "ledger_base")
        if str(self.directory.parent) != str(base):
            _fail("Gate B ledger namespace left its approved root")
        claimed_directory, claim_identity = _verify_namespace_claim(
            base,
            self.directory,
            kind="ledger",
            test_batch_hash=self.request.batch.test_batch_hash,
            attempt_ordinal=None,
            authorization_directory=self.authorization_directory,
            lock_path=self.lock_path,
        )
        directory = _verify_directory(self.directory, "Gate B ledger namespace")
        authorization = _verify_directory(
            self.authorization_directory, "Gate B authorization namespace"
        )
        lock_metadata = _verify_regular(self.lock_path, "Gate B namespace lock", expected_size=0)
        if (
            claimed_directory != self._directory_identity
            or claim_identity != self._claim_identity
            or (directory.st_dev, directory.st_ino) != self._directory_identity
            or (
                authorization.st_dev,
                authorization.st_ino,
            )
            != self._authorization_identity
            or (
                lock_metadata.st_dev,
                lock_metadata.st_ino,
            )
            != self._lock_identity
        ):
            _fail("Gate B ledger namespace identity changed")

    def _open_ledger_directory(self) -> int:
        self._verify_namespace()
        return _open_pinned_directory(
            self.directory,
            self._directory_identity,
            "Gate B ledger namespace",
        )

    def _open_authorization_directory(self) -> int:
        self._verify_namespace()
        return _open_pinned_directory(
            self.authorization_directory,
            self._authorization_identity,
            "Gate B authorization namespace",
        )

    def read_authorization(self, path: Path, label: str) -> bytes:
        if path.parent != self.authorization_directory:
            _fail(f"{label} path is outside its pinned namespace")
        descriptor = self._open_authorization_directory()
        try:
            raw = _read_pinned_at(
                descriptor,
                self.authorization_directory,
                path.name,
                label,
            )
            self._verify_namespace()
            return raw
        finally:
            os.close(descriptor)

    def _load_chain_at(self, directory_descriptor: int) -> tuple[GateBLedgerRecord, ...]:
        names = _directory_names_at(directory_descriptor, self.directory)
        self._verify_namespace()
        allowed_nonrecords = {".gate-b.lock", "authorizations"}
        record_names = []
        for name in names:
            if name in allowed_nonrecords:
                continue
            match = _RECORD_RE.fullmatch(name)
            if match is None:
                _fail("Gate B ledger namespace contains an unexpected entry")
            record_names.append((int(match.group(1)), name))
        record_names.sort()
        if [sequence for sequence, _name in record_names] != list(range(1, len(record_names) + 1)):
            _fail("Gate B ledger record names are not contiguous")
        records = []
        previous = None
        for sequence, name in record_names:
            raw = _read_pinned_at(
                directory_descriptor,
                self.directory,
                name,
                "Gate B ledger record",
            )
            self._verify_namespace()
            path = self.directory / name
            record = _record_from(
                path,
                raw,
                previous,
                sequence,
                self.request.readiness.sha256,
                self._retry_catalog,
            )
            if record.payload["test_batch_hash"] != self.request.batch.test_batch_hash:
                _fail("ledger record batch hash mismatch")
            readiness = self.request.readiness.payload
            expected_authority = {
                "RESERVED": (
                    readiness["authorized_ledger_manager_actor_id"],
                    readiness["authorized_ledger_manager_role"],
                ),
                "STARTED": (self.request.actor_id, "test_runner"),
                "SEALED": (self.request.actor_id, "test_runner"),
                "FAILED_CLOSED": (self.request.actor_id, "test_runner"),
                "RELEASED": (
                    readiness["designated_release_approver_id"],
                    readiness["designated_release_approver_role"],
                ),
                "RETRY_AUTHORIZED": (
                    readiness["designated_retry_approver_id"],
                    readiness["designated_retry_approver_role"],
                ),
            }[record.to_state]
            if (
                record.payload["actor_id"],
                record.payload["actor_role"],
            ) != expected_authority:
                _fail("ledger record actor authority mismatch")
            records.append(record)
            previous = record
        if _directory_names_at(directory_descriptor, self.directory) != names:
            _fail("Gate B ledger topology changed while loading")
        self._verify_namespace()
        return tuple(records)

    def load_chain(self) -> tuple[GateBLedgerRecord, ...]:
        directory_descriptor = self._open_ledger_directory()
        try:
            return self._load_chain_at(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def append(self, payload: dict[str, Any]) -> GateBLedgerRecord:
        chain = self.load_chain()
        previous = chain[-1] if chain else None
        return self.append_after(previous, payload)

    def append_after(
        self,
        previous: GateBLedgerRecord | None,
        payload: dict[str, Any],
    ) -> GateBLedgerRecord:
        sequence = previous.record_sequence + 1 if previous is not None else 1
        _validate_record_payload(
            payload,
            previous=previous,
            expected_sequence=sequence,
            expected_initial_authorization_sha256=self.request.readiness.sha256,
            retry_catalog=self._retry_catalog,
        )
        raw = canonical_json_bytes(payload)
        name = f"record-{sequence:06d}.json"
        path = self.directory / name
        directory_descriptor = self._open_ledger_directory()
        try:
            chain_before = self._load_chain_at(directory_descriptor)
            current_previous = chain_before[-1] if chain_before else None
            if previous is None:
                if current_previous is not None:
                    _fail("ledger append expected an empty current chain")
            elif (
                current_previous is None
                or current_previous.record_sha256 != previous.record_sha256
                or current_previous.record_sequence != previous.record_sequence
                or current_previous._raw != previous._raw
                or current_previous._path != previous._path
            ):
                _fail("ledger append previous record is stale")
            _record_from(
                path,
                raw,
                current_previous,
                sequence,
                self.request.readiness.sha256,
                self._retry_catalog,
            )
            _write_exclusive_at(
                directory_descriptor,
                self.directory,
                name,
                raw,
            )
            self._verify_namespace()
            chain_after = self._load_chain_at(directory_descriptor)
            if len(chain_after) != sequence or tuple(
                record._raw for record in chain_after[:-1]
            ) != tuple(record._raw for record in chain_before):
                _fail("ledger chain changed across durable append")
            created = chain_after[-1]
            if (
                created.record_sequence != sequence
                or created.record_sha256 != sha256_bytes(raw)
                or created._raw != raw
                or created._path != path
            ):
                _fail("durable ledger append did not retain the requested record")
            return created
        finally:
            os.close(directory_descriptor)


def _new_record(
    request: GateBRequestLike,
    previous: GateBLedgerRecord | None,
    *,
    attempt_ordinal: int,
    from_state: str,
    to_state: str,
    actor_id: str,
    actor_role: str,
    reason_id: str | None = None,
    reason_detail_sha256: str | None = None,
    quarantine_manifest_sha256: str | None = None,
    authorization_record_sha256: str | None = None,
    next_attempt_ordinal: int | None = None,
) -> dict[str, Any]:
    _reject_v2_request(request)
    return {
        "schema_version": ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION,
        "artifact_type": "gate_b_test_attempt_ledger_record",
        "test_batch_hash": request.batch.test_batch_hash,
        "record_sequence": 1 if previous is None else previous.record_sequence + 1,
        "attempt_ordinal": attempt_ordinal,
        "from_state": from_state,
        "to_state": to_state,
        "previous_record_sha256": ZERO_SHA256 if previous is None else previous.record_sha256,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "timestamp_utc": _now_utc(),
        "reason_id": reason_id,
        "reason_detail_sha256": reason_detail_sha256,
        "quarantine_manifest_sha256": quarantine_manifest_sha256,
        "authorization_record_sha256": authorization_record_sha256,
        "next_attempt_ordinal": next_attempt_ordinal,
    }


def _reserve_attempt(
    request: GateBRequestLike, *, expected_latest_record_sha256: str | None
) -> GateBAttemptReservation:
    """Durably reserve one attempt through the sole ledger reservation path."""
    _reject_v2_request(request)
    store = GateBLedgerStore(request)
    with store.lock():
        chain = store.load_chain()
        latest = chain[-1] if chain else None
        if latest is None:
            if expected_latest_record_sha256 is not None or request.attempt_ordinal != 1:
                _fail("initial reservation requires null latest hash and ordinal one")
            from_state = "UNSEEN"
            ordinal = 1
            quarantine_hash = None
            authorization_hash = request.readiness.sha256
        else:
            if (
                expected_latest_record_sha256 != latest.record_sha256
                or latest.to_state != "RETRY_AUTHORIZED"
            ):
                _fail("reservation latest-record trust anchor mismatch")
            ordinal = latest.payload["next_attempt_ordinal"]
            if request.attempt_ordinal != ordinal:
                _fail("request attempt ordinal does not match retry authorization")
            from_state = "RETRY_AUTHORIZED"
            quarantine_hash = latest.payload["quarantine_manifest_sha256"]
            authorization_hash = latest.payload["authorization_record_sha256"]
        readiness = request.readiness.payload
        payload = _new_record(
            request,
            latest,
            attempt_ordinal=ordinal,
            from_state=from_state,
            to_state="RESERVED",
            actor_id=readiness["authorized_ledger_manager_actor_id"],
            actor_role=readiness["authorized_ledger_manager_role"],
            quarantine_manifest_sha256=quarantine_hash,
            authorization_record_sha256=authorization_hash,
        )
        record = store.append(payload)
    return GateBAttemptReservation(
        request.batch.test_batch_hash,
        ordinal,
        record.record_sha256,
        "RESERVED",
        record,
        store.directory,
    )


def _append_started(
    request: GateBRequestLike,
    reservation: GateBAttemptReservation,
    *,
    store: GateBLedgerStore,
) -> GateBLedgerRecord:
    """Append STARTED while the caller still holds the namespace lock."""
    _reject_v2_request(request)
    latest = reservation.record
    if latest.record_sha256 != reservation.reserved_record_sha256:
        _fail("reservation object hash mismatch")
    payload = _new_record(
        request,
        latest,
        attempt_ordinal=reservation.attempt_ordinal,
        from_state="RESERVED",
        to_state="STARTED",
        actor_id=request.actor_id,
        actor_role="test_runner",
    )
    return store.append_after(latest, payload)


def _access_entry_fields() -> set[str]:
    return {
        "schema_version",
        "artifact_type",
        "event_sequence",
        "previous_entry_sha256",
        "test_batch_hash",
        "attempt_ordinal",
        "actor_id",
        "timestamp_utc",
        "event_type",
        "execution_context_sha256",
        "execution_evidence_sha256",
        "failure_class",
        "byte_count",
        "output_name",
        "cumulative_input_sha256",
        "reason_id",
    }


def _validate_access_log_bytes(
    raw: bytes,
    *,
    test_batch_hash: str,
    attempt_ordinal: int,
    actor_id: str,
    execution_context_sha256: str,
) -> tuple[Mapping[str, Any], ...]:
    """Validate every access-log line, hash link, field, and lifecycle."""
    _six_digit_positive(attempt_ordinal, "access-log attempt ordinal")
    if not raw or not raw.endswith(b"\n"):
        _fail("access log is empty or lacks its final canonical LF")
    lines = raw.splitlines(keepends=True)
    entries: list[dict[str, Any]] = []
    previous = ZERO_SHA256
    eof_seen = False
    failure_events = []
    for sequence, line in enumerate(lines, start=1):
        entry = _strict_canonical_object(line, "Gate B access-log entry")
        _closed(entry, _access_entry_fields(), "access-log entry")
        if (
            isinstance(entry["event_sequence"], bool)
            or not isinstance(entry["event_sequence"], int)
            or isinstance(entry["attempt_ordinal"], bool)
            or not isinstance(entry["attempt_ordinal"], int)
            or entry["schema_version"] != ACCESS_LOG_ENTRY_SCHEMA_VERSION
            or entry["artifact_type"] != "gate_b_test_access_log_entry"
            or entry["event_sequence"] != sequence
            or entry["previous_entry_sha256"] != previous
            or entry["test_batch_hash"] != test_batch_hash
            or entry["attempt_ordinal"] != attempt_ordinal
            or entry["actor_id"] != actor_id
            or entry["execution_context_sha256"] != execution_context_sha256
            or entry["event_type"] not in _ACCESS_EVENTS
        ):
            _fail("access-log identity or sequence mismatch")
        _timestamp(entry["timestamp_utc"], "access-log")
        event = entry["event_type"]
        if event in _FAILURE_EVENT_BINDINGS:
            failure_class, _state = _FAILURE_EVENT_BINDINGS[event]
            if entry["failure_class"] != failure_class:
                _fail("access-log failure class mismatch")
            _atom(entry["reason_id"], "access-log reason ID")
            failure_events.append(entry)
        elif entry["failure_class"] is not None or entry["reason_id"] is not None:
            _fail("nonfailure access-log entry contains failure material")
        if event == "input_read":
            if (
                eof_seen
                or isinstance(entry["byte_count"], bool)
                or not isinstance(entry["byte_count"], int)
                or not 1 <= entry["byte_count"] <= 1048576
                or entry["output_name"] is not None
            ):
                _fail("access-log input read is invalid")
            _sha(entry["cumulative_input_sha256"], "cumulative input hash")
        elif event == "input_eof":
            if (
                eof_seen
                or isinstance(entry["byte_count"], bool)
                or entry["byte_count"] != 0
                or entry["output_name"] is not None
            ):
                _fail("access-log EOF is duplicated or invalid")
            _sha(entry["cumulative_input_sha256"], "final input hash")
            eof_seen = True
        elif event == "output_write":
            if (
                isinstance(entry["byte_count"], bool)
                or not isinstance(entry["byte_count"], int)
                or not 1 <= entry["byte_count"] <= 1048576
                or entry["output_name"] not in _WRITABLE_OUTPUTS
            ):
                _fail("access-log output write is invalid")
            if entry["cumulative_input_sha256"] is not None:
                _fail("output event has an input digest")
        else:
            if (
                entry["byte_count"] is not None
                or entry["output_name"] is not None
                or entry["cumulative_input_sha256"] is not None
            ):
                _fail("access-log conditional fields are invalid")
        if entry["execution_evidence_sha256"] is not None:
            _sha(entry["execution_evidence_sha256"], "execution evidence hash")
        entries.append(entry)
        previous = sha256_bytes(line)

    events = [entry["event_type"] for entry in entries]
    if events[0] == "environment_verification_failed":
        if any(entry["execution_evidence_sha256"] is not None for entry in entries):
            _fail("environment-failure lifecycle must not claim execution evidence")
    elif events[0] == "environment_verified":
        if any(entry["execution_evidence_sha256"] is None for entry in entries):
            _fail("verified-environment lifecycle lacks execution evidence")
        if len({entry["execution_evidence_sha256"] for entry in entries}) != 1:
            _fail("verified-environment evidence digest changed within lifecycle")
    else:
        _fail("access-log lifecycle lacks an environment gate")
    if events[-1] not in {"seal_started", "failure_seal_started"}:
        _fail("access-log lifecycle lacks a final seal event")
    if events[-1] == "seal_started":
        if events[:3] != ["environment_verified", "started_appended", "test_input_verified"]:
            _fail("successful access-log prefix is invalid")
        if events[-3:] != ["capabilities_closed", "executor_returned", "seal_started"]:
            _fail("successful access-log suffix is invalid")
        if any(event not in {"input_read", "input_eof", "output_write"} for event in events[3:-3]):
            _fail("successful access-log callback lifecycle is invalid")
        if not eof_seen or failure_events:
            _fail("successful access log must contain one EOF and no failure")
    else:
        if len(failure_events) != 1:
            _fail("failed access log must contain exactly one mapped failure event")
        failure_event = failure_events[0]["event_type"]
        exact_pre_callback = {
            "environment_verification_failed": [
                "environment_verification_failed",
                "failure_seal_started",
            ],
            "test_input_prestart_failed": [
                "environment_verified",
                "test_input_prestart_failed",
                "failure_seal_started",
            ],
            "started_append_failed": [
                "environment_verified",
                "started_append_failed",
                "failure_seal_started",
            ],
        }
        if failure_event in exact_pre_callback:
            if events != exact_pre_callback[failure_event]:
                _fail("pre-callback failure lifecycle is invalid")
        elif failure_event == "executor_failed":
            if events[-3:] != [
                "capabilities_closed",
                "executor_failed",
                "failure_seal_started",
            ]:
                _fail("executor-failure access-log suffix is invalid")
            if events[:3] != [
                "environment_verified",
                "started_appended",
                "test_input_verified",
            ] or any(
                event not in {"input_read", "input_eof", "output_write"} for event in events[3:-3]
            ):
                _fail("executor-failure callback lifecycle is invalid")
        else:
            direct_poststart = [
                "environment_verified",
                "started_appended",
                "test_input_poststart_failed",
                "failure_seal_started",
            ]
            callback_poststart = (
                events[:3]
                == [
                    "environment_verified",
                    "started_appended",
                    "test_input_verified",
                ]
                and events[-3:]
                == [
                    "capabilities_closed",
                    "test_input_poststart_failed",
                    "failure_seal_started",
                ]
                and all(
                    event in {"input_read", "input_eof", "output_write"} for event in events[3:-3]
                )
            )
            if events != direct_poststart and not callback_poststart:
                _fail("poststart input-failure lifecycle is invalid")
    return tuple(MappingProxyType(entry) for entry in entries)


def _validate_output_log_sizes(
    entries: tuple[Mapping[str, Any], ...],
    sizes: Mapping[str, int],
) -> None:
    logged = {name: 0 for name in _WRITABLE_OUTPUTS}
    for entry in entries:
        if entry["event_type"] == "output_write":
            logged[entry["output_name"]] += entry["byte_count"]
    if any(logged[name] != sizes[name] for name in _WRITABLE_OUTPUTS):
        _fail("quarantine output sizes disagree with durable access log")


@dataclass(slots=True)
class GateBQuarantine:
    """Fresh attempt directory with seven exclusive pinned output handles."""

    test_batch_hash: str
    attempt_ordinal: int
    _base_directory: Path = field(repr=False)
    _base_identity: tuple[int, int] = field(repr=False)
    _base_descriptor: int = field(repr=False)
    _batch_directory: Path = field(repr=False)
    _batch_identity: tuple[int, int] = field(repr=False)
    _batch_descriptor: int = field(repr=False)
    _batch_claim_path: Path = field(repr=False)
    _batch_claim_identity: tuple[int, int] = field(repr=False)
    _directory: Path = field(repr=False)
    _handles: dict[str, BinaryIO] = field(repr=False)
    _identities: dict[str, tuple[int, int]] = field(repr=False)
    _directory_identity: tuple[int, int] = field(repr=False)
    _claim_path: Path = field(repr=False)
    _claim_identity: tuple[int, int] = field(repr=False)
    _directory_descriptor: int = field(repr=False)
    _sealed: bool = field(default=False, repr=False)

    @classmethod
    def create(
        cls,
        request: GateBRequestLike,
        quarantine_base_descriptor: int | None = None,
    ) -> GateBQuarantine:
        _reject_v2_request(request)
        _six_digit_positive(request.attempt_ordinal, "quarantine attempt ordinal")
        base = _verify_root_ref(request.roots["quarantine_base"], "quarantine_base")
        if quarantine_base_descriptor is None:
            base_descriptor = _open_directory_descriptor(base)
        else:
            try:
                base_descriptor = os.dup(quarantine_base_descriptor)
            except OSError as exc:
                raise GateBLedgerError("quarantine base descriptor cannot be duplicated") from exc
        batch_descriptor = -1
        directory_descriptor = -1
        handles: dict[str, BinaryIO] = {}
        try:
            base, base_identity = _verify_pinned_root_descriptor(
                request.roots["quarantine_base"],
                "quarantine_base",
                base_descriptor,
            )
            batch_name = request.batch.test_batch_hash
            batch_directory = base / batch_name
            batch_claim_path = _namespace_claim_path(
                base,
                "quarantine_batch",
                request.batch.test_batch_hash,
            )
            if not _namespace_claim_exists(
                batch_claim_path,
                base_descriptor=base_descriptor,
            ):
                try:
                    _mkdir_at(base_descriptor, base, batch_name)
                except FileExistsError:
                    _fail("unclaimed quarantine batch namespace already exists")
                batch_descriptor = _open_directory_at(
                    base_descriptor,
                    base,
                    batch_name,
                    "quarantine batch namespace",
                )
                batch_metadata = os.fstat(batch_descriptor)
                try:
                    _write_namespace_claim(
                        base,
                        kind="quarantine_batch",
                        test_batch_hash=request.batch.test_batch_hash,
                        attempt_ordinal=None,
                        namespace_metadata=batch_metadata,
                        base_descriptor=base_descriptor,
                    )
                except FileExistsError:
                    _fail("quarantine batch namespace claim raced")
            else:
                batch_descriptor = _open_directory_at(
                    base_descriptor,
                    base,
                    batch_name,
                    "claimed Gate B namespace",
                )
            batch_identity, batch_claim_identity = _verify_namespace_claim(
                base,
                batch_directory,
                kind="quarantine_batch",
                test_batch_hash=request.batch.test_batch_hash,
                attempt_ordinal=None,
                base_descriptor=base_descriptor,
                namespace_descriptor=batch_descriptor,
            )
            claim_path = _namespace_claim_path(
                base,
                "quarantine_attempt",
                request.batch.test_batch_hash,
                request.attempt_ordinal,
            )
            if _namespace_claim_exists(
                claim_path,
                base_descriptor=base_descriptor,
            ):
                _fail("quarantine attempt namespace was already claimed")
            attempt_name = f"attempt-{request.attempt_ordinal:06d}"
            attempt_directory = batch_directory / attempt_name
            try:
                _mkdir_at(
                    batch_descriptor,
                    batch_directory,
                    attempt_name,
                )
            except FileExistsError:
                _fail("unclaimed quarantine attempt namespace already exists")
            directory_descriptor = _open_directory_at(
                batch_descriptor,
                batch_directory,
                attempt_name,
                "quarantine attempt namespace",
            )
            directory_metadata = os.fstat(directory_descriptor)
            try:
                _write_namespace_claim(
                    base,
                    kind="quarantine_attempt",
                    test_batch_hash=request.batch.test_batch_hash,
                    attempt_ordinal=request.attempt_ordinal,
                    namespace_metadata=directory_metadata,
                    base_descriptor=base_descriptor,
                )
            except FileExistsError:
                _fail("quarantine attempt namespace claim raced")
            claimed_directory, claim_identity = _verify_namespace_claim(
                base,
                kind="quarantine_attempt",
                test_batch_hash=request.batch.test_batch_hash,
                attempt_ordinal=request.attempt_ordinal,
                namespace=attempt_directory,
                base_descriptor=base_descriptor,
                namespace_descriptor=directory_descriptor,
            )
            if claimed_directory != (directory_metadata.st_dev, directory_metadata.st_ino):
                _fail("quarantine attempt claim identity mismatch")
            identities = {}
            for name in QUARANTINE_OUTPUT_NAMES:
                descriptor = _open_new_at(
                    directory_descriptor,
                    attempt_directory,
                    _OUTPUT_PATHS[name],
                )
                metadata = os.fstat(descriptor)
                identity = (metadata.st_dev, metadata.st_ino)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or identity in identities.values()
                ):
                    os.close(descriptor)
                    _fail("quarantine output topology or physical alias failed")
                handles[name] = os.fdopen(descriptor, "r+b", buffering=0)
                identities[name] = identity
            for handle in handles.values():
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "nt":
                _verify_directory(attempt_directory, "quarantine attempt namespace")
            else:
                os.fsync(directory_descriptor)
            _verify_pinned_root_descriptor(
                request.roots["quarantine_base"],
                "quarantine_base",
                base_descriptor,
            )
            _verify_directory_entry_identity(
                base_descriptor,
                base,
                batch_name,
                batch_identity,
                "quarantine batch namespace",
            )
            _verify_directory_entry_identity(
                batch_descriptor,
                batch_directory,
                attempt_name,
                claimed_directory,
                "quarantine attempt namespace",
            )
        except BaseException:
            for handle in handles.values():
                handle.close()
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            if batch_descriptor >= 0:
                os.close(batch_descriptor)
            os.close(base_descriptor)
            raise
        return cls(
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=request.attempt_ordinal,
            _base_directory=base,
            _base_identity=base_identity,
            _base_descriptor=base_descriptor,
            _batch_directory=batch_directory,
            _batch_identity=batch_identity,
            _batch_descriptor=batch_descriptor,
            _batch_claim_path=batch_claim_path,
            _batch_claim_identity=batch_claim_identity,
            _directory=attempt_directory,
            _handles=handles,
            _identities=identities,
            _directory_identity=(directory_metadata.st_dev, directory_metadata.st_ino),
            _claim_path=claim_path,
            _claim_identity=claim_identity,
            _directory_descriptor=directory_descriptor,
        )

    def writable_handle(self, name: str) -> BinaryIO:
        if self._sealed or name not in _WRITABLE_OUTPUTS:
            _fail("requested quarantine output is unavailable")
        return self._handles[name]

    def access_log_handle(self) -> BinaryIO:
        if self._sealed:
            _fail("access log is unavailable after seal")
        return self._handles["access_log"]

    def invalidate_partial(self) -> None:
        first_error: BaseException | None = None
        for handle in self._handles.values():
            if not handle.closed:
                try:
                    handle.flush()
                    os.fsync(handle.fileno())
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                finally:
                    try:
                        handle.close()
                    except BaseException as exc:
                        if first_error is None:
                            first_error = exc
        if self._directory_descriptor >= 0:
            try:
                os.close(self._directory_descriptor)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            finally:
                self._directory_descriptor = -1
        if self._batch_descriptor >= 0:
            try:
                os.close(self._batch_descriptor)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            finally:
                self._batch_descriptor = -1
        if self._base_descriptor >= 0:
            try:
                os.close(self._base_descriptor)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            finally:
                self._base_descriptor = -1
        if first_error is not None:
            raise GateBLedgerError("partial evidence cleanup was incomplete") from first_error

    def seal(
        self,
        request: GateBRequestLike,
        *,
        status: str,
        started_record_sha256: str | None,
        sealed_at_utc: str | None = None,
    ) -> tuple[Path, str]:
        _reject_v2_request(request)
        if self._sealed or status not in {"sealed", "failed_closed"}:
            _fail("quarantine cannot be sealed in this state")
        _six_digit_positive(request.attempt_ordinal, "quarantine attempt ordinal")
        if status == "sealed":
            _sha(started_record_sha256, "sealed STARTED record hash")
        elif started_record_sha256 is not None:
            _sha(started_record_sha256, "failed STARTED record hash")
        quarantine_base, base_identity = _verify_pinned_root_descriptor(
            request.roots["quarantine_base"],
            "quarantine_base",
            self._base_descriptor,
        )
        if (
            str(self._base_directory) != str(quarantine_base)
            or base_identity != self._base_identity
        ):
            _fail("quarantine base identity changed")
        expected_directory = (
            quarantine_base
            / request.batch.test_batch_hash
            / f"attempt-{request.attempt_ordinal:06d}"
        )
        expected_batch_directory = quarantine_base / request.batch.test_batch_hash
        _verify_directory_entry_identity(
            self._base_descriptor,
            quarantine_base,
            request.batch.test_batch_hash,
            self._batch_identity,
            "quarantine batch namespace",
        )
        batch_identity, batch_claim_identity = _verify_namespace_claim(
            quarantine_base,
            expected_batch_directory,
            kind="quarantine_batch",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=None,
            base_descriptor=self._base_descriptor,
            namespace_descriptor=self._batch_descriptor,
        )
        if (
            str(self._batch_directory) != str(expected_batch_directory)
            or batch_identity != self._batch_identity
            or batch_claim_identity != self._batch_claim_identity
            or self._batch_claim_path
            != _namespace_claim_path(
                quarantine_base,
                "quarantine_batch",
                request.batch.test_batch_hash,
            )
        ):
            _fail("quarantine batch namespace claim changed")
        if str(self._directory) != str(expected_directory):
            _fail("quarantine attempt left its exact derived namespace")
        _verify_directory_entry_identity(
            self._batch_descriptor,
            self._batch_directory,
            f"attempt-{request.attempt_ordinal:06d}",
            self._directory_identity,
            "quarantine attempt namespace",
        )
        claimed_directory, claim_identity = _verify_namespace_claim(
            quarantine_base,
            self._directory,
            kind="quarantine_attempt",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=request.attempt_ordinal,
            base_descriptor=self._base_descriptor,
            namespace_descriptor=self._directory_descriptor,
        )
        if (
            claimed_directory != self._directory_identity
            or claim_identity != self._claim_identity
            or self._claim_path
            != _namespace_claim_path(
                quarantine_base,
                "quarantine_attempt",
                request.batch.test_batch_hash,
                request.attempt_ordinal,
            )
        ):
            _fail("quarantine attempt namespace claim changed")
        directory_metadata = os.fstat(self._directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_ISLNK(directory_metadata.st_mode)
            or _reparse(directory_metadata)
            or (directory_metadata.st_dev, directory_metadata.st_ino) != self._directory_identity
        ):
            _fail("quarantine attempt directory identity changed")
        expected_unsealed = set(_OUTPUT_PATHS.values())
        if _directory_names_at(self._directory_descriptor, self._directory) != expected_unsealed:
            _fail("unsealed quarantine contains unexpected entries")
        access_handle = self._handles["access_log"]
        access_handle.flush()
        os.fsync(access_handle.fileno())
        access_handle.close()
        access_path = self._directory / _OUTPUT_PATHS["access_log"]
        access_metadata = _verify_regular(access_path, "quarantine access log")
        if (access_metadata.st_dev, access_metadata.st_ino) != self._identities["access_log"]:
            _fail("quarantine access-log identity changed")
        access_raw = _read_pinned_at(
            self._directory_descriptor,
            self._directory,
            _OUTPUT_PATHS["access_log"],
            "quarantine access log",
            expected_identity=self._identities["access_log"],
        )
        access_entries = _validate_access_log_bytes(
            access_raw,
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=request.attempt_ordinal,
            actor_id=request.actor_id,
            execution_context_sha256=request.execution_context.sha256,
        )
        expected_final_event = "seal_started" if status == "sealed" else "failure_seal_started"
        if access_entries[-1]["event_type"] != expected_final_event:
            _fail("quarantine status and access-log lifecycle disagree")
        artifact_bytes = {"access_log": access_raw}
        for name, handle in self._handles.items():
            if name == "access_log":
                continue
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            path = self._directory / _OUTPUT_PATHS[name]
            metadata = _verify_regular(path, f"quarantine {name}")
            if (metadata.st_dev, metadata.st_ino) != self._identities[name]:
                _fail("quarantine output identity changed")
            artifact_bytes[name] = _read_pinned_at(
                self._directory_descriptor,
                self._directory,
                _OUTPUT_PATHS[name],
                f"quarantine {name}",
                expected_identity=self._identities[name],
            )
        artifacts = []
        for name in QUARANTINE_OUTPUT_NAMES:
            raw = artifact_bytes[name]
            artifacts.append(
                {
                    "name": name,
                    "relative_path": _OUTPUT_PATHS[name],
                    "sha256": sha256_bytes(raw),
                    "size_bytes": len(raw),
                }
            )
        _validate_output_log_sizes(
            access_entries,
            {name: len(artifact_bytes[name]) for name in _WRITABLE_OUTPUTS},
        )
        manifest = {
            "schema_version": QUARANTINE_MANIFEST_SCHEMA_VERSION,
            "artifact_type": "gate_b_test_quarantine_manifest",
            "test_batch_hash": self.test_batch_hash,
            "attempt_ordinal": self.attempt_ordinal,
            "status": status,
            "batch_manifest_sha256": request.batch.sha256,
            "started_record_sha256": started_record_sha256,
            "sealed_at_utc": sealed_at_utc or _now_utc(),
            "artifacts": artifacts,
        }
        raw = canonical_json_bytes(manifest)
        path = _write_exclusive_at(
            self._directory_descriptor,
            self._directory,
            "quarantine-manifest.json",
            raw,
        )
        expected_names = set(_OUTPUT_PATHS.values()) | {"quarantine-manifest.json"}
        if _directory_names_at(self._directory_descriptor, self._directory) != expected_names:
            _fail("sealed quarantine contains unexpected entries")
        os.close(self._directory_descriptor)
        self._directory_descriptor = -1
        os.close(self._batch_descriptor)
        self._batch_descriptor = -1
        os.close(self._base_descriptor)
        self._base_descriptor = -1
        self._sealed = True
        return path, sha256_bytes(raw)


@dataclass(frozen=True, slots=True)
class _PinnedQuarantineFile:
    identity: tuple[int, int]
    size_bytes: int
    sha256: str


@dataclass(slots=True)
class _PinnedQuarantineLoad(AbstractContextManager["_PinnedQuarantineLoad"]):
    manifest: dict[str, Any]
    access_raw: bytes
    _base_directory: Path = field(repr=False)
    _base_identity: tuple[int, int] = field(repr=False)
    _base_descriptor: int = field(repr=False)
    _batch_directory: Path = field(repr=False)
    _batch_identity: tuple[int, int] = field(repr=False)
    _batch_claim_identity: tuple[int, int] = field(repr=False)
    _batch_descriptor: int = field(repr=False)
    _attempt_directory: Path = field(repr=False)
    _attempt_identity: tuple[int, int] = field(repr=False)
    _attempt_claim_identity: tuple[int, int] = field(repr=False)
    _attempt_descriptor: int = field(repr=False)
    _candidate: Path = field(repr=False)
    _files: Mapping[str, _PinnedQuarantineFile] = field(repr=False)
    _closed: bool = field(default=False, repr=False)

    def __enter__(self) -> _PinnedQuarantineLoad:
        if self._closed:
            _fail("pinned quarantine evidence is already closed")
        return self

    def verify_identity(self, request: GateBRequestLike) -> None:
        _reject_v2_request(request)
        if self._closed:
            _fail("pinned quarantine evidence is already closed")
        base, base_identity = _verify_pinned_root_descriptor(
            request.roots["quarantine_base"],
            "quarantine_base",
            self._base_descriptor,
        )
        batch_name = request.batch.test_batch_hash
        attempt_name = f"attempt-{request.attempt_ordinal:06d}"
        expected_batch = base / batch_name
        expected_attempt = expected_batch / attempt_name
        expected_candidate = expected_attempt / "quarantine-manifest.json"
        if (
            str(base) != str(self._base_directory)
            or base_identity != self._base_identity
            or str(expected_batch) != str(self._batch_directory)
            or str(expected_attempt) != str(self._attempt_directory)
            or str(expected_candidate) != str(self._candidate)
        ):
            _fail("pinned quarantine path or base identity changed")
        _verify_directory_entry_identity(
            self._base_descriptor,
            self._base_directory,
            batch_name,
            self._batch_identity,
            "pinned quarantine batch namespace",
        )
        batch_identity, batch_claim_identity = _verify_namespace_claim(
            self._base_directory,
            self._batch_directory,
            kind="quarantine_batch",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=None,
            base_descriptor=self._base_descriptor,
            namespace_descriptor=self._batch_descriptor,
        )
        _verify_directory_entry_identity(
            self._batch_descriptor,
            self._batch_directory,
            attempt_name,
            self._attempt_identity,
            "pinned quarantine attempt namespace",
        )
        attempt_identity, attempt_claim_identity = _verify_namespace_claim(
            self._base_directory,
            self._attempt_directory,
            kind="quarantine_attempt",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=request.attempt_ordinal,
            base_descriptor=self._base_descriptor,
            namespace_descriptor=self._attempt_descriptor,
        )
        if (
            batch_identity != self._batch_identity
            or batch_claim_identity != self._batch_claim_identity
            or attempt_identity != self._attempt_identity
            or attempt_claim_identity != self._attempt_claim_identity
        ):
            _fail("pinned quarantine namespace claim changed")
        if _directory_names_at(
            self._attempt_descriptor,
            self._attempt_directory,
        ) != set(self._files):
            _fail("pinned quarantine exact artifact topology changed")
        for name, expected in self._files.items():
            metadata = _regular_metadata_at(
                self._attempt_descriptor,
                self._attempt_directory,
                name,
                "pinned quarantine artifact",
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if identity != expected.identity or metadata.st_size != expected.size_bytes:
                _fail("pinned quarantine artifact identity or size changed")
            raw = _read_pinned_at(
                self._attempt_descriptor,
                self._attempt_directory,
                name,
                "pinned quarantine artifact",
                expected_identity=expected.identity,
            )
            if len(raw) != expected.size_bytes or sha256_bytes(raw) != expected.sha256:
                _fail("pinned quarantine artifact bytes changed")

    def close(self) -> None:
        if self._closed:
            return
        first_error: BaseException | None = None
        for name in (
            "_attempt_descriptor",
            "_batch_descriptor",
            "_base_descriptor",
        ):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                setattr(self, name, -1)
        self._closed = True
        if first_error is not None:
            raise GateBLedgerError("pinned quarantine evidence close failed") from first_error

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def _open_quarantine(
    request: GateBRequestLike,
    path: Path | str,
    expected_sha256: str,
) -> _PinnedQuarantineLoad:
    _reject_v2_request(request)
    _six_digit_positive(request.attempt_ordinal, "quarantine attempt ordinal")
    expected_hash = _sha(expected_sha256, "expected quarantine manifest hash")
    quarantine_base = _verify_root_ref(request.roots["quarantine_base"], "quarantine_base")
    base_descriptor = _open_directory_descriptor(quarantine_base)
    batch_descriptor = -1
    attempt_descriptor = -1
    try:
        quarantine_base, base_identity = _verify_pinned_root_descriptor(
            request.roots["quarantine_base"],
            "quarantine_base",
            base_descriptor,
        )
        batch_name = request.batch.test_batch_hash
        batch_directory = quarantine_base / batch_name
        batch_descriptor = _open_directory_at(
            base_descriptor,
            quarantine_base,
            batch_name,
            "pinned quarantine batch namespace",
        )
        batch_identity, batch_claim_identity = _verify_namespace_claim(
            quarantine_base,
            batch_directory,
            kind="quarantine_batch",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=None,
            base_descriptor=base_descriptor,
            namespace_descriptor=batch_descriptor,
        )
        attempt_name = f"attempt-{request.attempt_ordinal:06d}"
        attempt_directory = batch_directory / attempt_name
        attempt_descriptor = _open_directory_at(
            batch_descriptor,
            batch_directory,
            attempt_name,
            "pinned quarantine attempt namespace",
        )
        attempt_identity, attempt_claim_identity = _verify_namespace_claim(
            quarantine_base,
            attempt_directory,
            kind="quarantine_attempt",
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=request.attempt_ordinal,
            base_descriptor=base_descriptor,
            namespace_descriptor=attempt_descriptor,
        )
        candidate = Path(path)
        expected_candidate = attempt_directory / "quarantine-manifest.json"
        if not candidate.is_absolute() or str(candidate) != str(expected_candidate):
            _fail("quarantine manifest is outside its exact derived namespace")
        manifest, access_raw, files = _load_quarantine_pinned(
            request,
            candidate,
            expected_hash,
            attempt_directory,
            attempt_descriptor,
        )
        pinned = _PinnedQuarantineLoad(
            manifest=manifest,
            access_raw=access_raw,
            _base_directory=quarantine_base,
            _base_identity=base_identity,
            _base_descriptor=base_descriptor,
            _batch_directory=batch_directory,
            _batch_identity=batch_identity,
            _batch_claim_identity=batch_claim_identity,
            _batch_descriptor=batch_descriptor,
            _attempt_directory=attempt_directory,
            _attempt_identity=attempt_identity,
            _attempt_claim_identity=attempt_claim_identity,
            _attempt_descriptor=attempt_descriptor,
            _candidate=candidate,
            _files=files,
        )
        pinned.verify_identity(request)
        return pinned
    except BaseException:
        if attempt_descriptor >= 0:
            os.close(attempt_descriptor)
        if batch_descriptor >= 0:
            os.close(batch_descriptor)
        os.close(base_descriptor)
        raise


def _load_quarantine(
    request: GateBRequestLike,
    path: Path | str,
    expected_sha256: str,
) -> tuple[dict[str, Any], bytes]:
    _reject_v2_request(request)
    with _open_quarantine(request, path, expected_sha256) as pinned:
        pinned.verify_identity(request)
        return pinned.manifest, pinned.access_raw


def _load_quarantine_pinned(
    request: GateBRequestLike,
    candidate: Path,
    expected_hash: str,
    expected_directory: Path,
    directory_descriptor: int,
) -> tuple[dict[str, Any], bytes, Mapping[str, _PinnedQuarantineFile]]:
    _reject_v2_request(request)
    manifest_metadata = _regular_metadata_at(
        directory_descriptor,
        expected_directory,
        candidate.name,
        "quarantine manifest",
    )
    manifest_identity = (manifest_metadata.st_dev, manifest_metadata.st_ino)
    raw = _read_pinned_at(
        directory_descriptor,
        expected_directory,
        candidate.name,
        "quarantine manifest",
        expected_identity=manifest_identity,
    )
    if sha256_bytes(raw) != expected_hash:
        _fail("quarantine manifest hash mismatch")
    files: dict[str, _PinnedQuarantineFile] = {
        candidate.name: _PinnedQuarantineFile(
            identity=manifest_identity,
            size_bytes=len(raw),
            sha256=expected_hash,
        )
    }
    value = _strict_canonical_object(raw, "quarantine manifest")
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "test_batch_hash",
            "attempt_ordinal",
            "status",
            "batch_manifest_sha256",
            "started_record_sha256",
            "sealed_at_utc",
            "artifacts",
        },
        "quarantine manifest",
    )
    _six_digit_positive(value["attempt_ordinal"], "quarantine manifest attempt ordinal")
    if (
        value["schema_version"] != QUARANTINE_MANIFEST_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_test_quarantine_manifest"
        or value["test_batch_hash"] != request.batch.test_batch_hash
        or value["attempt_ordinal"] != request.attempt_ordinal
        or value["batch_manifest_sha256"] != request.batch.sha256
        or value["status"] not in {"sealed", "failed_closed"}
    ):
        _fail("quarantine manifest identity mismatch")
    _timestamp(value["sealed_at_utc"], "quarantine seal")
    if value["status"] == "sealed":
        _sha(value["started_record_sha256"], "quarantine STARTED record hash")
    elif value["started_record_sha256"] is not None:
        _sha(value["started_record_sha256"], "failed quarantine STARTED hash")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(QUARANTINE_OUTPUT_NAMES):
        _fail("quarantine artifact list is incomplete")
    physical_identities = {manifest_identity}
    artifact_identities = {}
    artifact_sizes = {}
    for raw_ref, name in zip(artifacts, QUARANTINE_OUTPUT_NAMES, strict=True):
        ref = _closed(raw_ref, {"name", "relative_path", "sha256", "size_bytes"}, "artifact")
        if ref["name"] != name or ref["relative_path"] != _OUTPUT_PATHS[name]:
            _fail("quarantine artifact order or path mismatch")
        expected_artifact_hash = _sha(ref["sha256"], "quarantine artifact hash")
        if (
            isinstance(ref["size_bytes"], bool)
            or not isinstance(ref["size_bytes"], int)
            or ref["size_bytes"] < 0
        ):
            _fail("quarantine artifact size is invalid")
        metadata = _regular_metadata_at(
            directory_descriptor,
            expected_directory,
            ref["relative_path"],
            "artifact",
        )
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in physical_identities:
            _fail("quarantine artifact physical alias detected")
        physical_identities.add(identity)
        artifact_identities[name] = identity
        artifact_raw = _read_pinned_at(
            directory_descriptor,
            expected_directory,
            ref["relative_path"],
            "artifact",
            expected_identity=identity,
        )
        if (
            len(artifact_raw) != ref["size_bytes"]
            or sha256_bytes(artifact_raw) != expected_artifact_hash
        ):
            _fail("quarantine artifact bytes changed")
        files[ref["relative_path"]] = _PinnedQuarantineFile(
            identity=identity,
            size_bytes=ref["size_bytes"],
            sha256=expected_artifact_hash,
        )
        artifact_sizes[name] = len(artifact_raw)
    if _directory_names_at(directory_descriptor, expected_directory) != set(
        _OUTPUT_PATHS.values()
    ) | {"quarantine-manifest.json"}:
        _fail("quarantine directory topology mismatch")
    access_raw = _read_pinned_at(
        directory_descriptor,
        expected_directory,
        _OUTPUT_PATHS["access_log"],
        "access log",
        expected_identity=artifact_identities["access_log"],
    )
    access_entries = _validate_access_log_bytes(
        access_raw,
        test_batch_hash=request.batch.test_batch_hash,
        attempt_ordinal=request.attempt_ordinal,
        actor_id=request.actor_id,
        execution_context_sha256=request.execution_context.sha256,
    )
    expected_final_event = "seal_started" if value["status"] == "sealed" else "failure_seal_started"
    if access_entries[-1]["event_type"] != expected_final_event:
        _fail("quarantine status and access-log lifecycle disagree")
    _validate_output_log_sizes(access_entries, artifact_sizes)
    return value, access_raw, MappingProxyType(files)


def _validate_failed_access_evidence(
    request: GateBRequestLike,
    failed_record: GateBLedgerRecord,
    access_raw: bytes,
) -> None:
    _reject_v2_request(request)
    entries = _validate_access_log_bytes(
        access_raw,
        test_batch_hash=request.batch.test_batch_hash,
        attempt_ordinal=request.attempt_ordinal,
        actor_id=request.actor_id,
        execution_context_sha256=request.execution_context.sha256,
    )
    failures = [entry for entry in entries if entry["event_type"] in _FAILURE_EVENT_BINDINGS]
    if len(failures) != 1:
        _fail("failed access evidence is not singular")
    failure = failures[0]
    failure_class, from_state = _FAILURE_EVENT_BINDINGS[failure["event_type"]]
    expected_reason = request.batch.reason_for(failure_class, from_state)
    if (
        failed_record.to_state != "FAILED_CLOSED"
        or failed_record.from_state != from_state
        or failed_record.payload["reason_id"] != expected_reason
        or failure["failure_class"] != failure_class
        or failure["reason_id"] != expected_reason
    ):
        _fail("FAILED_CLOSED record and access-log failure evidence disagree")


@_sanitized_api
def mark_gate_b_failed_closed(
    request: GateBRequestLike,
    reservation: GateBAttemptReservation | GateBLedgerRecord,
    *,
    failure_class: str,
    quarantine_manifest_path: Path | str,
    expected_quarantine_manifest_sha256: str,
) -> GateBLedgerRecord:
    """Append a mapped FAILED_CLOSED transition after complete failed sealing."""
    with _open_quarantine(
        request,
        quarantine_manifest_path,
        expected_quarantine_manifest_sha256,
    ) as pinned:
        manifest = pinned.manifest
        access_raw = pinned.access_raw
        if manifest["status"] != "failed_closed":
            _fail("FAILED_CLOSED requires a failed-closed quarantine manifest")
        store = GateBLedgerStore(request)
        with store.lock():
            pinned.verify_identity(request)
            chain = store.load_chain()
            latest = chain[-1] if chain else None
            if latest is None or latest.to_state not in {"RESERVED", "STARTED"}:
                _fail("ledger is not in a failure-eligible state")
            if isinstance(reservation, GateBAttemptReservation):
                if latest.record_sha256 != reservation.reserved_record_sha256:
                    _fail("failure reservation is stale")
            elif latest.record_sha256 != reservation.record_sha256:
                _fail("failure STARTED record is stale")
            from_state = latest.to_state
            reason_id = request.batch.reason_for(failure_class, from_state)
            entries = _validate_access_log_bytes(
                access_raw,
                test_batch_hash=request.batch.test_batch_hash,
                attempt_ordinal=request.attempt_ordinal,
                actor_id=request.actor_id,
                execution_context_sha256=request.execution_context.sha256,
            )
            failures = [entry for entry in entries if entry["failure_class"] is not None]
            if (
                len(failures) != 1
                or failures[0]["failure_class"] != failure_class
                or failures[0]["reason_id"] != reason_id
            ):
                _fail("failure map, access log, and ledger disagree")
            expected_started = latest.record_sha256 if from_state == "STARTED" else None
            if manifest["started_record_sha256"] != expected_started:
                _fail("failed quarantine STARTED binding mismatch")
            payload = _new_record(
                request,
                latest,
                attempt_ordinal=request.attempt_ordinal,
                from_state=from_state,
                to_state="FAILED_CLOSED",
                actor_id=request.actor_id,
                actor_role="test_runner",
                reason_id=reason_id,
                reason_detail_sha256=_canonical_reason_detail_sha256(reason_id),
                quarantine_manifest_sha256=expected_quarantine_manifest_sha256,
            )
            pinned.verify_identity(request)
            record = store.append(payload)
            pinned.verify_identity(request)
            return record


@_sanitized_api
def seal_gate_b_attempt(
    request: GateBRequestLike,
    started_record: GateBLedgerRecord,
    *,
    quarantine_manifest_path: Path | str,
    expected_quarantine_manifest_sha256: str,
) -> GateBLedgerRecord:
    """Append SEALED only after exact quarantine reopen and rehash."""
    with _open_quarantine(
        request,
        quarantine_manifest_path,
        expected_quarantine_manifest_sha256,
    ) as pinned:
        manifest = pinned.manifest
        if (
            manifest["status"] != "sealed"
            or manifest["started_record_sha256"] != started_record.record_sha256
        ):
            _fail("SEALED quarantine binding mismatch")
        store = GateBLedgerStore(request)
        with store.lock():
            pinned.verify_identity(request)
            chain = store.load_chain()
            latest = chain[-1] if chain else None
            if latest is None or latest.record_sha256 != started_record.record_sha256:
                _fail("STARTED record is no longer latest")
            payload = _new_record(
                request,
                latest,
                attempt_ordinal=started_record.attempt_ordinal,
                from_state="STARTED",
                to_state="SEALED",
                actor_id=request.actor_id,
                actor_role="test_runner",
                quarantine_manifest_sha256=expected_quarantine_manifest_sha256,
            )
            pinned.verify_identity(request)
            record = store.append(payload)
            pinned.verify_identity(request)
            return record


def _authorization_path(
    store: GateBLedgerStore, kind: str, ordinal: int, authorization_hash: str
) -> Path:
    if kind not in {"release", "retry"}:
        _fail("authorization kind is invalid")
    _six_digit_positive(ordinal, "authorization attempt ordinal")
    authorization_hash = _sha(authorization_hash, "authorization hash")
    return store.authorization_directory / (
        f"{kind}-attempt-{ordinal:06d}-{authorization_hash}.json"
    )


@_sanitized_api
def authorize_gate_b_release(
    request: GateBRequestLike,
    sealed_record: GateBLedgerRecord,
    *,
    authorization_path: Path | str,
    expected_authorization_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
) -> GateBLedgerRecord:
    """Append or idempotently return the one durable RELEASED transition."""
    expected_authorization_sha256 = _sha(
        expected_authorization_sha256,
        "release authorization hash",
    )
    expected_approval_record_sha256 = _sha(
        expected_approval_record_sha256,
        "release approval record hash",
    )
    expected_signature_record_sha256 = _sha(
        expected_signature_record_sha256,
        "release signature record hash",
    )
    store = GateBLedgerStore(request)
    expected_path = _authorization_path(
        store, "release", sealed_record.attempt_ordinal, expected_authorization_sha256
    )
    supplied_path = Path(authorization_path)
    if not supplied_path.is_absolute() or str(supplied_path) != str(expected_path):
        _fail("release authorization path is outside its derived namespace")
    authorization_raw = store.read_authorization(supplied_path, "release authorization")
    if sha256_bytes(authorization_raw) != expected_authorization_sha256:
        _fail("release authorization stored-byte hash mismatch")
    authorization = load_gate_b_release_authorization(
        supplied_path,
        expected_sha256=expected_authorization_sha256,
        expected_approval_record_sha256=expected_approval_record_sha256,
        expected_signature_record_sha256=expected_signature_record_sha256,
    )
    if store.read_authorization(supplied_path, "release authorization") != authorization_raw:
        _fail("release authorization changed during validation")
    store._verify_namespace()
    auth = authorization.payload
    manifest_path = (
        Path(request.roots["quarantine_base"]["absolute_path"])
        / request.batch.test_batch_hash
        / f"attempt-{request.attempt_ordinal:06d}"
        / "quarantine-manifest.json"
    )
    with (
        _open_quarantine(
            request,
            manifest_path,
            sealed_record.payload["quarantine_manifest_sha256"],
        ) as pinned,
        store.lock(),
    ):
        pinned.verify_identity(request)
        chain = store.load_chain()
        latest = chain[-1] if chain else None
        idempotent = (
            latest is not None
            and latest.to_state == "RELEASED"
            and latest.payload["authorization_record_sha256"] == expected_authorization_sha256
        )
        if idempotent:
            if (
                len(chain) < 2
                or chain[-2].record_sha256 != sealed_record.record_sha256
                or latest.payload["quarantine_manifest_sha256"]
                != sealed_record.payload["quarantine_manifest_sha256"]
            ):
                _fail("idempotent release source record mismatch")
        elif latest is None or latest.record_sha256 != sealed_record.record_sha256:
            _fail("sealed record is stale or already transitioned")
        manifest = pinned.manifest
        access_raw = pinned.access_raw
        if (
            auth["test_batch_hash"] != request.batch.test_batch_hash
            or auth["attempt_ordinal"] != request.attempt_ordinal
            or auth["sealed_record_sha256"] != sealed_record.record_sha256
            or auth["quarantine_manifest_sha256"]
            != sealed_record.payload["quarantine_manifest_sha256"]
            or auth["access_log_sha256"] != sha256_bytes(access_raw)
            or auth["approver_id"] != request.readiness.payload["designated_release_approver_id"]
            or auth["approver_role"]
            != request.readiness.payload["designated_release_approver_role"]
            or manifest["status"] != "sealed"
        ):
            _fail("release authorization evidence mismatch")
        if idempotent:
            pinned.verify_identity(request)
            return latest
        payload = _new_record(
            request,
            latest,
            attempt_ordinal=request.attempt_ordinal,
            from_state="SEALED",
            to_state="RELEASED",
            actor_id=auth["approver_id"],
            actor_role=auth["approver_role"],
            quarantine_manifest_sha256=sealed_record.payload["quarantine_manifest_sha256"],
            authorization_record_sha256=expected_authorization_sha256,
        )
        pinned.verify_identity(request)
        record = store.append(payload)
        pinned.verify_identity(request)
        return record


@_sanitized_api
def authorize_gate_b_retry(
    request: GateBRequestLike,
    failed_record: GateBLedgerRecord,
    *,
    authorization_path: Path | str,
    expected_authorization_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
) -> GateBLedgerRecord:
    """Append or idempotently return a role-separated retry authorization."""
    expected_authorization_sha256 = _sha(
        expected_authorization_sha256,
        "retry authorization hash",
    )
    expected_approval_record_sha256 = _sha(
        expected_approval_record_sha256,
        "retry approval record hash",
    )
    expected_signature_record_sha256 = _sha(
        expected_signature_record_sha256,
        "retry signature record hash",
    )
    store = GateBLedgerStore(request)
    expected_path = _authorization_path(
        store, "retry", failed_record.attempt_ordinal, expected_authorization_sha256
    )
    supplied_path = Path(authorization_path)
    if not supplied_path.is_absolute() or str(supplied_path) != str(expected_path):
        _fail("retry authorization path is outside its derived namespace")
    authorization_raw = store.read_authorization(supplied_path, "retry authorization")
    if sha256_bytes(authorization_raw) != expected_authorization_sha256:
        _fail("retry authorization stored-byte hash mismatch")
    authorization = load_gate_b_retry_authorization(
        supplied_path,
        expected_sha256=expected_authorization_sha256,
        expected_approval_record_sha256=expected_approval_record_sha256,
        expected_signature_record_sha256=expected_signature_record_sha256,
    )
    if store.read_authorization(supplied_path, "retry authorization") != authorization_raw:
        _fail("retry authorization changed during validation")
    store._verify_namespace()
    auth = authorization.payload
    manifest_path = (
        Path(request.roots["quarantine_base"]["absolute_path"])
        / request.batch.test_batch_hash
        / f"attempt-{request.attempt_ordinal:06d}"
        / "quarantine-manifest.json"
    )
    with (
        _open_quarantine(
            request,
            manifest_path,
            failed_record.payload["quarantine_manifest_sha256"],
        ) as pinned,
        store.lock(),
    ):
        pinned.verify_identity(request)
        chain = store.load_chain()
        latest = chain[-1] if chain else None
        idempotent = (
            latest is not None
            and latest.to_state == "RETRY_AUTHORIZED"
            and latest.payload["authorization_record_sha256"] == expected_authorization_sha256
        )
        if idempotent:
            if (
                len(chain) < 2
                or chain[-2].record_sha256 != failed_record.record_sha256
                or latest.payload["quarantine_manifest_sha256"]
                != failed_record.payload["quarantine_manifest_sha256"]
                or latest.payload["reason_id"] != failed_record.payload["reason_id"]
            ):
                _fail("idempotent retry source record mismatch")
        elif latest is None or latest.record_sha256 != failed_record.record_sha256:
            _fail("failed record is stale or already transitioned")
        manifest = pinned.manifest
        access_raw = pinned.access_raw
        selection_hash, coordinates_hash = request.batch.roots_independent_digests
        _require_reason_eligible(
            failed_record.payload["reason_id"],
            failed_record.from_state,
            store._retry_catalog,
        )
        _validate_failed_access_evidence(request, failed_record, access_raw)
        if (
            auth["test_batch_hash"] != request.batch.test_batch_hash
            or auth["failed_record_sha256"] != failed_record.record_sha256
            or auth["failed_attempt_ordinal"] != failed_record.attempt_ordinal
            or auth["quarantine_manifest_sha256"]
            != failed_record.payload["quarantine_manifest_sha256"]
            or auth["access_log_sha256"] != sha256_bytes(access_raw)
            or auth["technical_reason_id"] != failed_record.payload["reason_id"]
            or auth["approver_id"] != request.readiness.payload["designated_retry_approver_id"]
            or auth["approver_role"] != request.readiness.payload["designated_retry_approver_role"]
            or auth["failed_runner_actor_id"] != request.actor_id
            or auth["next_attempt_ordinal"] != failed_record.attempt_ordinal + 1
            or auth["unchanged_implementation_commit"] != request.batch.payload["git"]["commit_oid"]
            or auth["unchanged_batch_manifest_sha256"] != request.batch.sha256
            or auth["unchanged_selection_sha256"] != selection_hash
            or auth["unchanged_coordinates_sha256"] != coordinates_hash
            or manifest["status"] != "failed_closed"
        ):
            _fail("retry authorization evidence mismatch")
        if idempotent:
            pinned.verify_identity(request)
            return latest
        payload = _new_record(
            request,
            latest,
            attempt_ordinal=request.attempt_ordinal,
            from_state="FAILED_CLOSED",
            to_state="RETRY_AUTHORIZED",
            actor_id=auth["approver_id"],
            actor_role=auth["approver_role"],
            reason_id=auth["technical_reason_id"],
            quarantine_manifest_sha256=failed_record.payload["quarantine_manifest_sha256"],
            authorization_record_sha256=expected_authorization_sha256,
            next_attempt_ordinal=auth["next_attempt_ordinal"],
        )
        pinned.verify_identity(request)
        record = store.append(payload)
        pinned.verify_identity(request)
        return record
