"""Closed-world Gate B pre-Test contracts.

This module implements a fail-closed research governance boundary. It is not a
security sandbox against a host administrator or malicious in-process code.
Actual Test roots and operational values are always explicit caller inputs.
"""

from __future__ import annotations

import copy
import ctypes
import json
import os
import re
import stat
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from phase6.contracts import canonical_json_bytes, sha256_bytes

BATCH_MANIFEST_SCHEMA_VERSION = "phase6-gate-b-test-batch-manifest-v1"
ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION = "phase6-gate-b-attempt-ledger-record-v1"
QUARANTINE_MANIFEST_SCHEMA_VERSION = "phase6-gate-b-quarantine-manifest-v1"
LOADER_REQUEST_SCHEMA_VERSION = "phase6-gate-b-test-loader-request-v1"
READINESS_AUTHORIZATION_SCHEMA_VERSION = "phase6-gate-b-readiness-authorization-v2"
HUMAN_APPROVAL_RECORD_SCHEMA_VERSION = "phase6-gate-b-human-approval-record-v2"
HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION = "phase6-gate-b-human-signature-record-v2"
RELEASE_AUTHORIZATION_SCHEMA_VERSION = "phase6-gate-b-release-authorization-v1"
RETRY_AUTHORIZATION_SCHEMA_VERSION = "phase6-gate-b-retry-authorization-v1"
ROOT_ANCHOR_SCHEMA_VERSION = "phase6-gate-b-root-anchor-v1"
PREAPPROVAL_ROOT_IDENTITY_PROJECTION_SCHEMA_VERSION = (
    "phase6-gate-b-preapproval-root-identity-projection-v1"
)
PREAPPROVAL_ROOT_IDENTITY_PROJECTION_V2_SCHEMA_VERSION = (
    "phase6-gate-b-preapproval-root-identity-projection-v2"
)
ROOT_IDENTITY_PROJECTION_DESCRIPTOR_V2_SCHEMA_VERSION = (
    "phase6-gate-b-root-identity-projection-descriptor-v2"
)
ROOT_IDENTITY_SERIALIZATION_PROFILE_V2 = "windows-volume8-file16-lowerhex-v1"
HUMAN_APPROVAL_RECORD_V3_SCHEMA_VERSION = "phase6-gate-b-human-approval-record-v3"
HUMAN_SIGNATURE_RECORD_V3_SCHEMA_VERSION = "phase6-gate-b-human-signature-record-v3"
READINESS_AUTHORIZATION_V3_SCHEMA_VERSION = "phase6-gate-b-readiness-authorization-v3"
ROOT_ANCHOR_V2_SCHEMA_VERSION = "phase6-gate-b-root-anchor-v2"
LOADER_REQUEST_V2_SCHEMA_VERSION = "phase6-gate-b-test-loader-request-v2"
SOURCE_MATERIALIZATION_PROJECTION_SIZE_BYTES = 1111
SOURCE_MATERIALIZATION_PROJECTION_SHA256 = (
    "134f7169a949b41de3bb0b6de8f9c80c3e65cab477d31bae2581281df8c57a09"
)
ROOT_ANCHOR_POLICY_VERSION = "phase6-gate-b-root-anchor-policy-v1"
OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION = "phase6-gate-b-opponent-payload-index-v1"
EXECUTION_CONFIG_INDEX_SCHEMA_VERSION = "phase6-gate-b-execution-config-index-v1"
EXECUTION_CONTEXT_SCHEMA_VERSION = "phase6-gate-b-execution-context-v1"
ACCESS_LOG_ENTRY_SCHEMA_VERSION = "phase6-gate-b-access-log-entry-v1"
TOPOLOGY_POLICY_VERSION = "phase6-gate-b-physical-topology-v1"
INPUT_FRAMING_VERSION = "phase6-gate-b-input-framing-v1"
DEPENDENCY_LOCK_SCHEMA_VERSION = "phase6-production-dependency-lock-v1"
SELECTED_CONFIG_LOCK_SCHEMA_VERSION = "phase6-selected-config-lock-v1"

ZERO_SHA256 = "0" * 64
MAX_INT63 = 1 << 63
COMPONENT_NAMES = (
    "baseline_table",
    "estimator_config",
    "evaluator",
    "execution_config_index",
    "execution_sampler",
    "ground_truth_extractor",
    "opponent_catalog",
    "opponent_payload_index",
    "selected_config_lock",
    "validation_selection_report",
)
LEDGER_STATES = (
    "RESERVED",
    "STARTED",
    "SEALED",
    "RELEASED",
    "FAILED_CLOSED",
    "RETRY_AUTHORIZED",
)
QUARANTINE_OUTPUT_NAMES = (
    "stdout",
    "stderr",
    "progress",
    "metrics",
    "log",
    "result",
    "access_log",
)
PREAPPROVAL_ROOT_ROLE_ORDER = ("ledger_base", "quarantine_base", "test_root")
FAILURE_CLASS_STATES = (
    ("execution_environment_failure", "RESERVED"),
    ("test_input_prestart_failure", "RESERVED"),
    ("started_append_failure", "RESERVED"),
    ("test_input_poststart_failure", "STARTED"),
    ("executor_callback_failure", "STARTED"),
)
ACTIVE_MODULE_PATHS = (
    ("phase6.contracts", "src/phase6/contracts.py"),
    ("phase6.gate_b_contracts", "src/phase6/gate_b_contracts.py"),
    ("phase6.gate_b_ledger", "src/phase6/gate_b_ledger.py"),
    ("phase6.gate_b_loader", "src/phase6/gate_b_loader.py"),
)

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_OID_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATOM_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_HEX_ID_RE = re.compile(r"(?:0|[1-9a-f][0-9a-f]*)\Z")
_DECIMAL_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d*[1-9])?\Z")
_HUMAN_RECORD_LOADER_TOKEN = object()
_PREAPPROVAL_PROJECTION_TOKEN = object()
_PREAPPROVAL_PROJECTION_V2_TOKEN = object()
_V2_TRUST_CHAIN_TOKEN = object()
_V2_PROJECTION_REGISTRY: dict[int, tuple[object, ...]] = {}
_V2_TRUST_CHAIN_REGISTRY: dict[int, tuple[object, ...]] = {}


class GateBContractError(ValueError):
    """Raised when an exact Gate B contract fails closed."""


def _sanitized_api(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        error_message: str | None = None
        try:
            return function(*args, **kwargs)
        except GateBContractError as exc:
            error_message = str(exc)
        except Exception:
            error_message = "Gate B contract operation failed closed"
        error = GateBContractError(error_message)
        error.__cause__ = None
        error.__context__ = None
        error.__traceback__ = None
        raise error

    return wrapped


def _fail(message: str) -> None:
    raise GateBContractError(message)


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON field")
        result[key] = value
    return result


def _strict_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    """Parse one exact canonical JSON object while rejecting duplicate fields."""
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda _value: _fail("non-finite JSON number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateBContractError(f"{label} is not strict canonical JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise GateBContractError(f"{label} is not canonical JSON") from exc
    if canonical != raw:
        _fail(f"{label} bytes are not canonical")
    return value


def _frozen(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _frozen(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_frozen(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _closed(value: object, fields: Sequence[str] | set[str], label: str) -> dict[str, Any]:
    expected = set(fields)
    if not isinstance(value, dict) or set(value) != expected:
        _fail(f"{label} fields are not closed-world")
    return value


def _exact_json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _exact_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _exact_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _ascii(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        _fail(f"{label} must be nonempty printable ASCII")
    return value


def _atom(value: object, label: str) -> str:
    text = _ascii(value, label)
    if _ATOM_RE.fullmatch(text) is None:
        _fail(f"{label} is not a canonical identifier")
    return text


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _oid(value: object, label: str) -> str:
    if not isinstance(value, str) or _OID_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase Git object ID")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        _fail(f"{label} must be fraction-free UTC RFC 3339")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GateBContractError(f"{label} must be fraction-free UTC RFC 3339") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} must use canonical UTC calendar fields")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_INT63,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{label} must be an integer")
    if value < minimum or value >= maximum:
        _fail(f"{label} is outside its integer domain")
    return value


def _hex_identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_ID_RE.fullmatch(value) is None:
        _fail(f"{label} must be canonical lowercase hexadecimal")
    return value


def _safe_relative_path(value: object, label: str) -> str:
    text = _ascii(value, label)
    path = PurePosixPath(text)
    if (
        "\\" in text
        or ":" in text
        or "://" in text
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != text
    ):
        _fail(f"{label} must be a canonical safe POSIX relative path")
    return text


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or any(ord(character) < 0x20 for character in value):
        _fail(f"{label} must be a nonempty path without control characters")
    text = value
    candidate = Path(text)
    if not candidate.is_absolute() or ".." in candidate.parts or str(candidate) != text:
        _fail(f"{label} must be absolute")
    return candidate


def _retained_reference_path(value: object, label: str) -> Path:
    """Validate retained join metadata without touching the filesystem."""
    if type(value) is not type(Path()):
        _fail(f"{label} must use the current concrete path type")
    text = str(value)
    if (
        not text
        or not value.is_absolute()
        or ".." in value.parts
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in text)
    ):
        _fail(f"{label} must be an absolute control-free retained reference")
    return value


def _native_io_path(path: Path) -> str | Path:
    if os.name != "nt":
        return path
    text = str(path)
    if text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def _windows_open_contract_descriptor(
    path: Path,
    *,
    _kernel32=None,
    _open_osfhandle=None,
) -> int:
    """Open one existing artifact without following its final reparse point."""
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
    handle = create_file(
        _native_io_path(path),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080 | 0x00200000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    handle_value = handle.value if isinstance(handle, ctypes.c_void_p) else handle
    if handle_value in (None, invalid):
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        return open_osfhandle(handle_value, flags)
    except BaseException:
        kernel32.CloseHandle(ctypes.c_void_p(handle_value))
        raise


def _required_posix_nofollow(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail("required POSIX O_NOFOLLOW primitive is unavailable")
    return value


def _open_contract_descriptor(path: Path) -> int:
    if os.name == "nt":
        return _windows_open_contract_descriptor(path)
    if os.name != "posix":
        _fail("unsupported artifact-open platform")
    nofollow = _required_posix_nofollow(getattr(os, "O_NOFOLLOW", None))
    return os.open(_native_io_path(path), os.O_RDONLY | nofollow)


def _contract_windows_stream_names(path: Path) -> tuple[str, ...]:
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
    handle = find_first(str(_native_io_path(path)), 0, ctypes.byref(data), 0)
    if handle in (None, invalid):
        _fail("required stream enumeration failed closed")
    names = [data.cStreamName]
    try:
        while find_next(handle, ctypes.byref(data)):
            names.append(data.cStreamName)
        if ctypes.get_last_error() not in {0, 38}:
            _fail("required stream enumeration failed closed")
    finally:
        find_close(handle)
    return tuple(names)


def _single_link_regular(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and not bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    )


def _unique_sequence(
    value: object,
    label: str,
    validator: Callable[[object, str], Any],
    *,
    allow_empty: bool,
) -> tuple[Any, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        _fail(f"{label} must be an ordered list")
    result = tuple(validator(item, f"{label} item") for item in value)
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicates")
    return result


def _validate_component_ref(value: object, expected_name: str) -> dict[str, Any]:
    ref = _closed(
        value,
        {"name", "relative_path", "schema_version", "sha256", "size_bytes"},
        f"{expected_name} component",
    )
    if _ascii(ref["name"], f"{expected_name} component name") != expected_name:
        _fail(f"{expected_name} component name mismatch")
    _safe_relative_path(ref["relative_path"], f"{expected_name} component path")
    _ascii(ref["schema_version"], f"{expected_name} component schema")
    _sha(ref["sha256"], f"{expected_name} component hash")
    _integer(ref["size_bytes"], f"{expected_name} component size", minimum=1)
    return ref


def _validate_selection_item(value: object, label: str) -> dict[str, Any]:
    item = _closed(value, {"config_id", "name", "sha256"}, label)
    _ascii(item["config_id"], f"{label} config ID")
    _ascii(item["name"], f"{label} name")
    _sha(item["sha256"], f"{label} hash")
    return item


def _validate_retry_catalog(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, list) or not value:
        _fail("technical retry reasons must be a nonempty ordered list")
    result: dict[str, tuple[str, ...]] = {}
    for index, raw in enumerate(value):
        item = _closed(raw, {"eligible_from_states", "reason_id"}, "retry reason")
        reason_id = _atom(item["reason_id"], "retry reason ID")
        if reason_id in result:
            _fail("technical retry reason IDs must be unique")
        states = item["eligible_from_states"]
        if (
            not isinstance(states, list)
            or not states
            or len(states) != len(set(states))
            or any(state not in {"RESERVED", "STARTED"} for state in states)
            or states != [state for state in ("RESERVED", "STARTED") if state in states]
        ):
            _fail(f"retry reason {index} states are not canonical")
        result[reason_id] = tuple(states)
    return result


def _validate_failure_map(
    value: object, catalog: Mapping[str, tuple[str, ...]]
) -> dict[tuple[str, str], str]:
    if not isinstance(value, list) or len(value) != len(FAILURE_CLASS_STATES):
        _fail("failure reason map must contain exactly five entries")
    result: dict[tuple[str, str], str] = {}
    for raw, expected in zip(value, FAILURE_CLASS_STATES, strict=True):
        item = _closed(raw, {"failure_class", "from_state", "reason_id"}, "failure map")
        actual = (
            _ascii(item["failure_class"], "failure class"),
            _ascii(item["from_state"], "failure map state"),
        )
        if actual != expected:
            _fail("failure reason map order or state is invalid")
        reason_id = _atom(item["reason_id"], "mapped reason ID")
        if reason_id not in catalog or expected[1] not in catalog[reason_id]:
            _fail("mapped failure reason is not eligible for its state")
        if actual in result:
            _fail("failure class mapping is duplicated")
        result[actual] = reason_id
    return result


def _validate_batch_manifest(value: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "artifact_type",
        "created_at_utc",
        "canonicalization",
        "git",
        "runtime",
        "components",
        "selection",
        "test_input",
        "coordinates",
        "ledger_policy",
        "quarantine_policy",
        "governance",
    }
    _closed(value, fields, "batch manifest")
    if value["schema_version"] != BATCH_MANIFEST_SCHEMA_VERSION:
        _fail("batch manifest schema version mismatch")
    if value["artifact_type"] != "gate_b_test_batch_manifest":
        _fail("batch manifest artifact type mismatch")
    _timestamp(value["created_at_utc"], "batch creation timestamp")

    canonicalization = _closed(
        value["canonicalization"],
        {"allow_nan", "encoding", "ensure_ascii", "separators", "sort_keys", "trailing_lf"},
        "canonicalization",
    )
    expected_canonicalization = {
        "allow_nan": False,
        "encoding": "utf-8",
        "ensure_ascii": True,
        "separators": [",", ":"],
        "sort_keys": True,
        "trailing_lf": True,
    }
    if not _exact_json_equal(canonicalization, expected_canonicalization):
        _fail("canonicalization policy mismatch")

    git = _closed(value["git"], {"branch", "commit_oid"}, "batch git")
    if git["branch"] != "main":
        _fail("batch branch must be main")
    _oid(git["commit_oid"], "batch commit")

    runtime = _closed(
        value["runtime"],
        {
            "dependency_lock",
            "machine",
            "os_name",
            "os_release",
            "python_implementation",
            "python_version",
        },
        "batch runtime",
    )
    lock = _closed(
        runtime["dependency_lock"],
        {"name", "schema_version", "sha256", "size_bytes"},
        "batch dependency lock",
    )
    if (
        lock["name"] != "dependency_lock"
        or lock["schema_version"] != DEPENDENCY_LOCK_SCHEMA_VERSION
    ):
        _fail("batch dependency lock identity mismatch")
    _sha(lock["sha256"], "batch dependency lock hash")
    _integer(lock["size_bytes"], "batch dependency lock size", minimum=1)
    for name in ("machine", "os_name", "os_release", "python_implementation", "python_version"):
        _ascii(runtime[name], f"batch runtime {name}")

    components = _closed(value["components"], set(COMPONENT_NAMES), "batch components")
    validated_components = {
        name: _validate_component_ref(components[name], name) for name in COMPONENT_NAMES
    }
    if (
        validated_components["opponent_payload_index"]["schema_version"]
        != OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION
        or validated_components["execution_config_index"]["schema_version"]
        != EXECUTION_CONFIG_INDEX_SCHEMA_VERSION
        or validated_components["selected_config_lock"]["schema_version"]
        != SELECTED_CONFIG_LOCK_SCHEMA_VERSION
    ):
        _fail("strict Gate B component schema mismatch")

    selection = _closed(
        value["selection"],
        {
            "ablations",
            "comparators",
            "manual_override",
            "primary_config_id",
            "primary_config_sha256",
            "selection_report_sha256",
        },
        "batch selection",
    )
    if selection["manual_override"] is not False:
        _fail("manual override must be false")
    primary_id = _ascii(selection["primary_config_id"], "primary config ID")
    primary_hash = _sha(selection["primary_config_sha256"], "primary config hash")
    _sha(selection["selection_report_sha256"], "selection report hash")
    if selection["selection_report_sha256"] != components["validation_selection_report"]["sha256"]:
        _fail("selection report hash join mismatch")
    if primary_hash == components["selected_config_lock"]["sha256"]:
        _fail("primary config hash must not identify the selected-lock wrapper")
    named_items: list[tuple[str, str]] = []
    for group_name in ("comparators", "ablations"):
        group = selection[group_name]
        if not isinstance(group, list):
            _fail(f"{group_name} must be an ordered list")
        for index, raw in enumerate(group):
            item = _validate_selection_item(raw, f"{group_name} {index}")
            named_items.append((item["config_id"], item["name"]))
    ids = [item[0] for item in named_items]
    names = [item[1] for item in named_items]
    if (
        len(ids) != len(set(ids))
        or len(names) != len(set(names))
        or primary_id in ids
        or "primary" in names
    ):
        _fail("selection IDs and names must be globally unique and exclude primary")

    test_input = _closed(
        value["test_input"],
        {
            "execution_config_index_sha256",
            "format_id",
            "framing_version",
            "opponent_payload_index_sha256",
            "physical_split_id",
            "split_id",
        },
        "batch Test input",
    )
    for name in ("format_id", "physical_split_id", "split_id"):
        _ascii(test_input[name], f"Test input {name}")
    if test_input["framing_version"] != INPUT_FRAMING_VERSION:
        _fail("Test input framing version mismatch")
    for name in ("execution_config_index_sha256", "opponent_payload_index_sha256"):
        _sha(test_input[name], f"Test input {name}")
    if (
        test_input["execution_config_index_sha256"]
        != components["execution_config_index"]["sha256"]
        or test_input["opponent_payload_index_sha256"]
        != components["opponent_payload_index"]["sha256"]
    ):
        _fail("Test input index hash join mismatch")

    coordinates = _closed(
        value["coordinates"],
        {"horizons", "opponent_ids", "repetition_ids", "seed_mapping"},
        "batch coordinates",
    )
    opponent_ids = _unique_sequence(
        coordinates["opponent_ids"], "opponent IDs", _ascii, allow_empty=False
    )
    repetition_ids = _unique_sequence(
        coordinates["repetition_ids"], "repetition IDs", _ascii, allow_empty=False
    )
    horizons_raw = coordinates["horizons"]
    if not isinstance(horizons_raw, list) or not horizons_raw:
        _fail("horizons must be a nonempty ordered list")
    horizons = tuple(_integer(item, "horizon", minimum=1) for item in horizons_raw)
    if tuple(sorted(set(horizons))) != horizons:
        _fail("horizons must be unique and strictly increasing")
    expected_coordinates = [
        (opponent_id, horizon, repetition_id)
        for opponent_id in opponent_ids
        for horizon in horizons
        for repetition_id in repetition_ids
    ]
    seed_mapping = coordinates["seed_mapping"]
    if not isinstance(seed_mapping, list) or len(seed_mapping) != len(expected_coordinates):
        _fail("seed mapping must cover the exact Cartesian product")
    for raw, expected in zip(seed_mapping, expected_coordinates, strict=True):
        item = _closed(raw, {"horizon", "opponent_id", "repetition_id", "seed"}, "seed mapping")
        _integer(item["horizon"], "seed mapping horizon", minimum=1)
        actual = (item["opponent_id"], item["horizon"], item["repetition_id"])
        if actual != expected:
            _fail("seed mapping order or coordinate mismatch")
        _integer(item["seed"], "seed")

    ledger_policy = _closed(
        value["ledger_policy"],
        {
            "cleanup",
            "exclusive_create",
            "namespace_derivation",
            "retain_partial",
            "states",
            "topology_policy_version",
        },
        "ledger policy",
    )
    if not _exact_json_equal(
        ledger_policy,
        {
            "cleanup": "never",
            "exclusive_create": True,
            "namespace_derivation": "ledger_base/<test_batch_hash>",
            "retain_partial": True,
            "states": list(LEDGER_STATES),
            "topology_policy_version": TOPOLOGY_POLICY_VERSION,
        },
    ):
        _fail("ledger policy mismatch")

    quarantine_policy = _closed(
        value["quarantine_policy"],
        {
            "exclusive_create",
            "namespace_derivation",
            "outputs",
            "read_before_release",
            "retain_partial",
            "stream_before_release",
        },
        "quarantine policy",
    )
    if not _exact_json_equal(
        quarantine_policy,
        {
            "exclusive_create": True,
            "namespace_derivation": "quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>",
            "outputs": list(QUARANTINE_OUTPUT_NAMES),
            "read_before_release": False,
            "retain_partial": True,
            "stream_before_release": False,
        },
    ):
        _fail("quarantine policy mismatch")

    governance = _closed(
        value["governance"],
        {
            "failure_reason_map",
            "ledger_manager_role",
            "release_approver_role",
            "retry_approver_role",
            "role_distinctness_required",
            "runner_role",
            "technical_retry_reasons",
        },
        "batch governance",
    )
    if (
        governance["ledger_manager_role"] != "ledger_manager"
        or governance["release_approver_role"] != "release_approver"
        or governance["retry_approver_role"] != "retry_approver"
        or governance["runner_role"] != "test_runner"
        or governance["role_distinctness_required"] is not True
    ):
        _fail("governance role policy mismatch")
    catalog = _validate_retry_catalog(governance["technical_retry_reasons"])
    _validate_failure_map(governance["failure_reason_map"], catalog)


def _validate_authorization_common(value: dict[str, Any], expected_schema: str, kind: str) -> None:
    if value["schema_version"] != expected_schema or value["artifact_type"] != kind:
        _fail("authorization schema identity mismatch")
    _atom(value["authorization_id"], "authorization ID")
    _timestamp(value["authorized_at_utc"], "authorization timestamp")
    _atom(value["approval_record_id"], "approval record ID")
    _sha(value["approval_record_sha256"], "approval record hash")
    _sha(value["signature_record_sha256"], "signature record hash")


def _validate_readiness_authorization(value: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "artifact_type",
        "authorization_id",
        "authorized_at_utc",
        "approval_record_id",
        "approval_record_sha256",
        "signature_record_sha256",
        "gate_b_ready",
        "test_batch_hash",
        "approved_implementation_commit",
        "approved_execution_context_sha256",
        "approved_roots_sha256",
        "authorized_runner_actor_id",
        "authorized_runner_role",
        "authorized_ledger_manager_actor_id",
        "authorized_ledger_manager_role",
        "designated_release_approver_id",
        "designated_release_approver_role",
        "designated_retry_approver_id",
        "designated_retry_approver_role",
        "ledger_namespace_derivation",
        "quarantine_namespace_derivation",
    }
    _closed(value, fields, "readiness authorization")
    _validate_authorization_common(
        value, READINESS_AUTHORIZATION_SCHEMA_VERSION, "gate_b_readiness_authorization"
    )
    if value["gate_b_ready"] is not True:
        _fail("readiness authorization must explicitly authorize Gate B")
    _sha(value["test_batch_hash"], "authorized batch hash")
    _oid(value["approved_implementation_commit"], "authorized implementation commit")
    _sha(value["approved_execution_context_sha256"], "authorized context hash")
    _sha(value["approved_roots_sha256"], "authorized roots hash")
    role_fields = (
        ("authorized_runner_actor_id", "authorized_runner_role", "test_runner"),
        (
            "authorized_ledger_manager_actor_id",
            "authorized_ledger_manager_role",
            "ledger_manager",
        ),
        (
            "designated_release_approver_id",
            "designated_release_approver_role",
            "release_approver",
        ),
        ("designated_retry_approver_id", "designated_retry_approver_role", "retry_approver"),
    )
    actor_ids = []
    for actor_field, role_field, expected_role in role_fields:
        actor_ids.append(_atom(value[actor_field], actor_field))
        if value[role_field] != expected_role:
            _fail("readiness role mismatch")
    if len(actor_ids) != len(set(actor_ids)):
        _fail("readiness actors must be pairwise distinct")
    if (
        value["ledger_namespace_derivation"] != "ledger_base/<test_batch_hash>"
        or value["quarantine_namespace_derivation"]
        != "quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>"
    ):
        _fail("readiness namespace policy mismatch")


_OPERATIONAL_ACTOR_FIELDS = (
    ("authorized_runner_actor_id", "authorized_runner_role", "test_runner"),
    (
        "authorized_ledger_manager_actor_id",
        "authorized_ledger_manager_role",
        "ledger_manager",
    ),
    (
        "designated_release_approver_id",
        "designated_release_approver_role",
        "release_approver",
    ),
    (
        "designated_retry_approver_id",
        "designated_retry_approver_role",
        "retry_approver",
    ),
)


def _validate_human_approval_record(value: dict[str, Any]) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "approval_record_id",
            "approved_at_utc",
            "approver_actor_id",
            "approver_role",
            "approval_decision",
            "approval_scope",
            "test_batch_hash",
            "approved_implementation_commit",
            "approved_execution_context_sha256",
            "approved_roots_sha256",
            "authorized_runner_actor_id",
            "authorized_runner_role",
            "authorized_ledger_manager_actor_id",
            "authorized_ledger_manager_role",
            "designated_release_approver_id",
            "designated_release_approver_role",
            "designated_retry_approver_id",
            "designated_retry_approver_role",
            "expected_attempt_ordinal",
            "release_authorized",
            "retry_authorized",
        },
        "human approval record",
    )
    if (
        value["schema_version"] != HUMAN_APPROVAL_RECORD_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_human_approval_record"
    ):
        _fail("human approval record schema identity mismatch")
    _atom(value["approval_record_id"], "approval record ID")
    _timestamp(value["approved_at_utc"], "approval timestamp")
    approver = _atom(value["approver_actor_id"], "approver actor ID")
    if (
        value["approver_role"] != "human_gate_b_approver"
        or value["approval_decision"] != "APPROVE_INITIAL_GATE_B_READINESS"
        or value["approval_scope"] != "initial_attempt_only"
    ):
        _fail("human approval policy mismatch")
    _sha(value["test_batch_hash"], "approved batch hash")
    _oid(value["approved_implementation_commit"], "approved implementation commit")
    _sha(value["approved_execution_context_sha256"], "approved context hash")
    _sha(value["approved_roots_sha256"], "approved roots hash")
    operational: list[str] = []
    for actor_field, role_field, expected_role in _OPERATIONAL_ACTOR_FIELDS:
        operational.append(_atom(value[actor_field], actor_field))
        if value[role_field] != expected_role:
            _fail("human approval operational role mismatch")
    if len(set(operational)) != len(operational):
        _fail("human approval operational actors must be pairwise distinct")
    if approver in operational:
        _fail("human approver must differ from every operational actor")
    if (
        _integer(
            value["expected_attempt_ordinal"],
            "human approval expected attempt ordinal",
            minimum=1,
            maximum=2,
        )
        != 1
        or value["release_authorized"] is not False
        or value["retry_authorized"] is not False
    ):
        _fail("human approval initial-attempt policy mismatch")


def _validate_human_signature_record(
    value: dict[str, Any],
    approval: Mapping[str, Any],
    approval_sha256: str,
) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "signature_record_id",
            "signed_at_utc",
            "signer_actor_id",
            "signer_role",
            "signature_method",
            "attestation",
            "approval_record_id",
            "approval_record_sha256",
            "test_batch_hash",
            "approved_implementation_commit",
            "approved_execution_context_sha256",
            "approved_roots_sha256",
        },
        "human signature record",
    )
    if (
        value["schema_version"] != HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_human_signature_record"
    ):
        _fail("human signature record schema identity mismatch")
    signature_id = _atom(value["signature_record_id"], "signature record ID")
    _timestamp(value["signed_at_utc"], "signature timestamp")
    signer = _atom(value["signer_actor_id"], "signature actor ID")
    if (
        value["signer_role"] != "human_gate_b_attestor"
        or value["signature_method"] != "human-governance-attestation-v1"
        or value["attestation"] != "ATTEST_EXACT_GATE_B_APPROVAL_RECORD"
    ):
        _fail("human signature policy mismatch")
    _atom(value["approval_record_id"], "signature approval record ID")
    _sha(value["approval_record_sha256"], "signature approval record hash")
    if (
        value["approval_record_id"] != approval["approval_record_id"]
        or value["approval_record_sha256"] != approval_sha256
    ):
        _fail("human signature approval binding mismatch")
    if signature_id == approval["approval_record_id"]:
        _fail("approval and signature record IDs must differ")
    for field_name in (
        "test_batch_hash",
        "approved_execution_context_sha256",
        "approved_roots_sha256",
    ):
        _sha(value[field_name], f"signature {field_name}")
        if value[field_name] != approval[field_name]:
            _fail("human signature approval scope mismatch")
    _oid(value["approved_implementation_commit"], "signature implementation commit")
    if value["approved_implementation_commit"] != approval["approved_implementation_commit"]:
        _fail("human signature implementation binding mismatch")
    operational = {approval[actor_field] for actor_field, _, _ in _OPERATIONAL_ACTOR_FIELDS}
    if signer in operational:
        _fail("human attestor must differ from every operational actor")


def _validate_release_authorization(value: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "artifact_type",
        "authorization_id",
        "authorized_at_utc",
        "approval_record_id",
        "approval_record_sha256",
        "signature_record_sha256",
        "test_batch_hash",
        "attempt_ordinal",
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
        "access_log_sha256",
        "approver_id",
        "approver_role",
        "non_disclosure_attested",
    }
    _closed(value, fields, "release authorization")
    _validate_authorization_common(
        value, RELEASE_AUTHORIZATION_SCHEMA_VERSION, "gate_b_release_authorization"
    )
    _sha(value["test_batch_hash"], "release batch hash")
    _integer(
        value["attempt_ordinal"],
        "release attempt ordinal",
        minimum=1,
        maximum=1000000,
    )
    _sha(value["sealed_record_sha256"], "sealed record hash")
    _sha(value["quarantine_manifest_sha256"], "release quarantine hash")
    _sha(value["access_log_sha256"], "release access log hash")
    _atom(value["approver_id"], "release approver ID")
    if value["approver_role"] != "release_approver" or value["non_disclosure_attested"] is not True:
        _fail("release authorization governance mismatch")


def _validate_retry_authorization(value: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "artifact_type",
        "authorization_id",
        "authorized_at_utc",
        "approval_record_id",
        "approval_record_sha256",
        "signature_record_sha256",
        "test_batch_hash",
        "failed_record_sha256",
        "failed_attempt_ordinal",
        "quarantine_manifest_sha256",
        "access_log_sha256",
        "non_disclosure_attested",
        "disclosure_event_detected",
        "technical_reason_id",
        "approver_id",
        "approver_role",
        "failed_runner_actor_id",
        "next_attempt_ordinal",
        "unchanged_implementation_commit",
        "unchanged_batch_manifest_sha256",
        "unchanged_selection_sha256",
        "unchanged_coordinates_sha256",
    }
    _closed(value, fields, "retry authorization")
    _validate_authorization_common(
        value, RETRY_AUTHORIZATION_SCHEMA_VERSION, "gate_b_retry_authorization"
    )
    _sha(value["test_batch_hash"], "retry batch hash")
    _sha(value["failed_record_sha256"], "failed record hash")
    failed_ordinal = _integer(
        value["failed_attempt_ordinal"],
        "failed attempt ordinal",
        minimum=1,
        maximum=1000000,
    )
    next_ordinal = _integer(
        value["next_attempt_ordinal"],
        "next attempt ordinal",
        minimum=1,
        maximum=1000000,
    )
    if next_ordinal != failed_ordinal + 1:
        _fail("retry next attempt ordinal mismatch")
    _sha(value["quarantine_manifest_sha256"], "retry quarantine hash")
    _sha(value["access_log_sha256"], "retry access log hash")
    if (
        value["non_disclosure_attested"] is not True
        or value["disclosure_event_detected"] is not False
    ):
        _fail("retry disclosure governance mismatch")
    _atom(value["technical_reason_id"], "retry technical reason")
    _atom(value["approver_id"], "retry approver ID")
    _atom(value["failed_runner_actor_id"], "failed runner actor ID")
    if value["approver_role"] != "retry_approver":
        _fail("retry approver role mismatch")
    _oid(value["unchanged_implementation_commit"], "retry implementation commit")
    _sha(value["unchanged_batch_manifest_sha256"], "retry batch manifest hash")
    _sha(value["unchanged_selection_sha256"], "retry selection hash")
    _sha(value["unchanged_coordinates_sha256"], "retry coordinates hash")


def _validate_root_anchor(value: dict[str, Any], expected_role: str) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "root_role",
            "anchor_id",
            "created_at_utc",
            "approval_record_sha256",
        },
        "root anchor",
    )
    if (
        value["schema_version"] != ROOT_ANCHOR_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_root_anchor"
    ):
        _fail("root anchor schema identity mismatch")
    if (
        expected_role not in {"ledger_base", "quarantine_base"}
        or value["root_role"] != expected_role
    ):
        _fail("root anchor role mismatch")
    _atom(value["anchor_id"], "root anchor ID")
    _timestamp(value["created_at_utc"], "root anchor timestamp")
    _sha(value["approval_record_sha256"], "root anchor approval hash")


def _validate_execution_context(value: dict[str, Any]) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "active_modules",
            "created_at_utc",
            "repository_root",
            "expected_implementation_commit",
            "runtime_fingerprint",
            "dependency_lock",
        },
        "execution context",
    )
    if (
        value["schema_version"] != EXECUTION_CONTEXT_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_execution_context"
    ):
        _fail("execution context schema identity mismatch")
    _timestamp(value["created_at_utc"], "execution context timestamp")
    repository = _closed(
        value["repository_root"],
        {"absolute_path", "file_id_hex", "identity_scheme", "volume_id_hex"},
        "execution repository root",
    )
    _absolute_path(repository["absolute_path"], "execution repository path")
    _hex_identity(repository["file_id_hex"], "execution repository file ID")
    _hex_identity(repository["volume_id_hex"], "execution repository volume ID")
    if repository["identity_scheme"] not in {
        "posix-device-inode-v1",
        "windows-volume-file-id-v1",
    }:
        _fail("execution repository identity scheme mismatch")
    _oid(value["expected_implementation_commit"], "execution context commit")
    modules = value["active_modules"]
    if not isinstance(modules, list) or len(modules) != len(ACTIVE_MODULE_PATHS):
        _fail("execution context active module list is incomplete")
    for raw, expected in zip(modules, ACTIVE_MODULE_PATHS, strict=True):
        item = _closed(raw, {"module_name", "repository_relative_path", "sha256"}, "active module")
        if (item["module_name"], item["repository_relative_path"]) != expected:
            _fail("active module order or identity mismatch")
        _sha(item["sha256"], "active module hash")
    fingerprint = _closed(
        value["runtime_fingerprint"],
        {
            "python_implementation",
            "python_version",
            "python_compiler",
            "platform",
            "system",
            "release",
            "version",
            "machine",
        },
        "runtime fingerprint",
    )
    for name, item in fingerprint.items():
        _ascii(item, f"runtime fingerprint {name}")
    lock = _closed(
        value["dependency_lock"], {"absolute_path", "sha256", "size_bytes"}, "context lock"
    )
    _absolute_path(lock["absolute_path"], "context dependency lock path")
    _sha(lock["sha256"], "context dependency lock hash")
    _integer(lock["size_bytes"], "context dependency lock size", minimum=1)


@dataclass(frozen=True, slots=True, init=False)
class GateBPreApprovalRootIdentityProjection:
    """Immutable canonical root identity approved before writable anchors exist."""

    payload: Mapping[str, Any]
    canonical_bytes: bytes
    sha256: str

    def __new__(
        cls,
        *,
        _token: object | None = None,
    ) -> GateBPreApprovalRootIdentityProjection:
        if _token is not _PREAPPROVAL_PROJECTION_TOKEN:
            raise TypeError("preapproval projection construction is private")
        return object.__new__(cls)


@_sanitized_api
def build_gate_b_preapproval_root_identity_projection(
    roots: object,
) -> GateBPreApprovalRootIdentityProjection:
    """Build the sole canonical v1 approval projection for full root references."""
    expected_roles = set(PREAPPROVAL_ROOT_ROLE_ORDER)
    expected_fields = {
        "absolute_path",
        "anchor_relative_path",
        "anchor_sha256",
        "file_id_hex",
        "identity_scheme",
        "root_role",
        "volume_id_hex",
    }
    if (
        type(roots) is not dict
        or set(roots) != expected_roles
        or any(type(key) is not str for key in roots)
    ):
        _fail("preapproval roots fields are not closed-world")
    expected_scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    projected_roots: list[dict[str, Any]] = []
    for role in PREAPPROVAL_ROOT_ROLE_ORDER:
        raw = roots[role]
        if (
            type(raw) is not dict
            or set(raw) != expected_fields
            or any(type(key) is not str for key in raw)
        ):
            _fail(f"{role} preapproval root fields are not closed-world")
        root_role = raw["root_role"]
        if type(root_role) is not str or root_role != role:
            _fail("preapproval root role mismatch")
        absolute_path = raw["absolute_path"]
        if type(absolute_path) is not str or not absolute_path:
            _fail(f"{role} preapproval root path must be a string")
        if any(unicodedata.category(character) in {"Cc", "Cf"} for character in absolute_path):
            _fail(f"{role} preapproval root path contains a control character")
        path = Path(absolute_path)
        if (
            type(path) is not type(Path())
            or not path.is_absolute()
            or ".." in path.parts
            or str(path) != absolute_path
        ):
            _fail(f"{role} preapproval root path must be canonical and absolute")
        identity_scheme = raw["identity_scheme"]
        if type(identity_scheme) is not str or identity_scheme != expected_scheme:
            _fail(f"{role} preapproval root identity scheme mismatch")
        identities: dict[str, str] = {}
        for field_name in ("volume_id_hex", "file_id_hex"):
            field_value = raw[field_name]
            if type(field_value) is not str or _HEX_ID_RE.fullmatch(field_value) is None:
                _fail(f"{role} preapproval root physical identity mismatch")
            identities[field_name] = field_value
        anchor_relative_path = raw["anchor_relative_path"]
        anchor_sha256 = raw["anchor_sha256"]
        if role == "test_root":
            if anchor_relative_path is not None or anchor_sha256 is not None:
                _fail("Test root preapproval anchor fields must be null")
        else:
            if (
                type(anchor_relative_path) is not str
                or anchor_relative_path != ".gate-b-root-anchor.json"
            ):
                _fail("writable root preapproval anchor path mismatch")
            if anchor_sha256 is not None and (
                type(anchor_sha256) is not str or _SHA_RE.fullmatch(anchor_sha256) is None
            ):
                _fail("writable root preapproval anchor hash mismatch")
        projected_roots.append(
            {
                "root_role": root_role,
                "absolute_path": absolute_path,
                "identity_scheme": identity_scheme,
                "volume_id_hex": identities["volume_id_hex"],
                "file_id_hex": identities["file_id_hex"],
                "anchor_relative_path": anchor_relative_path,
            }
        )
    plain_payload = {
        "schema_version": PREAPPROVAL_ROOT_IDENTITY_PROJECTION_SCHEMA_VERSION,
        "anchor_policy_version": ROOT_ANCHOR_POLICY_VERSION,
        "roots": projected_roots,
    }
    canonical_bytes = canonical_json_bytes(plain_payload)
    projection = object.__new__(GateBPreApprovalRootIdentityProjection)
    object.__setattr__(projection, "payload", _frozen(plain_payload))
    object.__setattr__(projection, "canonical_bytes", canonical_bytes)
    object.__setattr__(projection, "sha256", sha256_bytes(canonical_bytes))
    return projection


class GateBV2CompatibilityObject:
    """Nominal boundary shared only by compatibility-qualified v2 objects."""

    __slots__ = ()


@dataclass(frozen=True, slots=True, init=False)
class GateBPreApprovalRootIdentityProjectionV2(GateBV2CompatibilityObject):
    """Canonical fixed-width Windows root projection with immutable provenance."""

    payload: Mapping[str, Any]
    canonical_bytes: bytes
    sha256: str
    _token: object = field(repr=False, compare=False)

    def __new__(
        cls,
        *,
        _token: object | None = None,
    ) -> GateBPreApprovalRootIdentityProjectionV2:
        if _token is not _PREAPPROVAL_PROJECTION_V2_TOKEN:
            raise TypeError("v2 preapproval projection construction is private")
        return object.__new__(cls)


@dataclass(frozen=True, slots=True, init=False)
class GateBV2CompatibilityTrustChain(GateBV2CompatibilityObject):
    """Opaque, schema-joined compatibility chain that grants no lifecycle capability."""

    projection: GateBPreApprovalRootIdentityProjectionV2
    descriptor: Mapping[str, Any]
    roots: Mapping[str, Mapping[str, Any]]
    artifact_hashes: Mapping[str, str]
    request_payload: Mapping[str, Any]
    _artifact_raws: Mapping[str, bytes] = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(
        cls,
        *,
        _token: object | None = None,
    ) -> GateBV2CompatibilityTrustChain:
        if _token is not _V2_TRUST_CHAIN_TOKEN:
            raise TypeError("v2 compatibility trust-chain construction is private")
        return object.__new__(cls)


def is_gate_b_v2_compatibility_object(value: object) -> bool:
    """Return whether a value is nominally part of the non-executable v2 boundary."""
    return isinstance(value, GateBV2CompatibilityObject)


def _fixed_width_v2_identity(
    value: object,
    label: str,
    *,
    width: int,
) -> str:
    if (
        type(value) is not str
        or len(value) != width
        or any(character not in "0123456789abcdef" for character in value)
        or int(value, 16) == 0
    ):
        _fail(f"{label} must be exact nonzero fixed-width lowercase hexadecimal")
    return value


def _source_materialization_projection_v2(
    *,
    size_bytes: object,
    sha256: object,
    roots: list[dict[str, Any]],
) -> dict[str, Any]:
    size = _integer(
        size_bytes,
        "source materialization projection size",
        minimum=1,
    )
    digest = _sha(sha256, "source materialization projection hash")
    source_payload = {
        "schema_version": PREAPPROVAL_ROOT_IDENTITY_PROJECTION_SCHEMA_VERSION,
        "anchor_policy_version": ROOT_ANCHOR_POLICY_VERSION,
        "roots": copy.deepcopy(roots),
    }
    source_raw = canonical_json_bytes(source_payload)
    if (
        size != SOURCE_MATERIALIZATION_PROJECTION_SIZE_BYTES
        or digest != SOURCE_MATERIALIZATION_PROJECTION_SHA256
        or len(source_raw) != SOURCE_MATERIALIZATION_PROJECTION_SIZE_BYTES
        or sha256_bytes(source_raw) != SOURCE_MATERIALIZATION_PROJECTION_SHA256
    ):
        _fail("source materialization projection bytes and root tuple mismatch")
    return {
        "schema_version": PREAPPROVAL_ROOT_IDENTITY_PROJECTION_SCHEMA_VERSION,
        "serialization_profile": ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
        "size_bytes": size,
        "sha256": digest,
    }


def _validate_v2_projection_provenance(
    projection: GateBPreApprovalRootIdentityProjectionV2,
) -> dict[str, Any]:
    if (
        type(projection) is not GateBPreApprovalRootIdentityProjectionV2
        or object.__getattribute__(projection, "_token") is not _PREAPPROVAL_PROJECTION_V2_TOKEN
    ):
        _fail("v2 projection provenance mismatch")
    try:
        payload = _plain(projection.payload)
        current = (
            projection,
            copy.deepcopy(payload),
            projection.canonical_bytes,
            projection.sha256,
            object.__getattribute__(projection, "_token"),
        )
    except Exception:
        _fail("v2 projection provenance mismatch")
    if (
        _V2_PROJECTION_REGISTRY.get(id(projection)) != current
        or type(projection.canonical_bytes) is not bytes
        or canonical_json_bytes(payload) != projection.canonical_bytes
        or sha256_bytes(projection.canonical_bytes) != projection.sha256
    ):
        _fail("v2 projection provenance mismatch")
    return payload


@_sanitized_api
def build_gate_b_preapproval_root_identity_projection_v2(
    roots: object,
    *,
    source_projection_size_bytes: int = SOURCE_MATERIALIZATION_PROJECTION_SIZE_BYTES,
    source_projection_sha256: str = SOURCE_MATERIALIZATION_PROJECTION_SHA256,
    anchor_policy_version: str = ROOT_ANCHOR_POLICY_VERSION,
) -> GateBPreApprovalRootIdentityProjectionV2:
    """Build the sole fixed-width v2 projection without accepting a v1 alias."""
    expected_roles = set(PREAPPROVAL_ROOT_ROLE_ORDER)
    expected_fields = {
        "absolute_path",
        "anchor_relative_path",
        "anchor_sha256",
        "file_id_hex",
        "identity_scheme",
        "root_role",
        "volume_id_hex",
    }
    if (
        type(roots) is not dict
        or set(roots) != expected_roles
        or any(type(key) is not str for key in roots)
    ):
        _fail("v2 preapproval roots fields are not closed-world")
    if (
        type(anchor_policy_version) is not str
        or anchor_policy_version != ROOT_ANCHOR_POLICY_VERSION
    ):
        _fail("v2 anchor policy version mismatch")
    projected_roots: list[dict[str, Any]] = []
    for role in PREAPPROVAL_ROOT_ROLE_ORDER:
        raw = roots[role]
        if (
            type(raw) is not dict
            or set(raw) != expected_fields
            or any(type(key) is not str for key in raw)
        ):
            _fail(f"{role} v2 preapproval root fields are not closed-world")
        if type(raw["root_role"]) is not str or raw["root_role"] != role:
            _fail("v2 preapproval root role mismatch")
        absolute_path = raw["absolute_path"]
        if (
            type(absolute_path) is not str
            or not absolute_path
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in absolute_path)
        ):
            _fail(f"{role} v2 preapproval root path mismatch")
        path = Path(absolute_path)
        if not path.is_absolute() or ".." in path.parts or str(path) != absolute_path:
            _fail(f"{role} v2 preapproval root path must be canonical and absolute")
        if raw["identity_scheme"] != "windows-volume-file-id-v1":
            _fail(f"{role} v2 preapproval root identity scheme mismatch")
        volume_id = _fixed_width_v2_identity(
            raw["volume_id_hex"],
            f"{role} v2 volume ID",
            width=8,
        )
        file_id = _fixed_width_v2_identity(
            raw["file_id_hex"],
            f"{role} v2 file ID",
            width=16,
        )
        anchor_relative_path = raw["anchor_relative_path"]
        anchor_sha256 = raw["anchor_sha256"]
        if role == "test_root":
            if anchor_relative_path is not None or anchor_sha256 is not None:
                _fail("v2 Test root anchor fields must be null")
        else:
            if anchor_relative_path != ".gate-b-root-anchor.json":
                _fail("v2 writable root anchor path mismatch")
            if anchor_sha256 is not None:
                _sha(anchor_sha256, "v2 writable root anchor hash")
        projected_roots.append(
            {
                "root_role": role,
                "absolute_path": absolute_path,
                "identity_scheme": "windows-volume-file-id-v1",
                "volume_id_hex": volume_id,
                "file_id_hex": file_id,
                "anchor_relative_path": anchor_relative_path,
            }
        )
    source = _source_materialization_projection_v2(
        size_bytes=source_projection_size_bytes,
        sha256=source_projection_sha256,
        roots=projected_roots,
    )
    plain_payload = {
        "schema_version": PREAPPROVAL_ROOT_IDENTITY_PROJECTION_V2_SCHEMA_VERSION,
        "serialization_profile": ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
        "anchor_policy_version": ROOT_ANCHOR_POLICY_VERSION,
        "source_materialization_projection": source,
        "roots": projected_roots,
    }
    canonical_bytes = canonical_json_bytes(plain_payload)
    projection = GateBPreApprovalRootIdentityProjectionV2(_token=_PREAPPROVAL_PROJECTION_V2_TOKEN)
    object.__setattr__(projection, "payload", _frozen(plain_payload))
    object.__setattr__(projection, "canonical_bytes", canonical_bytes)
    object.__setattr__(projection, "sha256", sha256_bytes(canonical_bytes))
    object.__setattr__(projection, "_token", _PREAPPROVAL_PROJECTION_V2_TOKEN)
    _V2_PROJECTION_REGISTRY[id(projection)] = (
        projection,
        copy.deepcopy(plain_payload),
        canonical_bytes,
        projection.sha256,
        _PREAPPROVAL_PROJECTION_V2_TOKEN,
    )
    return projection


def _projection_descriptor_v2(
    projection: GateBPreApprovalRootIdentityProjectionV2,
) -> dict[str, Any]:
    payload = _validate_v2_projection_provenance(projection)
    return {
        "schema_version": ROOT_IDENTITY_PROJECTION_DESCRIPTOR_V2_SCHEMA_VERSION,
        "projection_schema_version": payload["schema_version"],
        "serialization_profile": payload["serialization_profile"],
        "anchor_policy_version": payload["anchor_policy_version"],
        "projection_sha256": projection.sha256,
        "source_materialization_projection_schema_version": payload[
            "source_materialization_projection"
        ]["schema_version"],
        "source_materialization_projection_serialization_profile": payload[
            "source_materialization_projection"
        ]["serialization_profile"],
        "source_materialization_projection_size_bytes": payload[
            "source_materialization_projection"
        ]["size_bytes"],
        "source_materialization_projection_sha256": payload["source_materialization_projection"][
            "sha256"
        ],
    }


@_sanitized_api
def gate_b_root_identity_projection_descriptor_v2(
    projection: GateBPreApprovalRootIdentityProjectionV2,
) -> Mapping[str, Any]:
    """Return the closed descriptor that every v2 trust link must copy exactly."""
    return _frozen(_projection_descriptor_v2(projection))


def _validate_projection_descriptor_v2(
    value: object,
    expected: dict[str, Any],
) -> None:
    descriptor = _closed(value, set(expected), "v2 projection descriptor")
    if not _exact_json_equal(descriptor, expected):
        _fail("v2 projection descriptor mismatch")


def _v2_artifact(
    raw: object,
    label: str,
) -> tuple[bytes, dict[str, Any], str]:
    if type(raw) is not bytes:
        _fail(f"{label} input must be bytes")
    owned = bytes(raw)
    payload = _strict_canonical_object(owned, label)
    return owned, payload, sha256_bytes(owned)


def _validate_v2_approval(
    value: dict[str, Any],
    descriptor: dict[str, Any],
) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "approval_record_id",
            "approved_at_utc",
            "approver_actor_id",
            "approver_role",
            "approval_decision",
            "projection_descriptor",
        },
        "v2 approval record",
    )
    if (
        value["schema_version"] != HUMAN_APPROVAL_RECORD_V3_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_human_approval_record"
        or value["approver_role"] != "human_gate_b_compatibility_approver"
        or value["approval_decision"] != "APPROVE_COMPATIBILITY_PREFLIGHT_ONLY"
    ):
        _fail("v2 approval record identity mismatch")
    _atom(value["approval_record_id"], "v2 approval record ID")
    _timestamp(value["approved_at_utc"], "v2 approval timestamp")
    _atom(value["approver_actor_id"], "v2 approval actor ID")
    _validate_projection_descriptor_v2(value["projection_descriptor"], descriptor)


def _validate_v2_signature(
    value: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    approval: dict[str, Any],
    approval_sha256: str,
) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "signature_record_id",
            "signed_at_utc",
            "signer_actor_id",
            "signer_role",
            "attestation",
            "approval_record_id",
            "approval_record_sha256",
            "projection_descriptor",
        },
        "v2 signature record",
    )
    if (
        value["schema_version"] != HUMAN_SIGNATURE_RECORD_V3_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_human_signature_record"
        or value["signer_role"] != "human_gate_b_compatibility_signer"
        or value["attestation"] != "ATTEST_COMPATIBILITY_PREFLIGHT_ONLY"
        or value["approval_record_id"] != approval["approval_record_id"]
        or value["approval_record_sha256"] != approval_sha256
    ):
        _fail("v2 signature record identity mismatch")
    _atom(value["signature_record_id"], "v2 signature record ID")
    _timestamp(value["signed_at_utc"], "v2 signature timestamp")
    signer = _atom(value["signer_actor_id"], "v2 signature actor ID")
    if signer == approval["approver_actor_id"]:
        _fail("v2 approval and signature actors must differ")
    _validate_projection_descriptor_v2(value["projection_descriptor"], descriptor)


def _validate_v2_readiness(
    value: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    approval: dict[str, Any],
    approval_sha256: str,
    signature_sha256: str,
) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "authorization_id",
            "authorized_at_utc",
            "approval_record_id",
            "approval_record_sha256",
            "signature_record_sha256",
            "compatibility_preflight_ready",
            "gate_b_ready",
            "projection_descriptor",
        },
        "v2 readiness authorization",
    )
    if (
        value["schema_version"] != READINESS_AUTHORIZATION_V3_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_readiness_authorization"
        or value["approval_record_id"] != approval["approval_record_id"]
        or value["approval_record_sha256"] != approval_sha256
        or value["signature_record_sha256"] != signature_sha256
        or value["compatibility_preflight_ready"] is not True
        or value["gate_b_ready"] is not False
    ):
        _fail("v2 readiness authorization identity mismatch")
    _atom(value["authorization_id"], "v2 readiness authorization ID")
    _timestamp(value["authorized_at_utc"], "v2 readiness timestamp")
    _validate_projection_descriptor_v2(value["projection_descriptor"], descriptor)


def _validate_v2_anchor(
    value: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    role: str,
    root: dict[str, Any],
    approval_sha256: str,
    readiness_sha256: str,
) -> None:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "root_role",
            "root_absolute_path",
            "anchor_id",
            "created_at_utc",
            "approval_record_sha256",
            "readiness_authorization_sha256",
            "projection_descriptor",
        },
        "v2 root anchor",
    )
    if (
        value["schema_version"] != ROOT_ANCHOR_V2_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_root_anchor"
        or value["root_role"] != role
        or value["root_absolute_path"] != root["absolute_path"]
        or value["approval_record_sha256"] != approval_sha256
        or value["readiness_authorization_sha256"] != readiness_sha256
    ):
        _fail("v2 root anchor identity mismatch")
    _atom(value["anchor_id"], "v2 root anchor ID")
    _timestamp(value["created_at_utc"], "v2 root anchor timestamp")
    _validate_projection_descriptor_v2(value["projection_descriptor"], descriptor)


def _validate_v2_request(
    value: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    approval_sha256: str,
    signature_sha256: str,
    readiness_sha256: str,
    anchor_hashes: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "requested_at_utc",
            "operation",
            "approval_record_sha256",
            "signature_record_sha256",
            "readiness_authorization_sha256",
            "projection_descriptor",
            "roots",
        },
        "v2 loader request",
    )
    if (
        value["schema_version"] != LOADER_REQUEST_V2_SCHEMA_VERSION
        or value["artifact_type"] != "gate_b_test_loader_request"
        or value["operation"] != "compatibility_preflight_only"
        or value["approval_record_sha256"] != approval_sha256
        or value["signature_record_sha256"] != signature_sha256
        or value["readiness_authorization_sha256"] != readiness_sha256
    ):
        _fail("v2 loader request identity mismatch")
    _timestamp(value["requested_at_utc"], "v2 loader request timestamp")
    _validate_projection_descriptor_v2(value["projection_descriptor"], descriptor)
    roots = _closed(
        value["roots"],
        set(PREAPPROVAL_ROOT_ROLE_ORDER),
        "v2 loader roots",
    )
    copied: dict[str, dict[str, Any]] = {}
    expected_fields = {
        "absolute_path",
        "anchor_relative_path",
        "anchor_sha256",
        "file_id_hex",
        "identity_scheme",
        "root_role",
        "volume_id_hex",
    }
    for role in PREAPPROVAL_ROOT_ROLE_ORDER:
        root = _closed(roots[role], expected_fields, f"v2 {role} request root")
        if root["root_role"] != role:
            _fail("v2 loader root role mismatch")
        if role == "test_root":
            if root["anchor_relative_path"] is not None or root["anchor_sha256"] is not None:
                _fail("v2 Test root anchor fields must be null")
        elif (
            root["anchor_relative_path"] != ".gate-b-root-anchor.json"
            or root["anchor_sha256"] != anchor_hashes[role]
        ):
            _fail("v2 loader root anchor hash mismatch")
        copied[role] = copy.deepcopy(root)
    return copied


@_sanitized_api
def build_gate_b_v2_compatibility_trust_chain(
    projection: GateBPreApprovalRootIdentityProjectionV2,
    *,
    approval_record_raw: bytes,
    signature_record_raw: bytes,
    readiness_authorization_raw: bytes,
    root_anchor_raws: Mapping[str, bytes],
    loader_request_raw: bytes,
) -> GateBV2CompatibilityTrustChain:
    """Join the closed v2 artifact family without creating or opening anything."""
    descriptor = _projection_descriptor_v2(projection)
    approval_raw, approval, approval_hash = _v2_artifact(
        approval_record_raw,
        "v2 approval record",
    )
    _validate_v2_approval(approval, descriptor)
    signature_raw, signature, signature_hash = _v2_artifact(
        signature_record_raw,
        "v2 signature record",
    )
    _validate_v2_signature(
        signature,
        descriptor,
        approval=approval,
        approval_sha256=approval_hash,
    )
    readiness_raw, readiness, readiness_hash = _v2_artifact(
        readiness_authorization_raw,
        "v2 readiness authorization",
    )
    _validate_v2_readiness(
        readiness,
        descriptor,
        approval=approval,
        approval_sha256=approval_hash,
        signature_sha256=signature_hash,
    )
    if type(root_anchor_raws) is not dict or set(root_anchor_raws) != {
        "ledger_base",
        "quarantine_base",
    }:
        _fail("v2 root anchor inputs are not closed-world")
    anchor_raw_values: dict[str, bytes] = {}
    anchor_hashes: dict[str, str] = {}
    projection_roots = {root["root_role"]: root for root in _plain(projection.payload)["roots"]}
    for role in ("ledger_base", "quarantine_base"):
        raw, payload, digest = _v2_artifact(root_anchor_raws[role], f"v2 {role} root anchor")
        anchor_raw_values[role] = raw
        anchor_hashes[role] = digest
        _validate_v2_anchor(
            payload,
            descriptor,
            role=role,
            root=projection_roots[role],
            approval_sha256=approval_hash,
            readiness_sha256=readiness_hash,
        )
    request_raw, request, request_hash = _v2_artifact(
        loader_request_raw,
        "v2 loader request",
    )
    roots = _validate_v2_request(
        request,
        descriptor,
        approval_sha256=approval_hash,
        signature_sha256=signature_hash,
        readiness_sha256=readiness_hash,
        anchor_hashes=anchor_hashes,
    )
    rebuilt = build_gate_b_preapproval_root_identity_projection_v2(roots)
    if rebuilt.canonical_bytes != projection.canonical_bytes or rebuilt.sha256 != projection.sha256:
        _fail("v2 loader roots differ from the approved projection")
    paths = {role: Path(root["absolute_path"]) for role, root in roots.items()}
    if len({os.path.normcase(str(path)) for path in paths.values()}) != 3:
        _fail("v2 loader roots must be lexically distinct")
    physical = {(root["volume_id_hex"], root["file_id_hex"]) for root in roots.values()}
    if len(physical) != 3:
        _fail("v2 loader roots must have distinct physical identities")
    for left_name, left in paths.items():
        for right_name, right in paths.items():
            if left_name != right_name and (left in right.parents or right in left.parents):
                _fail("v2 loader roots must be non-nested")
    artifact_hashes = {
        "approval_record": approval_hash,
        "signature_record": signature_hash,
        "readiness_authorization": readiness_hash,
        "ledger_root_anchor": anchor_hashes["ledger_base"],
        "quarantine_root_anchor": anchor_hashes["quarantine_base"],
        "loader_request": request_hash,
    }
    artifact_raws = {
        "approval_record": approval_raw,
        "signature_record": signature_raw,
        "readiness_authorization": readiness_raw,
        "ledger_root_anchor": anchor_raw_values["ledger_base"],
        "quarantine_root_anchor": anchor_raw_values["quarantine_base"],
        "loader_request": request_raw,
    }
    chain = GateBV2CompatibilityTrustChain(_token=_V2_TRUST_CHAIN_TOKEN)
    values = {
        "projection": projection,
        "descriptor": _frozen(descriptor),
        "roots": _frozen(roots),
        "artifact_hashes": _frozen(artifact_hashes),
        "request_payload": _frozen(request),
        "_artifact_raws": MappingProxyType(dict(artifact_raws)),
        "_token": _V2_TRUST_CHAIN_TOKEN,
    }
    for name, value in values.items():
        object.__setattr__(chain, name, value)
    snapshot = (
        chain,
        projection,
        copy.deepcopy(descriptor),
        copy.deepcopy(roots),
        dict(artifact_hashes),
        dict(artifact_raws),
        copy.deepcopy(request),
    )
    _V2_TRUST_CHAIN_REGISTRY[id(chain)] = snapshot
    return chain


def validate_gate_b_v2_compatibility_trust_chain(
    chain: GateBV2CompatibilityTrustChain,
) -> GateBV2CompatibilityTrustChain:
    """Revalidate nominal type, exact schema bytes, hashes, and loader provenance."""
    if type(chain) is not GateBV2CompatibilityTrustChain:
        _fail("v2 compatibility trust-chain nominal type mismatch")
    registered = _V2_TRUST_CHAIN_REGISTRY.get(id(chain))
    try:
        current = (
            chain,
            chain.projection,
            _plain(chain.descriptor),
            _plain(chain.roots),
            dict(chain.artifact_hashes),
            dict(chain._artifact_raws),
            _plain(chain.request_payload),
        )
    except Exception:
        _fail("v2 compatibility trust-chain provenance mismatch")
    if (
        registered is None
        or registered[0] is not chain
        or registered[1] is not current[1]
        or chain._token is not _V2_TRUST_CHAIN_TOKEN
        or not all(
            _exact_json_equal(left, right)
            for left, right in zip(current[2:5], registered[2:5], strict=True)
        )
        or current[5] != registered[5]
        or not _exact_json_equal(current[6], registered[6])
        or any(sha256_bytes(raw) != current[4][name] for name, raw in current[5].items())
    ):
        _fail("v2 compatibility trust-chain provenance mismatch")
    _validate_v2_projection_provenance(chain.projection)
    return chain


@dataclass(frozen=True, slots=True)
class GateBBatchManifest:
    """Strict immutable batch bytes and their complete stored-byte hash."""

    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def test_batch_hash(self) -> str:
        return self.sha256

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload

    @property
    def raw_bytes(self) -> bytes:
        return self._raw

    @property
    def path(self) -> Path:
        return self._path

    @property
    def roots_independent_digests(self) -> tuple[str, str]:
        selection = canonical_json_bytes(_plain(self._payload["selection"]))
        coordinates = canonical_json_bytes(_plain(self._payload["coordinates"]))
        return sha256_bytes(selection), sha256_bytes(coordinates)

    def reason_for(self, failure_class: str, from_state: str) -> str:
        governance = self._payload["governance"]
        matches = [
            item
            for item in governance["failure_reason_map"]
            if item["failure_class"] == failure_class and item["from_state"] == from_state
        ]
        if len(matches) != 1:
            _fail("failure class and state do not map exactly once")
        reason_id = matches[0]["reason_id"]
        catalog = {
            item["reason_id"]: tuple(item["eligible_from_states"])
            for item in governance["technical_retry_reasons"]
        }
        if reason_id not in catalog or from_state not in catalog[reason_id]:
            _fail("mapped reason is not eligible for the current state")
        return reason_id


@dataclass(frozen=True, slots=True)
class GateBReadinessAuthorization:
    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload

    @property
    def path(self) -> Path:
        return self._path


@dataclass(frozen=True, slots=True, init=False)
class GateBHumanApprovalRecord:
    """Strict immutable bytes for one human Gate B approval attestation."""

    _sha256: str
    _raw: bytes = field(repr=False)
    _payload: Mapping[str, Any] = field(repr=False)
    _approval_record_id: str
    _loader_token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBHumanApprovalRecord:
        if _token is not _HUMAN_RECORD_LOADER_TOKEN:
            raise TypeError("human approval construction is private")
        return object.__new__(cls)

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def raw(self) -> bytes:
        return self._raw

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload

    @property
    def approval_record_id(self) -> str:
        return self._approval_record_id


@dataclass(frozen=True, slots=True, init=False)
class GateBHumanSignatureRecord:
    """Strict immutable bytes for one human Gate B signature attestation."""

    _sha256: str
    _raw: bytes = field(repr=False)
    _payload: Mapping[str, Any] = field(repr=False)
    _signature_record_id: str
    _approval_record_id: str
    _approval_record_sha256: str
    _loader_token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBHumanSignatureRecord:
        if _token is not _HUMAN_RECORD_LOADER_TOKEN:
            raise TypeError("human signature construction is private")
        return object.__new__(cls)

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def raw(self) -> bytes:
        return self._raw

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload

    @property
    def signature_record_id(self) -> str:
        return self._signature_record_id

    @property
    def approval_record_id(self) -> str:
        return self._approval_record_id

    @property
    def approval_record_sha256(self) -> str:
        return self._approval_record_sha256


_HUMAN_APPROVAL_REGISTRY: dict[
    int,
    tuple[GateBHumanApprovalRecord, bytes, str, dict[str, Any], str],
] = {}
_HUMAN_SIGNATURE_REGISTRY: dict[
    int,
    tuple[
        GateBHumanSignatureRecord,
        bytes,
        str,
        dict[str, Any],
        str,
        str,
        str,
    ],
] = {}


@dataclass(frozen=True, slots=True)
class GateBReleaseAuthorization:
    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload


@dataclass(frozen=True, slots=True)
class GateBRetryAuthorization:
    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload


@dataclass(frozen=True, slots=True)
class GateBRootAnchor:
    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload


@dataclass(frozen=True, slots=True)
class GateBExecutionContext:
    sha256: str
    _payload: Mapping[str, Any] = field(repr=False)
    _raw: bytes = field(repr=False)
    _path: Path = field(repr=False)

    @property
    def payload(self) -> Mapping[str, Any]:
        return self._payload

    @property
    def path(self) -> Path:
        return self._path


def _acquire_canonical_artifact(
    path: Path | str,
    *,
    label: str,
) -> tuple[Path, bytes]:
    candidate = Path(path)
    try:
        metadata = os.lstat(_native_io_path(candidate))
    except OSError as exc:
        raise GateBContractError(f"{label} is unavailable") from exc
    if not _single_link_regular(metadata):
        _fail(f"{label} must be a single-link physical regular file")
    if _contract_windows_stream_names(candidate) != ("::$DATA",):
        _fail(f"{label} has an alternate data stream")
    try:
        descriptor = _open_contract_descriptor(candidate)
        try:
            opened = os.fstat(descriptor)
            if not _single_link_regular(opened) or (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                _fail(f"{label} identity changed before read")
            chunks = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
            opened_after = os.fstat(descriptor)
            if not _single_link_regular(opened_after) or (
                opened_after.st_dev,
                opened_after.st_ino,
                opened_after.st_size,
            ) != (opened.st_dev, opened.st_ino, opened.st_size):
                _fail(f"{label} descriptor topology changed while loading")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise GateBContractError(f"{label} cannot be read") from exc
    after = os.lstat(_native_io_path(candidate))
    if not _single_link_regular(after):
        _fail(f"{label} topology changed while loading")
    if _contract_windows_stream_names(candidate) != ("::$DATA",):
        _fail(f"{label} stream topology changed while loading")
    if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        _fail(f"{label} identity changed while loading")
    return candidate.resolve(), bytes(raw)


def _validate_canonical_artifact_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    reference_path: Path,
    label: str,
    validator: Callable[[dict[str, Any]], None],
) -> tuple[Path, bytes, dict[str, Any]]:
    if type(raw) is not bytes:
        _fail(f"{label} input must be bytes")
    retained_path = _retained_reference_path(reference_path, f"{label} reference path")
    owned_raw = bytes(raw)
    expected = _sha(expected_sha256, f"{label} expected hash")
    if sha256_bytes(owned_raw) != expected:
        _fail(f"{label} stored-byte hash mismatch")
    value = _strict_canonical_object(owned_raw, label)
    validator(value)
    return retained_path, owned_raw, value


def _read_canonical_artifact(
    path: Path | str,
    *,
    expected_sha256: str,
    label: str,
    validator: Callable[[dict[str, Any]], None],
) -> tuple[Path, bytes, dict[str, Any]]:
    canonical_path, raw = _acquire_canonical_artifact(path, label=label)
    return _validate_canonical_artifact_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=canonical_path,
        label=label,
        validator=validator,
    )


def _load_gate_b_batch_manifest_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    reference_path: Path,
) -> GateBBatchManifest:
    canonical_path, owned_raw, value = _validate_canonical_artifact_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
        label="Gate B batch manifest",
        validator=_validate_batch_manifest,
    )
    return GateBBatchManifest(expected_sha256, _frozen(value), owned_raw, canonical_path)


@_sanitized_api
def load_gate_b_batch_manifest_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    reference_path: Path,
) -> GateBBatchManifest:
    """Strict-load retained batch bytes without filesystem access."""
    return _load_gate_b_batch_manifest_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
    )


@_sanitized_api
def load_gate_b_batch_manifest(path: Path | str, *, expected_sha256: str) -> GateBBatchManifest:
    """Strict-load a complete canonical Gate B batch manifest."""
    canonical_path, raw = _acquire_canonical_artifact(path, label="Gate B batch manifest")
    return _load_gate_b_batch_manifest_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=canonical_path,
    )


def _load_gate_b_readiness_authorization_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
    reference_path: Path,
) -> GateBReadinessAuthorization:
    approval_hash = _sha(expected_approval_record_sha256, "expected approval record hash")
    signature_hash = _sha(expected_signature_record_sha256, "expected signature record hash")
    canonical_path, owned_raw, value = _validate_canonical_artifact_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
        label="Gate B readiness authorization",
        validator=_validate_readiness_authorization,
    )
    if (
        value["approval_record_sha256"] != approval_hash
        or value["signature_record_sha256"] != signature_hash
    ):
        _fail("readiness authorization trust-anchor mismatch")
    return GateBReadinessAuthorization(
        expected_sha256,
        _frozen(value),
        owned_raw,
        canonical_path,
    )


@_sanitized_api
def load_gate_b_readiness_authorization_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
    reference_path: Path,
) -> GateBReadinessAuthorization:
    """Strict-load retained readiness bytes without filesystem access."""
    return _load_gate_b_readiness_authorization_bytes(
        raw,
        expected_sha256=expected_sha256,
        expected_approval_record_sha256=expected_approval_record_sha256,
        expected_signature_record_sha256=expected_signature_record_sha256,
        reference_path=reference_path,
    )


@_sanitized_api
def load_gate_b_readiness_authorization(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
) -> GateBReadinessAuthorization:
    """Load a readiness authorization using three independent trust anchors."""
    canonical_path, raw = _acquire_canonical_artifact(path, label="Gate B readiness authorization")
    return _load_gate_b_readiness_authorization_bytes(
        raw,
        expected_sha256=expected_sha256,
        expected_approval_record_sha256=expected_approval_record_sha256,
        expected_signature_record_sha256=expected_signature_record_sha256,
        reference_path=canonical_path,
    )


def _revalidate_human_approval_record(
    approval: GateBHumanApprovalRecord,
) -> dict[str, Any]:
    if type(approval) is not GateBHumanApprovalRecord:
        _fail("human approval record must be strict-loaded")
    registered = _HUMAN_APPROVAL_REGISTRY.get(id(approval))
    try:
        current_payload = _plain(approval.payload)
    except Exception:
        _fail("human approval record provenance mismatch")
    if (
        registered is None
        or registered[0] is not approval
        or approval._loader_token is not _HUMAN_RECORD_LOADER_TOKEN
        or approval.raw != registered[1]
        or approval.sha256 != registered[2]
        or not _exact_json_equal(current_payload, registered[3])
        or approval.approval_record_id != registered[4]
        or sha256_bytes(approval.raw) != approval.sha256
    ):
        _fail("human approval record provenance mismatch")
    reparsed = _strict_canonical_object(approval.raw, "human approval record")
    _validate_human_approval_record(reparsed)
    if (
        not _exact_json_equal(reparsed, current_payload)
        or reparsed["approval_record_id"] != approval.approval_record_id
    ):
        _fail("human approval record retained value mismatch")
    return reparsed


def _revalidate_human_signature_record(
    signature: GateBHumanSignatureRecord,
    approval_payload: Mapping[str, Any],
    approval_sha256: str,
) -> dict[str, Any]:
    if type(signature) is not GateBHumanSignatureRecord:
        _fail("human signature record must be strict-loaded")
    registered = _HUMAN_SIGNATURE_REGISTRY.get(id(signature))
    try:
        current_payload = _plain(signature.payload)
    except Exception:
        _fail("human signature record provenance mismatch")
    if (
        registered is None
        or registered[0] is not signature
        or signature._loader_token is not _HUMAN_RECORD_LOADER_TOKEN
        or signature.raw != registered[1]
        or signature.sha256 != registered[2]
        or not _exact_json_equal(current_payload, registered[3])
        or signature.signature_record_id != registered[4]
        or signature.approval_record_id != registered[5]
        or signature.approval_record_sha256 != registered[6]
        or sha256_bytes(signature.raw) != signature.sha256
    ):
        _fail("human signature record provenance mismatch")
    reparsed = _strict_canonical_object(signature.raw, "human signature record")
    _validate_human_signature_record(reparsed, approval_payload, approval_sha256)
    if (
        not _exact_json_equal(reparsed, current_payload)
        or reparsed["signature_record_id"] != signature.signature_record_id
        or reparsed["approval_record_id"] != signature.approval_record_id
        or reparsed["approval_record_sha256"] != signature.approval_record_sha256
    ):
        _fail("human signature record retained value mismatch")
    return reparsed


@_sanitized_api
def load_gate_b_human_approval_record_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
) -> GateBHumanApprovalRecord:
    """Strict-load canonical human approval bytes without creating authority."""
    if type(raw) is not bytes:
        _fail("human approval record input must be bytes")
    expected = _sha(expected_sha256, "human approval expected hash")
    if sha256_bytes(raw) != expected:
        _fail("human approval stored-byte hash mismatch")
    value = _strict_canonical_object(raw, "human approval record")
    _validate_human_approval_record(value)
    record = object.__new__(GateBHumanApprovalRecord)
    object.__setattr__(record, "_sha256", expected)
    object.__setattr__(record, "_raw", bytes(raw))
    object.__setattr__(record, "_payload", _frozen(value))
    object.__setattr__(record, "_approval_record_id", value["approval_record_id"])
    object.__setattr__(record, "_loader_token", _HUMAN_RECORD_LOADER_TOKEN)
    _HUMAN_APPROVAL_REGISTRY[id(record)] = (
        record,
        record.raw,
        record.sha256,
        copy.deepcopy(value),
        record.approval_record_id,
    )
    return record


@_sanitized_api
def load_gate_b_human_signature_record_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    approval: GateBHumanApprovalRecord,
) -> GateBHumanSignatureRecord:
    """Strict-load canonical signature bytes bound to one approval record."""
    approval_payload = _revalidate_human_approval_record(approval)
    if type(raw) is not bytes:
        _fail("human signature record input must be bytes")
    expected = _sha(expected_sha256, "human signature expected hash")
    if sha256_bytes(raw) != expected:
        _fail("human signature stored-byte hash mismatch")
    value = _strict_canonical_object(raw, "human signature record")
    _validate_human_signature_record(value, approval_payload, approval.sha256)
    record = object.__new__(GateBHumanSignatureRecord)
    object.__setattr__(record, "_sha256", expected)
    object.__setattr__(record, "_raw", bytes(raw))
    object.__setattr__(record, "_payload", _frozen(value))
    object.__setattr__(record, "_signature_record_id", value["signature_record_id"])
    object.__setattr__(record, "_approval_record_id", value["approval_record_id"])
    object.__setattr__(record, "_approval_record_sha256", value["approval_record_sha256"])
    object.__setattr__(record, "_loader_token", _HUMAN_RECORD_LOADER_TOKEN)
    _HUMAN_SIGNATURE_REGISTRY[id(record)] = (
        record,
        record.raw,
        record.sha256,
        copy.deepcopy(value),
        record.signature_record_id,
        record.approval_record_id,
        record.approval_record_sha256,
    )
    return record


@_sanitized_api
def validate_gate_b_readiness_human_trust_chain(
    approval: GateBHumanApprovalRecord,
    signature: GateBHumanSignatureRecord,
    readiness_payload: Mapping[str, Any],
) -> None:
    """Revalidate and join strict human records to one readiness payload."""
    approval_value = _revalidate_human_approval_record(approval)
    signature_value = _revalidate_human_signature_record(signature, approval_value, approval.sha256)
    if not isinstance(readiness_payload, Mapping):
        _fail("readiness payload must be a mapping")
    try:
        readiness = _plain(readiness_payload)
    except Exception:
        _fail("readiness payload is invalid")
    if not isinstance(readiness, dict):
        _fail("readiness payload must be a mapping")
    _validate_readiness_authorization(readiness)
    if (
        readiness["approval_record_id"] != approval.approval_record_id
        or readiness["approval_record_sha256"] != approval.sha256
        or readiness["signature_record_sha256"] != signature.sha256
    ):
        _fail("readiness human record binding mismatch")
    for field_name in (
        "test_batch_hash",
        "approved_implementation_commit",
        "approved_execution_context_sha256",
        "approved_roots_sha256",
    ):
        if (
            approval_value[field_name] != signature_value[field_name]
            or approval_value[field_name] != readiness[field_name]
        ):
            _fail("readiness human trust scope mismatch")
    operational: list[str] = []
    for actor_field, role_field, expected_role in _OPERATIONAL_ACTOR_FIELDS:
        if (
            approval_value[actor_field] != readiness[actor_field]
            or approval_value[role_field] != readiness[role_field]
            or approval_value[role_field] != expected_role
        ):
            _fail("readiness human operational actor binding mismatch")
        operational.append(approval_value[actor_field])
    if len(set(operational)) != len(operational):
        _fail("readiness operational actors must be pairwise distinct")
    if (
        approval_value["approver_actor_id"] in operational
        or signature_value["signer_actor_id"] in operational
    ):
        _fail("human governance actors must differ from operational actors")
    if approval.approval_record_id == signature.signature_record_id:
        _fail("approval and signature record IDs must differ")
    if (
        _integer(
            approval_value["expected_attempt_ordinal"],
            "human approval expected attempt ordinal",
            minimum=1,
            maximum=2,
        )
        != 1
        or approval_value["release_authorized"] is not False
        or approval_value["retry_authorized"] is not False
    ):
        _fail("readiness human initial-attempt policy mismatch")
    return None


@_sanitized_api
def load_gate_b_release_authorization(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
) -> GateBReleaseAuthorization:
    """Load a release authorization using three independent trust anchors."""
    approval_hash = _sha(expected_approval_record_sha256, "expected approval record hash")
    signature_hash = _sha(expected_signature_record_sha256, "expected signature record hash")
    canonical_path, raw, value = _read_canonical_artifact(
        path,
        expected_sha256=expected_sha256,
        label="Gate B release authorization",
        validator=_validate_release_authorization,
    )
    if (
        value["approval_record_sha256"] != approval_hash
        or value["signature_record_sha256"] != signature_hash
    ):
        _fail("release authorization trust-anchor mismatch")
    return GateBReleaseAuthorization(expected_sha256, _frozen(value), raw, canonical_path)


@_sanitized_api
def load_gate_b_retry_authorization(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_approval_record_sha256: str,
    expected_signature_record_sha256: str,
) -> GateBRetryAuthorization:
    """Load a retry authorization using three independent trust anchors."""
    approval_hash = _sha(expected_approval_record_sha256, "expected approval record hash")
    signature_hash = _sha(expected_signature_record_sha256, "expected signature record hash")
    canonical_path, raw, value = _read_canonical_artifact(
        path,
        expected_sha256=expected_sha256,
        label="Gate B retry authorization",
        validator=_validate_retry_authorization,
    )
    if (
        value["approval_record_sha256"] != approval_hash
        or value["signature_record_sha256"] != signature_hash
    ):
        _fail("retry authorization trust-anchor mismatch")
    return GateBRetryAuthorization(expected_sha256, _frozen(value), raw, canonical_path)


@_sanitized_api
def load_gate_b_root_anchor(
    path: Path | str,
    *,
    expected_sha256: str,
    expected_root_role: str,
    expected_approval_record_sha256: str,
) -> GateBRootAnchor:
    """Strict-load one synthetic or later-authorized writable-base anchor."""
    canonical_path, raw = _acquire_canonical_artifact(path, label="Gate B root anchor")
    return _load_gate_b_root_anchor_bytes(
        raw,
        expected_sha256=expected_sha256,
        expected_root_role=expected_root_role,
        expected_approval_record_sha256=expected_approval_record_sha256,
        reference_path=canonical_path,
    )


def _load_gate_b_root_anchor_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_root_role: str,
    expected_approval_record_sha256: str,
    reference_path: Path,
) -> GateBRootAnchor:
    approval_hash = _sha(expected_approval_record_sha256, "expected approval record hash")
    canonical_path, owned_raw, value = _validate_canonical_artifact_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
        label="Gate B root anchor",
        validator=lambda payload: _validate_root_anchor(payload, expected_root_role),
    )
    if value["approval_record_sha256"] != approval_hash:
        _fail("root anchor approval hash mismatch")
    return GateBRootAnchor(expected_sha256, _frozen(value), owned_raw, canonical_path)


@_sanitized_api
def load_gate_b_root_anchor_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_root_role: str,
    expected_approval_record_sha256: str,
    reference_path: Path,
) -> GateBRootAnchor:
    """Strict-load retained root-anchor bytes without filesystem access."""
    return _load_gate_b_root_anchor_bytes(
        raw,
        expected_sha256=expected_sha256,
        expected_root_role=expected_root_role,
        expected_approval_record_sha256=expected_approval_record_sha256,
        reference_path=reference_path,
    )


@_sanitized_api
def load_gate_b_execution_context(
    path: Path | str, *, expected_sha256: str
) -> GateBExecutionContext:
    """Strict-load an explicit Gate B execution context."""
    canonical_path, raw = _acquire_canonical_artifact(path, label="Gate B execution context")
    return _load_gate_b_execution_context_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=canonical_path,
    )


def _load_gate_b_execution_context_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    reference_path: Path,
) -> GateBExecutionContext:
    canonical_path, owned_raw, value = _validate_canonical_artifact_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
        label="Gate B execution context",
        validator=_validate_execution_context,
    )
    return GateBExecutionContext(expected_sha256, _frozen(value), owned_raw, canonical_path)


@_sanitized_api
def load_gate_b_execution_context_bytes(
    raw: bytes,
    *,
    expected_sha256: str,
    reference_path: Path,
) -> GateBExecutionContext:
    """Strict-load retained execution-context bytes without filesystem access."""
    return _load_gate_b_execution_context_bytes(
        raw,
        expected_sha256=expected_sha256,
        reference_path=reference_path,
    )


def _canonical_reason_detail_sha256(reason_id: str) -> str:
    """Return the fixed nonsecret failure-reason detail digest."""
    return sha256_bytes(canonical_json_bytes({"reason_id": _atom(reason_id, "reason ID")}))


def _decimal_string(value: object, label: str) -> str:
    """Validate a finite canonical fixed-point decimal string."""
    text = _ascii(value, label)
    if _DECIMAL_RE.fullmatch(text) is None or text in {"-0", "-0.0"}:
        _fail(f"{label} must be canonical fixed-point decimal text")
    return text


def _root_identity_payload(path: Path | str) -> dict[str, str]:
    """Return a synthetic-fixture-compatible physical directory identity."""
    candidate = Path(path).resolve()
    metadata = os.lstat(_native_io_path(candidate))
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("root identity target must be a directory")
    scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    return {
        "absolute_path": str(candidate),
        "file_id_hex": format(metadata.st_ino, "x"),
        "identity_scheme": scheme,
        "volume_id_hex": format(metadata.st_dev, "x"),
    }
