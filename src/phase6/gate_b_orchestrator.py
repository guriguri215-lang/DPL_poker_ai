"""Pinned Gate B materializers, one-shot orchestration, and closed CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from phase6.contracts import (
    CanonicalPhase6ContractArtifact,
    ValidatedPhase6ContractBundleEvidence,
    canonical_json_bytes,
    load_phase6_contract_bundle_evidence_from_canonical_artifacts,
    sha256_bytes,
)
from phase6.gate_b_contracts import (
    GateBContractError,
    GateBV2CompatibilityObject,
    GateBV2CompatibilityTrustChain,
    is_gate_b_v2_compatibility_object,
    load_gate_b_human_approval_record_bytes,
    load_gate_b_human_signature_record_bytes,
    load_gate_b_readiness_authorization_bytes,
    validate_gate_b_readiness_human_trust_chain,
    validate_gate_b_v2_compatibility_trust_chain,
)
from phase6.gate_b_executor import (
    MAX_AGGREGATE_OUTPUT_BYTES,
    OUTPUT_LIMITS,
    GateBDeadlineExceeded,
    GateBExecutorError,
    GateBProductionExecutor,
)
from phase6.gate_b_ledger import (
    GateBLedgerError,
    GateBLedgerStore,
)
from phase6.gate_b_loader import (
    GateBExecutorFailure,
    GateBInputCapability,
    GateBLoaderError,
    GateBLoaderRequest,
    GateBOutputsCapability,
    GateBRetainedArtifactSnapshot,
    GateBRetainedDirectorySnapshot,
    GateBRetainedLoaderBundle,
    PreparedGateBV2CompatibilityPreflight,
    _clear_gate_b_retained_calibration_roles,
    _register_gate_b_retained_calibration_roles,
    build_gate_b_retained_loader_bundle,
    create_gate_b_retained_artifact,
    load_gate_b_loader_request_from_retained,
    open_gate_b_retained_directory,
    open_gate_b_test_input,
    prepare_gate_b_test_open,
    prepare_gate_b_v2_compatibility_preflight,
    read_gate_b_retained_artifact,
    reserve_gate_b_attempt,
    verify_gate_b_execution_environment,
)
from phase6.gate_b_v2_route import (
    GateBV2PinnedSpecReference,
    GateBV2RouteError,
    PreparedGateBV2ExecutionRoute,
    close_gate_b_v2_execution_route,
    consume_gate_b_v2_execution_route,
    is_gate_b_v2_execution_route,
    prepare_gate_b_v2_execution_route_from_reference,
    validate_gate_b_v2_pinned_spec_reference,
    validate_prepared_gate_b_v2_execution_route,
)

READINESS_SPEC_SCHEMA = "phase6-gate-b-readiness-materialization-spec-v1"
REQUEST_SPEC_SCHEMA = "phase6-gate-b-request-materialization-spec-v1"
ONE_SHOT_SPEC_SCHEMA = "phase6-gate-b-one-shot-execution-spec-v1"
CALIBRATION_REFERENCE_SCHEMA = "phase6-gate-b-calibration-bundle-reference-v1"
READINESS_SPEC_V2_SCHEMA = "phase6-gate-b-readiness-materialization-spec-v2"
REQUEST_SPEC_V2_SCHEMA = "phase6-gate-b-request-materialization-spec-v2"
V2_EXECUTION_RECEIPT_SCHEMA = "phase6-gate-b-cli-execution-receipt-v2"

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX_RE = re.compile(r"(?:0|[1-9a-f][0-9a-f]*)\Z")
_CHILD_RE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"|\.[A-Za-z0-9][A-Za-z0-9._-]{0,126})\Z"
)
_RELATIVE_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*\Z"
)
_SPEC_TOKEN = object()
_V2_SPEC_TOKEN = object()
_OPENED_TOKEN = object()
_LOADED_SPECS: dict[int, object] = {}
_V2_SPEC_REGISTRY: dict[int, tuple[object, ...]] = {}

_ARTIFACT_REF_FIELDS = {
    "parent_absolute_path",
    "parent_volume_id_hex",
    "parent_file_id_hex",
    "direct_child_name",
    "expected_sha256",
    "expected_size_bytes",
}
_OUTPUT_REF_FIELDS = {
    "parent_absolute_path",
    "parent_volume_id_hex",
    "parent_file_id_hex",
    "direct_child_name",
}
_DIRECTORY_REF_FIELDS = {"absolute_path", "volume_id_hex", "file_id_hex"}
_PINNED_INPUT_FIELDS = {
    "batch_manifest",
    "readiness_authorization",
    "human_approval_record",
    "human_signature_record",
    "execution_context",
    "ledger_root_anchor",
    "quarantine_root_anchor",
}
_ONE_SHOT_PINNED_INPUT_FIELDS = _PINNED_INPUT_FIELDS | {
    "loader_request",
    "calibration_bundle",
}
_ROOT_FIELDS = {"test_root", "ledger_base", "quarantine_base"}
_OPERATION_VALUES = {
    "pre-dispatch",
    "materialize-readiness",
    "materialize-request",
    "execute-once",
}
_ERROR_CODE_VALUES = {
    "gate_b_invalid_arguments",
    "gate_b_spec_failure",
    "gate_b_materialization_failure",
    "gate_b_preflight_failure",
    "gate_b_contract_failure",
    "gate_b_ledger_failure",
    "gate_b_loader_failure",
    "gate_b_executor_failure",
    "gate_b_operation_timeout",
    "gate_b_orchestrator_failure",
    "gate_b_internal_failure",
    "gate_b_interrupted",
}


class GateBOrchestratorError(RuntimeError):
    """Sanitized orchestrator failure."""

    def __init__(self) -> None:
        super().__init__("Gate B orchestration failed closed")


class GateBSpecError(GateBOrchestratorError):
    """Pinned spec loading or strict parsing failed."""


class GateBMaterializationError(GateBOrchestratorError):
    """A materialization-specific join or output operation failed."""


class GateBPreflightError(GateBOrchestratorError):
    """A one-shot pre-reservation trust gate failed."""


class _CliUsageError(ValueError):
    pass


class _CliHelp(BaseException):
    pass


def _raise_sanitized(error_type: type[GateBOrchestratorError]) -> None:
    error = error_type()
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    raise error


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _strict_object(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise ValueError("canonical JSON requires one terminal LF")
    value = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=_duplicate_rejecting_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")),
    )
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("canonical JSON object mismatch")
    return value


def _closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields mismatch")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical lowercase hexadecimal")
    return value


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.abspath(value):
        raise ValueError(f"{label} must be normalized absolute")
    return path


def _child(value: object, label: str) -> str:
    if not isinstance(value, str) or _CHILD_RE.fullmatch(value) is None or value in {".", ".."}:
        raise ValueError(f"{label} must be a canonical direct-child name")
    return value


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _relative(value: object) -> str:
    if not isinstance(value, str) or _RELATIVE_RE.fullmatch(value) is None:
        raise ValueError("calibration relative path is not canonical")
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class GateBPinnedSpecReference:
    """Complete non-authoritative external reference for one top-level spec."""

    parent_absolute_path: Path
    parent_volume_id_hex: str
    parent_file_id_hex: str
    direct_child_name: str
    expected_sha256: str
    expected_size_bytes: int


@dataclass(frozen=True, slots=True)
class _PinnedArtifactReference:
    parent_absolute_path: Path
    parent_volume_id_hex: str
    parent_file_id_hex: str
    direct_child_name: str
    expected_sha256: str
    expected_size_bytes: int

    @property
    def path(self) -> Path:
        return self.parent_absolute_path / self.direct_child_name


@dataclass(frozen=True, slots=True)
class _PinnedOutputReference:
    parent_absolute_path: Path
    parent_volume_id_hex: str
    parent_file_id_hex: str
    direct_child_name: str

    @property
    def path(self) -> Path:
        return self.parent_absolute_path / self.direct_child_name


@dataclass(frozen=True, slots=True)
class _PinnedDirectoryReference:
    absolute_path: Path
    volume_id_hex: str
    file_id_hex: str


@dataclass(frozen=True, slots=True)
class _CalibrationBundleReference:
    root_manifest: _PinnedArtifactReference
    artifacts: tuple[tuple[str, _PinnedArtifactReference], ...]


@dataclass(frozen=True, slots=True, init=False)
class _ReadinessMaterializationSpec:
    output: _PinnedOutputReference
    approval_record: _PinnedArtifactReference
    signature_record: _PinnedArtifactReference
    authorization_payload: Mapping[str, Any]
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, init=False)
class _RequestMaterializationSpec:
    output: _PinnedOutputReference
    request_payload: Mapping[str, Any]
    pinned_inputs: Mapping[str, _PinnedArtifactReference]
    roots: Mapping[str, _PinnedDirectoryReference]
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _CommonParentReference:
    absolute_path: Path
    file_id_hex: str
    identity_scheme: str
    volume_id_hex: str
    expected_direct_children: tuple[str, ...]


@dataclass(frozen=True, slots=True, init=False)
class _OneShotExecutionSpec:
    pinned_inputs: Mapping[
        str,
        _PinnedArtifactReference | _CalibrationBundleReference,
    ]
    roots: Mapping[str, _PinnedDirectoryReference]
    common_parent: _CommonParentReference
    expected_latest_record_sha256: None
    operation_timeout_seconds: int
    process_timeout_seconds: int
    output_limits: Mapping[str, int]
    _token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, init=False)
class GateBV2CompatibilityMaterializationSpecs(GateBV2CompatibilityObject):
    """Strict v2 readiness/request spec joins with no materialization capability."""

    projection_descriptor: Mapping[str, Any]
    readiness_spec_sha256: str
    request_spec_sha256: str
    _artifact_hashes: Mapping[str, str] = field(repr=False, compare=False)
    _readiness_spec_raw: bytes = field(repr=False, compare=False)
    _request_spec_raw: bytes = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(
        cls,
        *,
        _token: object | None = None,
    ) -> GateBV2CompatibilityMaterializationSpecs:
        if _token is not _V2_SPEC_TOKEN:
            raise TypeError("v2 compatibility spec construction is private")
        return object.__new__(cls)


def _v2_spec_payload(raw: bytes, expected_sha256: str, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or sha256_bytes(raw) != _sha(expected_sha256, f"{label} hash"):
        raise ValueError(f"{label} stored-byte hash mismatch")
    return _strict_object(raw)


def _validate_v2_spec_descriptor(
    value: object,
    expected: Mapping[str, Any],
) -> None:
    if type(value) is not dict or canonical_json_bytes(value) != canonical_json_bytes(
        _plain(expected)
    ):
        raise ValueError("v2 compatibility spec projection descriptor mismatch")


def _validate_v2_materialization_specs(
    specs: GateBV2CompatibilityMaterializationSpecs,
) -> GateBV2CompatibilityMaterializationSpecs:
    if type(specs) is not GateBV2CompatibilityMaterializationSpecs:
        raise TypeError("v2 compatibility spec nominal type mismatch")
    registered = _V2_SPEC_REGISTRY.get(id(specs))
    try:
        current = (
            specs,
            canonical_json_bytes(_plain(specs.projection_descriptor)),
            specs.readiness_spec_sha256,
            specs.request_spec_sha256,
            canonical_json_bytes(_plain(specs._artifact_hashes)),
            specs._readiness_spec_raw,
            specs._request_spec_raw,
            specs._token,
        )
    except Exception:
        raise TypeError("v2 compatibility spec provenance mismatch") from None
    if (
        registered is None
        or registered[0] is not specs
        or current != registered
        or current[7] is not _V2_SPEC_TOKEN
        or sha256_bytes(current[5]) != current[2]
        or sha256_bytes(current[6]) != current[3]
    ):
        raise TypeError("v2 compatibility spec provenance mismatch")
    return specs


def validate_gate_b_v2_compatibility_materialization_specs(
    chain: GateBV2CompatibilityTrustChain,
    *,
    readiness_spec_raw: bytes,
    expected_readiness_spec_sha256: str,
    request_spec_raw: bytes,
    expected_request_spec_sha256: str,
) -> GateBV2CompatibilityMaterializationSpecs:
    """Validate schema-first v2 specs without creating readiness or request bytes."""
    try:
        validated = validate_gate_b_v2_compatibility_trust_chain(chain)
        descriptor = _plain(validated.descriptor)
        hashes = dict(validated.artifact_hashes)
        readiness = _v2_spec_payload(
            readiness_spec_raw,
            expected_readiness_spec_sha256,
            "v2 readiness materialization spec",
        )
        _closed(
            readiness,
            {
                "schema_version",
                "artifact_type",
                "projection_descriptor",
                "approval_record_sha256",
                "signature_record_sha256",
                "readiness_authorization_sha256",
            },
            "v2 readiness materialization spec",
        )
        if (
            readiness["schema_version"] != READINESS_SPEC_V2_SCHEMA
            or readiness["artifact_type"] != "gate_b_readiness_materialization_spec"
        ):
            raise ValueError("v2 readiness materialization spec identity mismatch")
        _validate_v2_spec_descriptor(readiness["projection_descriptor"], descriptor)
        if (
            readiness["approval_record_sha256"] != hashes["approval_record"]
            or readiness["signature_record_sha256"] != hashes["signature_record"]
            or readiness["readiness_authorization_sha256"] != hashes["readiness_authorization"]
        ):
            raise ValueError("v2 readiness materialization spec join mismatch")

        request = _v2_spec_payload(
            request_spec_raw,
            expected_request_spec_sha256,
            "v2 request materialization spec",
        )
        _closed(
            request,
            {
                "schema_version",
                "artifact_type",
                "projection_descriptor",
                "approval_record_sha256",
                "signature_record_sha256",
                "readiness_authorization_sha256",
                "root_anchor_sha256s",
                "loader_request_sha256",
            },
            "v2 request materialization spec",
        )
        if (
            request["schema_version"] != REQUEST_SPEC_V2_SCHEMA
            or request["artifact_type"] != "gate_b_request_materialization_spec"
        ):
            raise ValueError("v2 request materialization spec identity mismatch")
        _validate_v2_spec_descriptor(request["projection_descriptor"], descriptor)
        anchors = _closed(
            request["root_anchor_sha256s"],
            {"ledger_base", "quarantine_base"},
            "v2 request materialization anchor hashes",
        )
        if (
            request["approval_record_sha256"] != hashes["approval_record"]
            or request["signature_record_sha256"] != hashes["signature_record"]
            or request["readiness_authorization_sha256"] != hashes["readiness_authorization"]
            or anchors["ledger_base"] != hashes["ledger_root_anchor"]
            or anchors["quarantine_base"] != hashes["quarantine_root_anchor"]
            or request["loader_request_sha256"] != hashes["loader_request"]
        ):
            raise ValueError("v2 request materialization spec join mismatch")
        specs = GateBV2CompatibilityMaterializationSpecs(_token=_V2_SPEC_TOKEN)
        values = {
            "projection_descriptor": MappingProxyType(descriptor),
            "readiness_spec_sha256": expected_readiness_spec_sha256,
            "request_spec_sha256": expected_request_spec_sha256,
            "_artifact_hashes": MappingProxyType(dict(hashes)),
            "_readiness_spec_raw": bytes(readiness_spec_raw),
            "_request_spec_raw": bytes(request_spec_raw),
            "_token": _V2_SPEC_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(specs, name, value)
        snapshot = (
            specs,
            canonical_json_bytes(descriptor),
            expected_readiness_spec_sha256,
            expected_request_spec_sha256,
            canonical_json_bytes(hashes),
            bytes(readiness_spec_raw),
            bytes(request_spec_raw),
            _V2_SPEC_TOKEN,
        )
        _V2_SPEC_REGISTRY[id(specs)] = snapshot
        return specs
    except GateBSpecError:
        raise
    except (GateBContractError, TypeError, ValueError, UnicodeError):
        _raise_sanitized(GateBSpecError)


def prepare_gate_b_v2_compatibility(
    specs: GateBV2CompatibilityMaterializationSpecs,
    chain: GateBV2CompatibilityTrustChain,
) -> PreparedGateBV2CompatibilityPreflight:
    """Reach only the distinct v2 retained-root prepared boundary."""
    try:
        _validate_v2_materialization_specs(specs)
        validated = validate_gate_b_v2_compatibility_trust_chain(chain)
        if canonical_json_bytes(_plain(specs.projection_descriptor)) != canonical_json_bytes(
            _plain(validated.descriptor)
        ):
            raise ValueError("v2 compatibility specs and trust chain differ")
        if canonical_json_bytes(_plain(specs._artifact_hashes)) != canonical_json_bytes(
            _plain(validated.artifact_hashes)
        ):
            raise ValueError("v2 compatibility specs and trust-chain artifact hashes differ")
        return prepare_gate_b_v2_compatibility_preflight(validated)
    except GateBPreflightError:
        raise
    except (GateBContractError, GateBLedgerError, GateBLoaderError, TypeError, ValueError):
        _raise_sanitized(GateBPreflightError)


@dataclass(frozen=True, slots=True, init=False)
class _OpenedArtifact:
    reference: _PinnedArtifactReference
    parent: GateBRetainedDirectorySnapshot
    artifact: GateBRetainedArtifactSnapshot

    def __new__(cls, *, _token: object | None = None) -> _OpenedArtifact:
        if _token is not _OPENED_TOKEN:
            raise TypeError("opened artifact construction is private")
        return object.__new__(cls)


def _register_spec(spec: object) -> object:
    object.__setattr__(spec, "_token", _SPEC_TOKEN)
    _LOADED_SPECS[id(spec)] = spec
    return spec


def _require_loaded_spec(spec: object, expected_type: type) -> None:
    if (
        type(spec) is not expected_type
        or _LOADED_SPECS.get(id(spec)) is not spec
        or object.__getattribute__(spec, "_token") is not _SPEC_TOKEN
    ):
        raise TypeError("one-shot spec must be strict-loaded")


def _parse_artifact_reference(value: object, label: str) -> _PinnedArtifactReference:
    payload = _closed(value, _ARTIFACT_REF_FIELDS, label)
    return _PinnedArtifactReference(
        _absolute(payload["parent_absolute_path"], f"{label} parent"),
        _hex(payload["parent_volume_id_hex"], f"{label} parent volume ID"),
        _hex(payload["parent_file_id_hex"], f"{label} parent file ID"),
        _child(payload["direct_child_name"], f"{label} child"),
        _sha(payload["expected_sha256"], f"{label} expected hash"),
        _positive(payload["expected_size_bytes"], f"{label} expected size"),
    )


def _parse_output_reference(value: object, label: str) -> _PinnedOutputReference:
    payload = _closed(value, _OUTPUT_REF_FIELDS, label)
    return _PinnedOutputReference(
        _absolute(payload["parent_absolute_path"], f"{label} parent"),
        _hex(payload["parent_volume_id_hex"], f"{label} parent volume ID"),
        _hex(payload["parent_file_id_hex"], f"{label} parent file ID"),
        _child(payload["direct_child_name"], f"{label} child"),
    )


def _parse_directory_reference(value: object, label: str) -> _PinnedDirectoryReference:
    payload = _closed(value, _DIRECTORY_REF_FIELDS, label)
    return _PinnedDirectoryReference(
        _absolute(payload["absolute_path"], f"{label} path"),
        _hex(payload["volume_id_hex"], f"{label} volume ID"),
        _hex(payload["file_id_hex"], f"{label} file ID"),
    )


def _parse_roots(value: object) -> Mapping[str, _PinnedDirectoryReference]:
    payload = _closed(value, _ROOT_FIELDS, "roots")
    roots = {
        name: _parse_directory_reference(payload[name], f"{name} root")
        for name in ("test_root", "ledger_base", "quarantine_base")
    }
    identities = {(item.volume_id_hex, item.file_id_hex) for item in roots.values()}
    if len(identities) != 3:
        raise ValueError("root references must have distinct physical identities")
    return MappingProxyType(roots)


def _parse_pinned_inputs(
    value: object,
    *,
    one_shot: bool,
) -> Mapping[str, _PinnedArtifactReference | _CalibrationBundleReference]:
    expected = _ONE_SHOT_PINNED_INPUT_FIELDS if one_shot else _PINNED_INPUT_FIELDS
    payload = _closed(value, expected, "pinned inputs")
    result: dict[str, _PinnedArtifactReference | _CalibrationBundleReference] = {}
    for name in sorted(expected):
        if name == "calibration_bundle":
            result[name] = _parse_calibration_reference(payload[name])
        else:
            result[name] = _parse_artifact_reference(payload[name], name)
    return MappingProxyType(result)


def _parse_calibration_reference(value: object) -> _CalibrationBundleReference:
    payload = _closed(
        value,
        {"schema_version", "artifact_type", "root_manifest", "artifacts"},
        "calibration bundle reference",
    )
    if (
        payload["schema_version"] != CALIBRATION_REFERENCE_SCHEMA
        or payload["artifact_type"] != "gate_b_calibration_bundle_reference"
    ):
        raise ValueError("calibration bundle reference identity mismatch")
    artifacts_value = payload["artifacts"]
    if not isinstance(artifacts_value, list) or not artifacts_value:
        raise ValueError("calibration artifact references must be a nonempty list")
    artifacts: list[tuple[str, _PinnedArtifactReference]] = []
    for item in artifacts_value:
        row = _closed(
            item,
            {"relative_path", *_ARTIFACT_REF_FIELDS},
            "calibration artifact reference",
        )
        relative_path = _relative(row["relative_path"])
        ref_payload = {key: row[key] for key in _ARTIFACT_REF_FIELDS}
        artifacts.append(
            (
                relative_path,
                _parse_artifact_reference(ref_payload, "calibration artifact"),
            )
        )
    if [path for path, _reference in artifacts] != sorted(path for path, _reference in artifacts):
        raise ValueError("calibration artifact references are not canonically ordered")
    if len({path for path, _reference in artifacts}) != len(artifacts):
        raise ValueError("duplicate calibration relative path")
    return _CalibrationBundleReference(
        _parse_artifact_reference(payload["root_manifest"], "calibration root manifest"),
        tuple(artifacts),
    )


def _parse_common_parent(value: object) -> _CommonParentReference:
    payload = _closed(
        value,
        {
            "absolute_path",
            "file_id_hex",
            "identity_scheme",
            "volume_id_hex",
            "expected_direct_children",
        },
        "common parent",
    )
    identity_scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    if payload["identity_scheme"] != identity_scheme:
        raise ValueError("common-parent identity scheme mismatch")
    children = payload["expected_direct_children"]
    if (
        not isinstance(children, list)
        or len(children) != 3
        or any(_child(item, "common-parent child") != item for item in children)
        or children != sorted(children)
        or len(set(children)) != 3
    ):
        raise ValueError("common-parent direct children are not canonical")
    return _CommonParentReference(
        _absolute(payload["absolute_path"], "common-parent path"),
        _hex(payload["file_id_hex"], "common-parent file ID"),
        identity_scheme,
        _hex(payload["volume_id_hex"], "common-parent volume ID"),
        tuple(children),
    )


def _expected_output_limits() -> dict[str, int]:
    return {**OUTPUT_LIMITS, "aggregate_executor_writable": MAX_AGGREGATE_OUTPUT_BYTES}


def _parse_readiness_spec(value: Mapping[str, Any]) -> _ReadinessMaterializationSpec:
    payload = _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "output",
            "approval_record",
            "signature_record",
            "authorization_payload",
        },
        "readiness materialization spec",
    )
    if (
        payload["schema_version"] != READINESS_SPEC_SCHEMA
        or payload["artifact_type"] != "gate_b_readiness_materialization_spec"
        or not isinstance(payload["authorization_payload"], dict)
    ):
        raise ValueError("readiness materialization spec identity mismatch")
    spec = object.__new__(_ReadinessMaterializationSpec)
    object.__setattr__(spec, "output", _parse_output_reference(payload["output"], "output"))
    object.__setattr__(
        spec,
        "approval_record",
        _parse_artifact_reference(payload["approval_record"], "approval record"),
    )
    object.__setattr__(
        spec,
        "signature_record",
        _parse_artifact_reference(payload["signature_record"], "signature record"),
    )
    object.__setattr__(
        spec,
        "authorization_payload",
        MappingProxyType(dict(payload["authorization_payload"])),
    )
    return _register_spec(spec)  # type: ignore[return-value]


def _parse_request_spec(value: Mapping[str, Any]) -> _RequestMaterializationSpec:
    payload = _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "output",
            "request_payload",
            "pinned_inputs",
            "roots",
        },
        "request materialization spec",
    )
    if (
        payload["schema_version"] != REQUEST_SPEC_SCHEMA
        or payload["artifact_type"] != "gate_b_request_materialization_spec"
        or not isinstance(payload["request_payload"], dict)
    ):
        raise ValueError("request materialization spec identity mismatch")
    spec = object.__new__(_RequestMaterializationSpec)
    object.__setattr__(spec, "output", _parse_output_reference(payload["output"], "output"))
    object.__setattr__(
        spec,
        "request_payload",
        MappingProxyType(dict(payload["request_payload"])),
    )
    object.__setattr__(
        spec,
        "pinned_inputs",
        _parse_pinned_inputs(payload["pinned_inputs"], one_shot=False),
    )
    object.__setattr__(spec, "roots", _parse_roots(payload["roots"]))
    return _register_spec(spec)  # type: ignore[return-value]


def _parse_one_shot_spec(value: Mapping[str, Any]) -> _OneShotExecutionSpec:
    payload = _closed(
        value,
        {
            "schema_version",
            "artifact_type",
            "pinned_inputs",
            "roots",
            "common_parent",
            "expected_latest_record_sha256",
            "operation_timeout_seconds",
            "process_timeout_seconds",
            "output_limits",
        },
        "one-shot execution spec",
    )
    if (
        payload["schema_version"] != ONE_SHOT_SPEC_SCHEMA
        or payload["artifact_type"] != "gate_b_one_shot_execution_spec"
        or payload["expected_latest_record_sha256"] is not None
        or payload["operation_timeout_seconds"] != 7200
        or payload["process_timeout_seconds"] != 7500
        or payload["output_limits"] != _expected_output_limits()
    ):
        raise ValueError("one-shot execution spec identity mismatch")
    spec = object.__new__(_OneShotExecutionSpec)
    object.__setattr__(
        spec,
        "pinned_inputs",
        _parse_pinned_inputs(payload["pinned_inputs"], one_shot=True),
    )
    object.__setattr__(spec, "roots", _parse_roots(payload["roots"]))
    object.__setattr__(spec, "common_parent", _parse_common_parent(payload["common_parent"]))
    object.__setattr__(spec, "expected_latest_record_sha256", None)
    object.__setattr__(spec, "operation_timeout_seconds", 7200)
    object.__setattr__(spec, "process_timeout_seconds", 7500)
    object.__setattr__(
        spec,
        "output_limits",
        MappingProxyType(dict(payload["output_limits"])),
    )
    return _register_spec(spec)  # type: ignore[return-value]


def _validated_public_reference(
    reference: GateBPinnedSpecReference,
) -> _PinnedArtifactReference:
    if type(reference) is not GateBPinnedSpecReference:
        raise TypeError("spec reference type mismatch")
    return _PinnedArtifactReference(
        _absolute(str(reference.parent_absolute_path), "spec parent"),
        _hex(reference.parent_volume_id_hex, "spec parent volume ID"),
        _hex(reference.parent_file_id_hex, "spec parent file ID"),
        _child(reference.direct_child_name, "spec child"),
        _sha(reference.expected_sha256, "spec expected hash"),
        _positive(reference.expected_size_bytes, "spec expected size"),
    )


def _open_artifact(
    reference: _PinnedArtifactReference,
    stack: ExitStack,
    *,
    logical_role: str,
) -> _OpenedArtifact:
    parent = stack.enter_context(
        open_gate_b_retained_directory(
            logical_role=f"{logical_role}.parent",
            absolute_path=reference.parent_absolute_path,
            expected_volume_id_hex=reference.parent_volume_id_hex,
            expected_file_id_hex=reference.parent_file_id_hex,
        )
    )
    artifact = read_gate_b_retained_artifact(
        parent,
        logical_role=logical_role,
        direct_child_name=reference.direct_child_name,
        expected_sha256=reference.expected_sha256,
        expected_size_bytes=reference.expected_size_bytes,
    )
    if (
        artifact.reference_path != reference.path
        or artifact.sha256 != reference.expected_sha256
        or artifact.size_bytes != reference.expected_size_bytes
        or artifact.physical_identity == parent.physical_identity
    ):
        raise ValueError("opened artifact retained join mismatch")
    opened = _OpenedArtifact(_token=_OPENED_TOKEN)
    object.__setattr__(opened, "reference", reference)
    object.__setattr__(opened, "parent", parent)
    object.__setattr__(opened, "artifact", artifact)
    return opened


def _open_directory(
    reference: _PinnedDirectoryReference,
    stack: ExitStack,
    *,
    logical_role: str,
) -> GateBRetainedDirectorySnapshot:
    return stack.enter_context(
        open_gate_b_retained_directory(
            logical_role=logical_role,
            absolute_path=reference.absolute_path,
            expected_volume_id_hex=reference.volume_id_hex,
            expected_file_id_hex=reference.file_id_hex,
        )
    )


def _open_output_directory(
    reference: _PinnedOutputReference,
    stack: ExitStack,
    *,
    logical_role: str,
) -> GateBRetainedDirectorySnapshot:
    return stack.enter_context(
        open_gate_b_retained_directory(
            logical_role=logical_role,
            absolute_path=reference.parent_absolute_path,
            expected_volume_id_hex=reference.parent_volume_id_hex,
            expected_file_id_hex=reference.parent_file_id_hex,
        )
    )


def _open_root_anchor(
    reference: _PinnedArtifactReference,
    retained_root: GateBRetainedDirectorySnapshot,
    *,
    logical_role: str,
) -> _OpenedArtifact:
    if (
        reference.parent_absolute_path != retained_root.reference_path
        or reference.parent_volume_id_hex != retained_root.volume_id_hex
        or reference.parent_file_id_hex != retained_root.file_id_hex
    ):
        raise ValueError("root anchor differs from retained root")
    artifact = read_gate_b_retained_artifact(
        retained_root,
        logical_role=logical_role,
        direct_child_name=reference.direct_child_name,
        expected_sha256=reference.expected_sha256,
        expected_size_bytes=reference.expected_size_bytes,
    )
    opened = _OpenedArtifact(_token=_OPENED_TOKEN)
    object.__setattr__(opened, "reference", reference)
    object.__setattr__(opened, "parent", retained_root)
    object.__setattr__(opened, "artifact", artifact)
    return opened


def _reverify(opened: _OpenedArtifact) -> None:
    opened.parent.verify_identity()
    current = read_gate_b_retained_artifact(
        opened.parent,
        logical_role=opened.artifact.logical_role,
        direct_child_name=opened.reference.direct_child_name,
        expected_sha256=opened.reference.expected_sha256,
        expected_size_bytes=opened.reference.expected_size_bytes,
    )
    if (
        current.raw != opened.artifact.raw
        or current.sha256 != opened.artifact.sha256
        or current.size_bytes != opened.artifact.size_bytes
        or current.physical_identity != opened.artifact.physical_identity
    ):
        raise ValueError("pinned artifact changed after accepted loader call")


def _unique_physical_artifacts(opened: Sequence[_OpenedArtifact]) -> None:
    identities = [item.artifact.physical_identity for item in opened]
    if len(identities) != len(set(identities)):
        raise ValueError("pinned artifacts must be physically nonalias")


def _load_top_spec(
    reference: GateBPinnedSpecReference,
    stack: ExitStack,
    *,
    operation: str,
) -> _ReadinessMaterializationSpec | _RequestMaterializationSpec | _OneShotExecutionSpec:
    try:
        role_by_operation = {
            "materialize-readiness": "readiness.spec",
            "materialize-request": "request.spec",
            "execute-once": "one_shot.spec",
        }
        opened = _open_artifact(
            _validated_public_reference(reference),
            stack,
            logical_role=role_by_operation[operation],
        )
        value = _strict_object(opened.artifact.raw)
        if operation == "materialize-readiness":
            spec = _parse_readiness_spec(value)
        elif operation == "materialize-request":
            spec = _parse_request_spec(value)
        elif operation == "execute-once":
            spec = _parse_one_shot_spec(value)
        else:
            raise ValueError("unknown spec operation")
        _reverify(opened)
        return spec
    except GateBSpecError:
        raise
    except (GateBLedgerError, GateBLoaderError, OSError, ValueError, TypeError):
        _raise_sanitized(GateBSpecError)


def _artifact_ref_payload(payload: Mapping[str, Any], name: str) -> tuple[Path, str]:
    value = _closed(payload[name], {"absolute_path", "sha256"}, f"{name} embedded reference")
    return _absolute(value["absolute_path"], f"{name} embedded path"), _sha(
        value["sha256"],
        f"{name} embedded hash",
    )


def _join_request_payload(
    payload: Mapping[str, Any],
    pinned_inputs: Mapping[str, _PinnedArtifactReference],
    roots: Mapping[str, _PinnedDirectoryReference],
) -> None:
    for embedded_name, pinned_name in (
        ("batch_manifest", "batch_manifest"),
        ("readiness_authorization", "readiness_authorization"),
        ("execution_context", "execution_context"),
    ):
        embedded_path, embedded_hash = _artifact_ref_payload(payload, embedded_name)
        reference = pinned_inputs[pinned_name]
        if embedded_path != reference.path or embedded_hash != reference.expected_sha256:
            raise ValueError("request embedded artifact differs from pinned reference")
    roots_payload = _closed(payload["roots"], _ROOT_FIELDS, "request roots")
    for name in ("test_root", "ledger_base", "quarantine_base"):
        embedded = _closed(
            roots_payload[name],
            {
                "absolute_path",
                "anchor_relative_path",
                "anchor_sha256",
                "file_id_hex",
                "identity_scheme",
                "root_role",
                "volume_id_hex",
            },
            f"{name} embedded root",
        )
        reference = roots[name]
        if (
            _absolute(embedded["absolute_path"], f"{name} embedded path") != reference.absolute_path
            or embedded["volume_id_hex"] != reference.volume_id_hex
            or embedded["file_id_hex"] != reference.file_id_hex
            or embedded["root_role"] != name
        ):
            raise ValueError("request embedded root differs from pinned root")
        if name == "test_root":
            if (
                embedded["anchor_relative_path"] is not None
                or embedded["anchor_sha256"] is not None
            ):
                raise ValueError("Test root anchor fields must be null")
        else:
            anchor = pinned_inputs[f"{name.split('_')[0]}_root_anchor"]
            if (
                embedded["anchor_relative_path"] != anchor.direct_child_name
                or embedded["anchor_sha256"] != anchor.expected_sha256
                or reference.absolute_path != anchor.parent_absolute_path
                or reference.volume_id_hex != anchor.parent_volume_id_hex
                or reference.file_id_hex != anchor.parent_file_id_hex
            ):
                raise ValueError("request root anchor differs from pinned input")


def _strict_load_human_records(
    approval_opened: _OpenedArtifact,
    signature_opened: _OpenedArtifact,
) -> tuple[Any, Any]:
    approval = load_gate_b_human_approval_record_bytes(
        approval_opened.artifact.raw,
        expected_sha256=approval_opened.artifact.sha256,
    )
    signature = load_gate_b_human_signature_record_bytes(
        signature_opened.artifact.raw,
        expected_sha256=signature_opened.artifact.sha256,
        approval=approval,
    )
    if approval_opened.artifact.physical_identity == signature_opened.artifact.physical_identity:
        raise ValueError("approval and signature artifacts must be physically distinct")
    return approval, signature


def _validate_human_trust(
    approval: Any,
    signature: Any,
    readiness_payload: Mapping[str, Any],
) -> None:
    validate_gate_b_readiness_human_trust_chain(
        approval,
        signature,
        readiness_payload,
    )


def _materialization_receipt(operation: str) -> Mapping[str, str]:
    return MappingProxyType(
        {
            "schema_version": "phase6-gate-b-cli-materialization-receipt-v1",
            "operation": operation,
            "status": "created",
        }
    )


def materialize_gate_b_readiness(
    spec_reference: GateBPinnedSpecReference,
) -> Mapping[str, Any]:
    """Strict-load human records before exclusive readiness materialization."""
    with ExitStack() as stack:
        spec = _load_top_spec(
            spec_reference,
            stack,
            operation="materialize-readiness",
        )
        _require_loaded_spec(spec, _ReadinessMaterializationSpec)
        try:
            approval_opened = _open_artifact(
                spec.approval_record,
                stack,
                logical_role="readiness.approval_record",
            )
            signature_opened = _open_artifact(
                spec.signature_record,
                stack,
                logical_role="readiness.signature_record",
            )
            approval, signature = _strict_load_human_records(approval_opened, signature_opened)
            _validate_human_trust(
                approval,
                signature,
                spec.authorization_payload,
            )
            raw = canonical_json_bytes(_plain(spec.authorization_payload))
            output_parent = _open_output_directory(
                spec.output,
                stack,
                logical_role="readiness.output.parent",
            )
            created = create_gate_b_retained_artifact(
                output_parent,
                logical_role="readiness.output",
                direct_child_name=spec.output.direct_child_name,
                raw=raw,
            )
            if created.raw != raw:
                raise ValueError("readiness materialization changed canonical bytes")
            if (
                created.logical_role != "readiness.output"
                or created.bundle_slot_role != "readiness_authorization"
                or created.reference_path != spec.output.path
            ):
                raise ValueError("readiness output retained role mismatch")
            loaded = load_gate_b_readiness_authorization_bytes(
                created.raw,
                expected_sha256=created.sha256,
                expected_approval_record_sha256=approval_opened.artifact.sha256,
                expected_signature_record_sha256=signature_opened.artifact.sha256,
                reference_path=created.reference_path,
            )
            if canonical_json_bytes(_plain(loaded.payload)) != raw:
                raise ValueError("readiness strict reload differs from validated payload")
            _reverify(approval_opened)
            _reverify(signature_opened)
            output_parent.verify_identity()
            if created.physical_identity in {
                approval_opened.artifact.physical_identity,
                signature_opened.artifact.physical_identity,
            }:
                raise ValueError("readiness output physically aliases a human record")
            return _materialization_receipt("materialize-readiness")
        except GateBMaterializationError:
            raise
        except (
            GateBContractError,
            GateBLedgerError,
            GateBLoaderError,
            OSError,
            ValueError,
            TypeError,
        ):
            _raise_sanitized(GateBMaterializationError)


def _open_named_inputs(
    references: Mapping[str, _PinnedArtifactReference],
    stack: ExitStack,
    *,
    materializer: Literal["request", "one_shot"],
) -> dict[str, _OpenedArtifact]:
    ordered_names = {
        "request": (
            "batch_manifest",
            "readiness_authorization",
            "human_approval_record",
            "human_signature_record",
            "execution_context",
        ),
        "one_shot": (
            "loader_request",
            "batch_manifest",
            "readiness_authorization",
            "human_approval_record",
            "human_signature_record",
            "execution_context",
        ),
    }[materializer]
    if set(references) != set(ordered_names):
        raise ValueError("retained named input set mismatch")
    return {
        name: _open_artifact(
            references[name],
            stack,
            logical_role=f"{materializer}.{name}",
        )
        for name in ordered_names
    }


def _load_readiness_from_retained(
    opened: _OpenedArtifact,
    *,
    approval_sha256: str,
    signature_sha256: str,
) -> Any:
    return load_gate_b_readiness_authorization_bytes(
        opened.artifact.raw,
        expected_sha256=opened.artifact.sha256,
        expected_approval_record_sha256=approval_sha256,
        expected_signature_record_sha256=signature_sha256,
        reference_path=opened.artifact.reference_path,
    )


def _load_request_from_retained(
    bundle: GateBRetainedLoaderBundle,
    *,
    approval_sha256: str,
    signature_sha256: str,
) -> GateBLoaderRequest:
    return load_gate_b_loader_request_from_retained(
        bundle,
        expected_sha256=bundle.request.sha256,
        expected_readiness_authorization_sha256=bundle.readiness_authorization.sha256,
        expected_readiness_approval_record_sha256=approval_sha256,
        expected_readiness_signature_record_sha256=signature_sha256,
    )


def _open_retained_roots(
    references: Mapping[str, _PinnedDirectoryReference],
    stack: ExitStack,
    *,
    materializer: Literal["request", "one_shot"],
) -> dict[str, GateBRetainedDirectorySnapshot]:
    roots: dict[str, GateBRetainedDirectorySnapshot] = {}
    for name in ("test_root", "ledger_base", "quarantine_base"):
        roots[name] = _open_directory(
            references[name],
            stack,
            logical_role=f"{materializer}.{name}",
        )
        roots[name].verify_identity()
    return roots


def _open_retained_root_anchors(
    references: Mapping[str, _PinnedArtifactReference],
    roots: Mapping[str, GateBRetainedDirectorySnapshot],
    *,
    materializer: Literal["request", "one_shot"],
) -> dict[str, _OpenedArtifact]:
    return {
        "ledger_root_anchor": _open_root_anchor(
            references["ledger_root_anchor"],
            roots["ledger_base"],
            logical_role=f"{materializer}.ledger_root_anchor",
        ),
        "quarantine_root_anchor": _open_root_anchor(
            references["quarantine_root_anchor"],
            roots["quarantine_base"],
            logical_role=f"{materializer}.quarantine_root_anchor",
        ),
    }


def _build_retained_request_bundle(
    *,
    request: GateBRetainedArtifactSnapshot,
    opened: Mapping[str, _OpenedArtifact],
    roots: Mapping[str, GateBRetainedDirectorySnapshot],
) -> GateBRetainedLoaderBundle:
    return build_gate_b_retained_loader_bundle(
        request=request,
        batch_manifest=opened["batch_manifest"].artifact,
        readiness_authorization=opened["readiness_authorization"].artifact,
        execution_context=opened["execution_context"].artifact,
        ledger_root_anchor=opened["ledger_root_anchor"].artifact,
        quarantine_root_anchor=opened["quarantine_root_anchor"].artifact,
        test_root=roots["test_root"],
        ledger_base=roots["ledger_base"],
        quarantine_base=roots["quarantine_base"],
    )


def materialize_gate_b_loader_request(
    spec_reference: GateBPinnedSpecReference,
) -> Mapping[str, Any]:
    """Exclusive-create a loader request bound to all pinned input snapshots."""
    with ExitStack() as stack:
        spec = _load_top_spec(
            spec_reference,
            stack,
            operation="materialize-request",
        )
        _require_loaded_spec(spec, _RequestMaterializationSpec)
        try:
            references = {
                name: reference
                for name, reference in spec.pinned_inputs.items()
                if type(reference) is _PinnedArtifactReference
                and name not in {"ledger_root_anchor", "quarantine_root_anchor"}
            }
            all_references = {
                name: reference
                for name, reference in spec.pinned_inputs.items()
                if type(reference) is _PinnedArtifactReference
            }
            opened = _open_named_inputs(
                references,
                stack,
                materializer="request",
            )
            roots = _open_retained_roots(
                spec.roots,
                stack,
                materializer="request",
            )
            opened.update(
                _open_retained_root_anchors(
                    all_references,
                    roots,
                    materializer="request",
                )
            )
            _unique_physical_artifacts(tuple(opened.values()))
            _join_request_payload(spec.request_payload, all_references, spec.roots)
            readiness = _load_readiness_from_retained(
                opened["readiness_authorization"],
                approval_sha256=all_references["human_approval_record"].expected_sha256,
                signature_sha256=all_references["human_signature_record"].expected_sha256,
            )
            approval, signature = _strict_load_human_records(
                opened["human_approval_record"], opened["human_signature_record"]
            )
            _validate_human_trust(
                approval,
                signature,
                readiness.payload,
            )
            raw = canonical_json_bytes(_plain(spec.request_payload))
            output_parent = _open_output_directory(
                spec.output,
                stack,
                logical_role="request.output.parent",
            )
            created = create_gate_b_retained_artifact(
                output_parent,
                logical_role="request.output",
                direct_child_name=spec.output.direct_child_name,
                raw=raw,
            )
            if created.raw != raw:
                raise ValueError("request materialization changed canonical bytes")
            if (
                created.logical_role != "request.output"
                or created.bundle_slot_role != "request"
                or created.reference_path != spec.output.path
            ):
                raise ValueError("request output retained role mismatch")
            bundle = _build_retained_request_bundle(
                request=created,
                opened=opened,
                roots=roots,
            )
            request = _load_request_from_retained(
                bundle,
                approval_sha256=all_references["human_approval_record"].expected_sha256,
                signature_sha256=all_references["human_signature_record"].expected_sha256,
            )
            if request.request_sha256 != created.sha256:
                raise ValueError("request strict reload differs from canonical bytes")
            for item in opened.values():
                _reverify(item)
            roots["test_root"].verify_identity()
            output_parent.verify_identity()
            return _materialization_receipt("materialize-request")
        except GateBMaterializationError:
            raise
        except (
            GateBContractError,
            GateBLedgerError,
            GateBLoaderError,
            OSError,
            ValueError,
            TypeError,
        ):
            _raise_sanitized(GateBMaterializationError)


def _load_calibration_evidence(
    reference: _CalibrationBundleReference,
    stack: ExitStack,
) -> tuple[ValidatedPhase6ContractBundleEvidence, tuple[_OpenedArtifact, ...]]:
    relative_paths = tuple(relative_path for relative_path, _reference in reference.artifacts)
    _register_gate_b_retained_calibration_roles(relative_paths)
    stack.callback(_clear_gate_b_retained_calibration_roles)
    root_opened = _open_artifact(
        reference.root_manifest,
        stack,
        logical_role="one_shot.calibration_root_manifest",
    )
    opened = [
        _open_artifact(
            artifact_reference,
            stack,
            logical_role=f"one_shot.calibration_artifact:{relative_path}",
        )
        for relative_path, artifact_reference in reference.artifacts
    ]
    all_opened = (root_opened, *opened)
    _unique_physical_artifacts(all_opened)
    canonical_phase6_contract_artifacts = tuple(
        CanonicalPhase6ContractArtifact(
            relative_path=relative_path,
            raw=artifact.artifact.raw,
            expected_sha256=artifact.artifact.sha256,
        )
        for (relative_path, _reference), artifact in zip(
            reference.artifacts,
            opened,
            strict=True,
        )
    )
    phase6_contract_bundle_evidence = load_phase6_contract_bundle_evidence_from_canonical_artifacts(
        root_opened.artifact.raw,
        expected_sha256=root_opened.artifact.sha256,
        artifacts=canonical_phase6_contract_artifacts,
    )
    return phase6_contract_bundle_evidence, all_opened


def _preflight_gate_b_one_shot(
    spec: _OneShotExecutionSpec,
    request: GateBLoaderRequest,
    retained_roots: Mapping[str, GateBRetainedDirectorySnapshot],
    common_parent: GateBRetainedDirectorySnapshot,
) -> None:
    if is_gate_b_v2_compatibility_object(spec) or is_gate_b_v2_compatibility_object(request):
        _raise_sanitized(GateBPreflightError)
    _require_loaded_spec(spec, _OneShotExecutionSpec)
    try:
        if (
            type(request) is not GateBLoaderRequest
            or request.attempt_ordinal != 1
            or spec.expected_latest_record_sha256 is not None
            or spec.operation_timeout_seconds != 7200
            or spec.process_timeout_seconds != 7500
            or dict(spec.output_limits) != _expected_output_limits()
        ):
            raise ValueError("one-shot initial-attempt contract mismatch")
        expected_children = tuple(
            sorted(reference.absolute_path.name for reference in spec.roots.values())
        )
        if expected_children != spec.common_parent.expected_direct_children:
            raise ValueError("common-parent direct-child contract mismatch")
        for name, reference in spec.roots.items():
            request_root = request.roots[name]
            if (
                Path(request_root["absolute_path"]) != reference.absolute_path
                or request_root["volume_id_hex"] != reference.volume_id_hex
                or request_root["file_id_hex"] != reference.file_id_hex
                or reference.absolute_path.parent != spec.common_parent.absolute_path
            ):
                raise ValueError("request root differs from retained pinned root")
        if common_parent.direct_child_names() != expected_children:
            raise ValueError("common-parent direct-child contract mismatch")
        for name in ("ledger_base", "quarantine_base"):
            anchor_name = f"{name.split('_')[0]}_root_anchor"
            anchor_reference = spec.pinned_inputs[anchor_name]
            if type(anchor_reference) is not _PinnedArtifactReference or retained_roots[
                name
            ].direct_child_names() != (anchor_reference.direct_child_name,):
                raise ValueError("writable root must remain anchor-only")
        retained_roots["test_root"].verify_identity()
        retained_roots["ledger_base"].verify_identity()
        retained_roots["quarantine_base"].verify_identity()
        common_parent.verify_identity()
        verify_gate_b_execution_environment(request, request.execution_context)
        return None
    except GateBPreflightError:
        raise
    except (
        GateBContractError,
        GateBLedgerError,
        GateBLoaderError,
        OSError,
        ValueError,
        TypeError,
    ):
        _raise_sanitized(GateBPreflightError)


class _GateBCallbackClassifier:
    __slots__ = ("_delegate", "_failure_kind")

    def __init__(self, delegate: GateBProductionExecutor) -> None:
        self._delegate = delegate
        self._failure_kind: (
            Literal[
                "gate_b_operation_timeout",
                "gate_b_interrupted",
            ]
            | None
        ) = None

    @property
    def executor_id(self) -> str:
        return self._delegate.executor_id

    @property
    def executor_sha256(self) -> str:
        return self._delegate.executor_sha256

    def execute(
        self,
        input_capability: GateBInputCapability,
        quarantine_outputs: GateBOutputsCapability,
    ) -> None:
        try:
            return self._delegate.execute(input_capability, quarantine_outputs)
        except GateBDeadlineExceeded:
            self._failure_kind = "gate_b_operation_timeout"
            raise
        except KeyboardInterrupt:
            self._failure_kind = "gate_b_interrupted"
            raise

    def consume_failure_kind(
        self,
    ) -> (
        Literal[
            "gate_b_operation_timeout",
            "gate_b_interrupted",
        ]
        | None
    ):
        value = self._failure_kind
        self._failure_kind = None
        return value


def _execution_receipt(receipt: Any) -> Mapping[str, Any]:
    if receipt.state != "SEALED" or receipt.attempt_ordinal != 1:
        raise ValueError("one-shot receipt is not the exact initial SEALED state")
    return MappingProxyType(
        {
            "schema_version": "phase6-gate-b-cli-execution-receipt-v1",
            "operation": "execute-once",
            "status": "sealed",
            "attempt_ordinal": 1,
            "state": "SEALED",
        }
    )


def _open_with_callback_classification(
    prepared: Any,
    executor: GateBProductionExecutor,
) -> Any:
    callback_executor = _GateBCallbackClassifier(executor)
    try:
        return open_gate_b_test_input(
            prepared,
            executor=callback_executor,
        )
    except GateBExecutorFailure:
        failure_kind = callback_executor.consume_failure_kind()
        if failure_kind == "gate_b_operation_timeout":
            raise GateBDeadlineExceeded() from None
        if failure_kind == "gate_b_interrupted":
            raise KeyboardInterrupt from None
        raise


def _validate_gate_b_v2_execution_receipt(value: object) -> Mapping[str, Any]:
    fields = {
        "schema_version",
        "operation",
        "status",
        "attempt_ordinal",
        "state",
        "projection_sha256",
        "execution_binding_sha256",
        "loader_request_sha256",
        "execution_context_sha256",
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("v2 execution receipt fields mismatch")
    if (
        value["schema_version"] != V2_EXECUTION_RECEIPT_SCHEMA
        or value["operation"] != "execute-once-v2"
        or value["status"] != "sealed"
        or type(value["attempt_ordinal"]) is not int
        or value["attempt_ordinal"] != 1
        or value["state"] != "SEALED"
    ):
        raise ValueError("v2 execution receipt identity mismatch")
    for name in fields - {"schema_version", "operation", "status", "attempt_ordinal", "state"}:
        _sha(value[name], f"v2 receipt {name}")
    return MappingProxyType(dict(value))


def _gate_b_v2_receipt_bindings(route: object, request: GateBLoaderRequest) -> dict[str, str]:
    if type(route) is PreparedGateBV2ExecutionRoute:
        prepared = validate_prepared_gate_b_v2_execution_route(route)
        plan = prepared.plan
        return {
            "projection_sha256": plan.projection.sha256,
            "execution_binding_sha256": plan.execution_binding_sha256,
            "loader_request_sha256": plan.request.request_sha256,
            "execution_context_sha256": plan.request.execution_context.sha256,
        }
    roots_hash = sha256_bytes(canonical_json_bytes(_plain(request.roots)))
    binding_hash = sha256_bytes(
        canonical_json_bytes(
            {
                "projection_sha256": roots_hash,
                "loader_request_sha256": request.request_sha256,
                "execution_context_sha256": request.execution_context.sha256,
                "batch_manifest_sha256": request.batch.sha256,
            }
        )
    )
    return {
        "projection_sha256": roots_hash,
        "execution_binding_sha256": binding_hash,
        "loader_request_sha256": request.request_sha256,
        "execution_context_sha256": request.execution_context.sha256,
    }


def _gate_b_v2_execution_receipt(
    route: object,
    request: GateBLoaderRequest,
    receipt: Any,
) -> Mapping[str, Any]:
    if receipt.state != "SEALED" or receipt.attempt_ordinal != 1:
        raise ValueError("v2 one-shot receipt is not the exact initial SEALED state")
    chain = GateBLedgerStore(request).load_chain()
    if not chain or chain[-1].record_sha256 != receipt.sealed_record_sha256:
        raise ValueError("v2 sealed ledger receipt mismatch")
    manifest_hash = chain[-1].payload["quarantine_manifest_sha256"]
    bindings = _gate_b_v2_receipt_bindings(route, request)
    return _validate_gate_b_v2_execution_receipt(
        {
            "schema_version": V2_EXECUTION_RECEIPT_SCHEMA,
            "operation": "execute-once-v2",
            "status": "sealed",
            "attempt_ordinal": 1,
            "state": "SEALED",
            **bindings,
            "sealed_record_sha256": receipt.sealed_record_sha256,
            "quarantine_manifest_sha256": manifest_hash,
        }
    )


def _execute_prepared_gate_b_v2_once(route: object) -> Mapping[str, Any]:
    """Consume one retained v2 route after its complete pre-write boundary."""
    primary_error: BaseException | None = None
    try:
        try:
            request, executor = consume_gate_b_v2_execution_route(route)
        except GateBV2RouteError:
            _raise_sanitized(GateBPreflightError)
        reservation = reserve_gate_b_attempt(request, expected_latest_record_sha256=None)
        prepared = prepare_gate_b_test_open(request, reservation)
        receipt = _open_with_callback_classification(prepared, executor)
        return _gate_b_v2_execution_receipt(route, request, receipt)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            close_gate_b_v2_execution_route(route)
        except BaseException:
            if primary_error is None:
                raise


def execute_gate_b_v2_once(
    spec_reference: GateBV2PinnedSpecReference,
) -> Mapping[str, Any]:
    """Execute one closed v2 bootstrap through the exact retained-route lifecycle."""
    if is_gate_b_v2_execution_route(spec_reference):
        return _execute_prepared_gate_b_v2_once(spec_reference)
    try:
        validate_gate_b_v2_pinned_spec_reference(spec_reference)
    except GateBV2RouteError:
        _raise_sanitized(GateBSpecError)
    try:
        route = prepare_gate_b_v2_execution_route_from_reference(spec_reference)
    except GateBV2RouteError:
        _raise_sanitized(GateBPreflightError)
    return _execute_prepared_gate_b_v2_once(route)


def execute_gate_b_once(
    spec_reference: GateBPinnedSpecReference,
) -> Mapping[str, Any]:
    """Execute exactly one prevalidated Gate B attempt and stop at SEALED."""
    if is_gate_b_v2_compatibility_object(spec_reference):
        _raise_sanitized(GateBPreflightError)
    if type(spec_reference) is not GateBPinnedSpecReference:
        _raise_sanitized(GateBSpecError)
    with ExitStack() as stack:
        spec = _load_top_spec(spec_reference, stack, operation="execute-once")
        _require_loaded_spec(spec, _OneShotExecutionSpec)
        try:
            artifact_references = {
                name: reference
                for name, reference in spec.pinned_inputs.items()
                if type(reference) is _PinnedArtifactReference
                and name not in {"ledger_root_anchor", "quarantine_root_anchor"}
            }
            all_artifact_references = {
                name: reference
                for name, reference in spec.pinned_inputs.items()
                if type(reference) is _PinnedArtifactReference
            }
            opened = _open_named_inputs(
                artifact_references,
                stack,
                materializer="one_shot",
            )
            calibration_reference = spec.pinned_inputs["calibration_bundle"]
            if type(calibration_reference) is not _CalibrationBundleReference:
                raise TypeError("calibration reference type mismatch")
            phase6_contract_bundle_evidence, calibration_opened = _load_calibration_evidence(
                calibration_reference,
                stack,
            )
            retained_roots = _open_retained_roots(
                spec.roots,
                stack,
                materializer="one_shot",
            )
            opened.update(
                _open_retained_root_anchors(
                    all_artifact_references,
                    retained_roots,
                    materializer="one_shot",
                )
            )
            _unique_physical_artifacts((*opened.values(), *calibration_opened))
            common_parent = stack.enter_context(
                open_gate_b_retained_directory(
                    logical_role="one_shot.common_parent",
                    absolute_path=spec.common_parent.absolute_path,
                    expected_volume_id_hex=spec.common_parent.volume_id_hex,
                    expected_file_id_hex=spec.common_parent.file_id_hex,
                )
            )
            common_parent.verify_identity()
            approval, signature = _strict_load_human_records(
                opened["human_approval_record"],
                opened["human_signature_record"],
            )
            bundle = _build_retained_request_bundle(
                request=opened["loader_request"].artifact,
                opened=opened,
                roots=retained_roots,
            )
            request = _load_request_from_retained(
                bundle,
                approval_sha256=all_artifact_references["human_approval_record"].expected_sha256,
                signature_sha256=all_artifact_references["human_signature_record"].expected_sha256,
            )
            readiness = _load_readiness_from_retained(
                opened["readiness_authorization"],
                approval_sha256=all_artifact_references["human_approval_record"].expected_sha256,
                signature_sha256=all_artifact_references["human_signature_record"].expected_sha256,
            )
            _validate_human_trust(
                approval,
                signature,
                readiness.payload,
            )
            for item in opened.values():
                _reverify(item)
            for item in calibration_opened:
                _reverify(item)
            _preflight_gate_b_one_shot(
                spec,
                request,
                retained_roots,
                common_parent,
            )
            executor = GateBProductionExecutor.from_request(
                request,
                phase6_contract_bundle_evidence=phase6_contract_bundle_evidence,
                execution_context_sha256=request.execution_context.sha256,
                operation_timeout_seconds=spec.operation_timeout_seconds,
            )
        except GateBPreflightError:
            raise
        except (GateBLoaderError, GateBExecutorError):
            raise
        except (
            GateBContractError,
            GateBLedgerError,
            OSError,
            ValueError,
            TypeError,
        ):
            _raise_sanitized(GateBPreflightError)
        reservation = reserve_gate_b_attempt(
            request,
            expected_latest_record_sha256=None,
        )
        prepared = prepare_gate_b_test_open(request, reservation)
        receipt = _open_with_callback_classification(prepared, executor)
        return _execution_receipt(receipt)


class _ClosedParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _CliUsageError

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if status == 0:
            raise _CliHelp
        raise _CliUsageError


def _hash_argument(value: str) -> str:
    if _SHA_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected lowercase SHA-256")
    return value


def _hex_argument(value: str) -> str:
    if _HEX_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected canonical lowercase hexadecimal")
    return value


def _positive_argument(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected positive decimal integer") from exc
    if parsed <= 0 or str(parsed) != value:
        raise argparse.ArgumentTypeError("expected positive decimal integer")
    return parsed


def _path_argument(value: str) -> Path:
    try:
        return _absolute(value, "spec parent")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected normalized absolute path") from exc


def _child_argument(value: str) -> str:
    try:
        return _child(value, "spec child")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected canonical direct-child name") from exc


def _parser() -> argparse.ArgumentParser:
    parser = _ClosedParser(
        prog="phase6_gate_b_v1",
        description="Gate B materialization and one-shot lifecycle",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(
        dest="operation",
        required=True,
        parser_class=_ClosedParser,
    )
    for operation in ("materialize-readiness", "materialize-request", "execute-once"):
        child = subparsers.add_parser(
            operation,
            allow_abbrev=False,
        )
        child.add_argument("--spec-parent", required=True, type=_path_argument)
        child.add_argument(
            "--spec-parent-volume-id-hex",
            required=True,
            type=_hex_argument,
        )
        child.add_argument(
            "--spec-parent-file-id-hex",
            required=True,
            type=_hex_argument,
        )
        child.add_argument("--spec-name", required=True, type=_child_argument)
        child.add_argument(
            "--expected-spec-sha256",
            required=True,
            type=_hash_argument,
        )
        child.add_argument(
            "--expected-spec-size-bytes",
            required=True,
            type=_positive_argument,
        )
    return parser


def _candidate_operation(argv: Sequence[str]) -> str:
    if argv and argv[0] in {
        "materialize-readiness",
        "materialize-request",
        "execute-once",
    }:
        return argv[0]
    return "pre-dispatch"


def _spec_reference_from_namespace(namespace: argparse.Namespace) -> GateBPinnedSpecReference:
    return GateBPinnedSpecReference(
        namespace.spec_parent,
        namespace.spec_parent_volume_id_hex,
        namespace.spec_parent_file_id_hex,
        namespace.spec_name,
        namespace.expected_spec_sha256,
        namespace.expected_spec_size_bytes,
    )


def _error_payload(operation: str, error_code: str) -> dict[str, str]:
    if operation not in _OPERATION_VALUES or error_code not in _ERROR_CODE_VALUES:
        raise ValueError("closed CLI failure value mismatch")
    return {
        "schema_version": "phase6-gate-b-cli-error-v1",
        "operation": operation,
        "status": "failed",
        "error_code": error_code,
    }


def _emit_failure(operation: str, error_code: str, exit_status: int) -> int:
    try:
        sys.stderr.buffer.write(canonical_json_bytes(_error_payload(operation, error_code)))
        sys.stderr.buffer.flush()
    except BaseException:
        return exit_status
    return exit_status


def _dispatch(argv: Sequence[str]) -> Mapping[str, Any]:
    namespace = _parser().parse_args(list(argv))
    reference = _spec_reference_from_namespace(namespace)
    if namespace.operation == "materialize-readiness":
        return materialize_gate_b_readiness(reference)
    if namespace.operation == "materialize-request":
        return materialize_gate_b_loader_request(reference)
    if namespace.operation == "execute-once":
        return execute_gate_b_once(reference)
    raise _CliUsageError


def main(argv: Sequence[str] | None = None) -> int:
    """Closed, shell-free CLI dispatcher."""
    raw_argv = tuple(sys.argv[1:] if argv is None else argv)
    operation = _candidate_operation(raw_argv)
    try:
        payload = _dispatch(raw_argv)
        sys.stdout.buffer.write(canonical_json_bytes(_plain(payload)))
        sys.stdout.buffer.flush()
        return 0
    except _CliHelp:
        return 0
    except _CliUsageError:
        return _emit_failure(operation, "gate_b_invalid_arguments", 2)
    except GateBSpecError:
        return _emit_failure(operation, "gate_b_spec_failure", 1)
    except GateBMaterializationError:
        return _emit_failure(operation, "gate_b_materialization_failure", 1)
    except GateBPreflightError:
        return _emit_failure(operation, "gate_b_preflight_failure", 1)
    except GateBContractError:
        return _emit_failure(operation, "gate_b_contract_failure", 1)
    except GateBLedgerError:
        return _emit_failure(operation, "gate_b_ledger_failure", 1)
    except GateBLoaderError:
        return _emit_failure(operation, "gate_b_loader_failure", 1)
    except GateBDeadlineExceeded:
        return _emit_failure(operation, "gate_b_operation_timeout", 124)
    except GateBExecutorError:
        return _emit_failure(operation, "gate_b_executor_failure", 1)
    except GateBOrchestratorError:
        return _emit_failure(operation, "gate_b_orchestrator_failure", 1)
    except KeyboardInterrupt:
        return _emit_failure(operation, "gate_b_interrupted", 130)
    except Exception:
        return _emit_failure(operation, "gate_b_internal_failure", 1)
