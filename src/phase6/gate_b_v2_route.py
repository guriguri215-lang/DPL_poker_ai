"""Gate B Test v2 one-shot planning and retained execution boundary.

The production builder is read-only.  It extends one already-published v2
compatibility trust chain, joins only bytes that are already stored at pinned
paths, and reuses the published v2 root anchors.  Durable reservation remains
an orchestrator action after every retained root and stored artifact passes the
last pre-write verification.

The private disposable-fixture authority is intentionally separate.  It owns
one factory-created temporary directory and is the only route that may execute
the mock lifecycle used by tests.
"""

from __future__ import annotations

import copy
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from phase6.contracts import (
    CanonicalPhase6ContractArtifact,
    ValidatedPhase6ContractBundleEvidence,
    canonical_json_bytes,
    load_phase6_contract_bundle_evidence_from_canonical_artifacts,
    sha256_bytes,
    validate_phase6_contract_bundle_evidence,
)
from phase6.gate_b_contracts import (
    EXECUTION_CONTEXT_SCHEMA_VERSION,
    HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
    HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_SCHEMA_VERSION,
    ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
    GateBBatchManifest,
    GateBContractError,
    GateBExecutionContext,
    GateBReadinessAuthorization,
    GateBV2CompatibilityTrustChain,
    _closed,
    _frozen,
    _plain,
    _root_identity_payload,
    _strict_canonical_object,
    _timestamp,
    _validate_execution_context,
    _validate_human_approval_record,
    _validate_human_signature_record,
    _validate_readiness_authorization,
    build_gate_b_preapproval_root_identity_projection_v2,
    build_gate_b_v2_compatibility_trust_chain,
    gate_b_root_identity_projection_descriptor_v2,
    load_gate_b_batch_manifest_bytes,
    validate_gate_b_v2_compatibility_trust_chain,
)
from phase6.gate_b_executor import (
    MAX_AGGREGATE_OUTPUT_BYTES,
    OUTPUT_LIMITS,
    GateBProductionExecutor,
)
from phase6.gate_b_ledger import (
    GateBPinnedDirectory,
    _verify_directory,
    open_gate_b_v2_pinned_directory,
    verify_gate_b_v2_pinned_directory,
    verify_gate_b_v2_retained_root_topology,
)
from phase6.gate_b_loader import (
    GateBExecutionEvidence,
    GateBLoaderRequest,
    gate_b_v2_route_attestation_sha256,
    verify_gate_b_v2_execution_environment,
)

HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION = "phase6-gate-b-human-approval-record-v4"
HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION = "phase6-gate-b-human-signature-record-v4"
READINESS_AUTHORIZATION_V4_SCHEMA_VERSION = "phase6-gate-b-readiness-authorization-v4"
LOADER_REQUEST_V3_SCHEMA_VERSION = "phase6-gate-b-test-loader-request-v3"
EXECUTION_CONTEXT_V2_SCHEMA_VERSION = "phase6-gate-b-execution-context-v2"
ONE_SHOT_SPEC_V2_SCHEMA_VERSION = "phase6-gate-b-one-shot-execution-spec-v2"
ROUTE_BOOTSTRAP_V2_SCHEMA_VERSION = "phase6-gate-b-v2-route-bootstrap-v1"

_ROOT_ROLES = ("ledger_base", "quarantine_base", "test_root")
_ANCHOR_ROLES = ("ledger_base", "quarantine_base")
_COMPATIBILITY_HASH_FIELD = "compatibility_preflight_request_sha256"
_BUNDLE_ROOT_HASH_FIELD = "phase6_contract_bundle_root_manifest_sha256"
_BUNDLE_PROVENANCE_HASH_FIELD = "phase6_contract_bundle_provenance_sha256"
_SCIENCE_COMMIT_FIELD = "science_commit"
_ROUTE_COMMIT_FIELD = "execution_route_commit"
_ACTIVE_MODULES_HASH_FIELD = "active_module_sources_sha256"
_ROUTE_ATTESTATION_HASH_FIELD = "execution_route_attestation_sha256"
_ARTIFACT_HASH_FIELDS = {
    _COMPATIBILITY_HASH_FIELD,
    _BUNDLE_ROOT_HASH_FIELD,
    _BUNDLE_PROVENANCE_HASH_FIELD,
    "approval_record_sha256",
    "signature_record_sha256",
    "readiness_authorization_sha256",
    "ledger_root_anchor_sha256",
    "quarantine_root_anchor_sha256",
    "loader_request_sha256",
    "execution_context_sha256",
    "batch_manifest_sha256",
}
_PLAN_TOKEN = object()
_PREPARED_TOKEN = object()
_ARTIFACT_TOKEN = object()
_ROOT_REF_TOKEN = object()
_DISPOSABLE_AUTHORITY_TOKEN = object()
_DISPOSABLE_ROUTE_TOKEN = object()
_PINNED_SPEC_TOKEN = object()
_INPUT_OWNER_TOKEN = object()
_ANCHOR_NOT_PROVIDED = object()
_PLAN_REGISTRY: dict[int, tuple[object, ...]] = {}
_PREPARED_REGISTRY: dict[int, tuple[object, ...]] = {}
_ARTIFACT_REGISTRY: dict[int, tuple[object, ...]] = {}
_ROOT_REF_REGISTRY: dict[int, tuple[object, ...]] = {}
_DISPOSABLE_AUTHORITY_REGISTRY: dict[int, tuple[object, ...]] = {}
_DISPOSABLE_ROUTE_REGISTRY: dict[int, tuple[object, ...]] = {}
_PINNED_SPEC_REGISTRY: dict[int, tuple[object, ...]] = {}
_INPUT_OWNER_REGISTRY: dict[int, tuple[object, ...]] = {}
_V2_RUNTIME_REQUEST_PLANS: dict[int, object] = {}
_V2_RESERVATION_AUTHORIZATIONS: dict[int, tuple[object, object]] = {}
_DISPOSABLE_USED_AUTHORITIES: set[int] = set()

_OID_RE = re.compile(r"[0-9a-f]{40}\Z")
_VOLUME_RE = re.compile(r"[0-9a-f]{8}\Z")
_FILE_RE = re.compile(r"[0-9a-f]{16}\Z")
_CHILD_RE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"|\.[A-Za-z0-9][A-Za-z0-9._-]{0,126})\Z"
)
_BOOTSTRAP_INPUT_NAMES = {
    "compatibility_approval_record",
    "compatibility_signature_record",
    "compatibility_readiness_authorization",
    "ledger_root_anchor",
    "quarantine_root_anchor",
    "compatibility_loader_request",
}
_EXECUTION_INPUT_NAMES = {
    "approval_record",
    "signature_record",
    "readiness_authorization",
    "loader_request",
    "execution_context",
    "batch_manifest",
    "one_shot_spec",
}
_PIN_FIELDS = {
    "parent_absolute_path",
    "parent_identity_scheme",
    "parent_serialization_profile",
    "parent_volume_id_hex",
    "parent_file_id_hex",
    "direct_child_name",
    "expected_sha256",
    "expected_size_bytes",
}


class GateBV2RouteError(ValueError):
    """A sanitized v2 one-shot contract or retained-boundary failure."""


def _fail(message: str) -> None:
    error = GateBV2RouteError(message)
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    raise error


def _sha(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _absolute_path(value: object, label: str) -> Path:
    if type(value) is not str or not value:
        _fail(f"{label} must be an absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        _fail(f"{label} must be an absolute control-free path")
    return path


def _windows_drive_type(root: str) -> int:
    """Return the Win32 drive type without opening the candidate path."""
    if os.name != "nt":
        return 0
    import ctypes

    return int(ctypes.windll.kernel32.GetDriveTypeW(root))


def validate_gate_b_v2_fixed_local_path(value: object, label: str) -> Path:
    """Reject nonlocal, device, UNC, ADS, and noncanonical paths before any open."""
    if os.name != "nt" or not isinstance(value, Path):
        _fail(f"{label} must be a Windows fixed-local absolute path")
    text = str(value).replace("/", "\\")
    if (
        not text
        or text.startswith("\\\\")
        or len(text) < 3
        or text[1:3] != ":\\"
        or not text[0].isalpha()
        or ":" in text[2:]
        or ".." in value.parts
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in text)
        or not value.is_absolute()
        or str(value) != os.path.abspath(str(value))
    ):
        _fail(f"{label} must be a Windows fixed-local absolute path")
    drive_root = f"{text[0].upper()}:\\"
    if _windows_drive_type(drive_root) != 3:
        _fail(f"{label} must be on a fixed local volume")
    return value


def _validate_embedded_fixed_local_paths(value: object, label: str) -> None:
    """Reject every declared absolute-path field before retained input acquisition."""
    if isinstance(value, Mapping):
        for name, item in value.items():
            if name == "absolute_path":
                validate_gate_b_v2_fixed_local_path(
                    _absolute_path(item, f"{label} absolute path"),
                    f"{label} absolute path",
                )
            else:
                _validate_embedded_fixed_local_paths(item, label)
    elif isinstance(value, list | tuple):
        for item in value:
            _validate_embedded_fixed_local_paths(item, label)


@dataclass(frozen=True, slots=True, init=False)
class GateBV2PinnedSpecReference:
    """Nominal pinned reference to one closed v2 route-bootstrap manifest."""

    parent_absolute_path: Path
    parent_identity_scheme: str
    parent_serialization_profile: str
    parent_volume_id_hex: str
    parent_file_id_hex: str
    direct_child_name: str
    expected_sha256: str
    expected_size_bytes: int
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBV2PinnedSpecReference:
        if _token is not _PINNED_SPEC_TOKEN:
            raise TypeError("v2 pinned spec-reference construction is private")
        return object.__new__(cls)


def _pinned_spec_snapshot(reference: GateBV2PinnedSpecReference) -> tuple[object, ...]:
    return (
        reference,
        reference.parent_absolute_path,
        reference.parent_identity_scheme,
        reference.parent_serialization_profile,
        reference.parent_volume_id_hex,
        reference.parent_file_id_hex,
        reference.direct_child_name,
        reference.expected_sha256,
        reference.expected_size_bytes,
        reference._token,
    )


def build_gate_b_v2_pinned_spec_reference(
    *,
    parent_absolute_path: Path,
    parent_identity_scheme: str,
    parent_serialization_profile: str,
    parent_volume_id_hex: str,
    parent_file_id_hex: str,
    direct_child_name: str,
    expected_sha256: str,
    expected_size_bytes: int,
) -> GateBV2PinnedSpecReference:
    """Build a closed nominal bootstrap reference without filesystem I/O."""
    try:
        parent = validate_gate_b_v2_fixed_local_path(parent_absolute_path, "v2 spec parent")
        if (
            parent_identity_scheme != "windows-volume-file-id-v1"
            or parent_serialization_profile != ROOT_IDENTITY_SERIALIZATION_PROFILE_V2
            or _VOLUME_RE.fullmatch(parent_volume_id_hex) is None
            or int(parent_volume_id_hex, 16) == 0
            or _FILE_RE.fullmatch(parent_file_id_hex) is None
            or int(parent_file_id_hex, 16) == 0
            or type(direct_child_name) is not str
            or _CHILD_RE.fullmatch(direct_child_name) is None
            or direct_child_name in {".", ".."}
            or ":" in direct_child_name
            or type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
            or type(expected_size_bytes) is not int
            or not 0 < expected_size_bytes < (1 << 63)
        ):
            _fail("v2 pinned spec-reference fields mismatch")
        reference = GateBV2PinnedSpecReference(_token=_PINNED_SPEC_TOKEN)
        values = {
            "parent_absolute_path": parent,
            "parent_identity_scheme": parent_identity_scheme,
            "parent_serialization_profile": parent_serialization_profile,
            "parent_volume_id_hex": parent_volume_id_hex,
            "parent_file_id_hex": parent_file_id_hex,
            "direct_child_name": direct_child_name,
            "expected_sha256": expected_sha256,
            "expected_size_bytes": expected_size_bytes,
            "_token": _PINNED_SPEC_TOKEN,
        }
        for name, item in values.items():
            object.__setattr__(reference, name, item)
        _PINNED_SPEC_REGISTRY[id(reference)] = _pinned_spec_snapshot(reference)
        return reference
    except GateBV2RouteError:
        raise
    except (TypeError, ValueError, OSError, OverflowError):
        _fail("v2 pinned spec-reference fields mismatch")


def validate_gate_b_v2_pinned_spec_reference(
    reference: GateBV2PinnedSpecReference,
) -> GateBV2PinnedSpecReference:
    if type(reference) is not GateBV2PinnedSpecReference:
        _fail("v2 pinned spec-reference nominal type mismatch")
    try:
        current = _pinned_spec_snapshot(reference)
        validate_gate_b_v2_fixed_local_path(reference.parent_absolute_path, "v2 spec parent")
    except GateBV2RouteError:
        raise
    except Exception:
        _fail("v2 pinned spec-reference provenance mismatch")
    if (
        _PINNED_SPEC_REGISTRY.get(id(reference)) != current
        or reference._token is not _PINNED_SPEC_TOKEN
    ):
        _fail("v2 pinned spec-reference provenance mismatch")
    return reference


def _bootstrap_pin(value: object, label: str) -> dict[str, Any]:
    pin = _closed(value, _PIN_FIELDS, label)
    parent = validate_gate_b_v2_fixed_local_path(
        Path(pin["parent_absolute_path"]), f"{label} parent"
    )
    if (
        pin["parent_identity_scheme"] != "windows-volume-file-id-v1"
        or pin["parent_serialization_profile"] != ROOT_IDENTITY_SERIALIZATION_PROFILE_V2
        or type(pin["parent_volume_id_hex"]) is not str
        or _VOLUME_RE.fullmatch(pin["parent_volume_id_hex"]) is None
        or int(pin["parent_volume_id_hex"], 16) == 0
        or type(pin["parent_file_id_hex"]) is not str
        or _FILE_RE.fullmatch(pin["parent_file_id_hex"]) is None
        or int(pin["parent_file_id_hex"], 16) == 0
        or type(pin["direct_child_name"]) is not str
        or _CHILD_RE.fullmatch(pin["direct_child_name"]) is None
        or pin["direct_child_name"] in {".", ".."}
        or ":" in pin["direct_child_name"]
        or type(pin["expected_sha256"]) is not str
        or len(pin["expected_sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in pin["expected_sha256"])
        or type(pin["expected_size_bytes"]) is not int
        or pin["expected_size_bytes"] <= 0
    ):
        _fail(f"{label} fields mismatch")
    result = dict(pin)
    result["parent_absolute_path"] = parent
    return result


def _bootstrap_relative_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or ":" in value:
        _fail("v2 bundle relative path mismatch")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail("v2 bundle relative path mismatch")
    return value


def _validate_bootstrap_payload(raw: bytes) -> dict[str, Any]:
    payload = _strict_canonical_object(raw, "v2 route bootstrap")
    _closed(
        payload,
        {
            "schema_version",
            "artifact_type",
            "compatibility_inputs",
            "phase6_contract_bundle",
            "execution_inputs",
        },
        "v2 route bootstrap",
    )
    if (
        payload["schema_version"] != ROUTE_BOOTSTRAP_V2_SCHEMA_VERSION
        or payload["artifact_type"] != "gate_b_v2_route_bootstrap"
    ):
        _fail("v2 route-bootstrap identity mismatch")
    compatibility = _closed(
        payload["compatibility_inputs"],
        _BOOTSTRAP_INPUT_NAMES,
        "v2 compatibility inputs",
    )
    execution = _closed(
        payload["execution_inputs"],
        _EXECUTION_INPUT_NAMES,
        "v2 execution inputs",
    )
    for name, pin in compatibility.items():
        compatibility[name] = _bootstrap_pin(pin, f"v2 {name}")
    for name, pin in execution.items():
        execution[name] = _bootstrap_pin(pin, f"v2 {name}")
    bundle = _closed(
        payload["phase6_contract_bundle"],
        {"root_manifest", "artifacts"},
        "v2 contract bundle",
    )
    bundle["root_manifest"] = _bootstrap_pin(bundle["root_manifest"], "v2 contract root manifest")
    if type(bundle["artifacts"]) is not list or not bundle["artifacts"]:
        _fail("v2 contract bundle artifact inventory mismatch")
    normalized_artifacts = []
    relative_paths: set[str] = set()
    for index, value in enumerate(bundle["artifacts"]):
        item = _closed(value, {"relative_path", "reference"}, "v2 contract artifact")
        relative = _bootstrap_relative_path(item["relative_path"])
        if relative in relative_paths:
            _fail("v2 contract bundle artifact inventory mismatch")
        relative_paths.add(relative)
        normalized_artifacts.append(
            {
                "relative_path": relative,
                "reference": _bootstrap_pin(item["reference"], f"v2 contract artifact {index}"),
            }
        )
    bundle["artifacts"] = normalized_artifacts
    return payload


def _descriptor_equal(value: object, expected: Mapping[str, Any], label: str) -> None:
    if type(value) is not dict:
        _fail(f"{label} projection descriptor mismatch")
    try:
        observed = canonical_json_bytes(value)
        canonical_expected = canonical_json_bytes(_plain(expected))
    except (TypeError, ValueError):
        _fail(f"{label} projection descriptor mismatch")
    if observed != canonical_expected:
        _fail(f"{label} projection descriptor mismatch")


@dataclass(frozen=True, slots=True)
class _RetainedInputParent:
    path: Path
    serialization_profile: str | None
    volume_id_hex: str
    file_id_hex: str


@dataclass(frozen=True, slots=True)
class _RetainedInputArtifact:
    logical_name: str
    parent_key: str
    direct_child_name: str
    reference_path: Path
    raw: bytes = field(repr=False)
    sha256: str
    size_bytes: int
    physical_identity: tuple[str, str]


@dataclass(frozen=True, slots=True, init=False)
class _GateBV2RetainedInputOwner:
    """Own already-verified artifact parents through the pre-write boundary."""

    parents: Mapping[str, _RetainedInputParent]
    directories: Mapping[str, GateBPinnedDirectory] = field(repr=False, compare=False)
    artifacts: Mapping[str, _RetainedInputArtifact] = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> _GateBV2RetainedInputOwner:
        if _token is not _INPUT_OWNER_TOKEN:
            raise TypeError("v2 retained-input owner construction is private")
        return object.__new__(cls)


def _input_owner_snapshot(owner: _GateBV2RetainedInputOwner) -> tuple[object, ...]:
    return (
        owner,
        tuple(owner.parents.items()),
        tuple(owner.directories.items()),
        tuple(owner.artifacts.items()),
        owner._closed,
        owner._token,
    )


def _validate_input_owner(
    owner: _GateBV2RetainedInputOwner,
    *,
    reread: bool,
) -> _GateBV2RetainedInputOwner:
    if type(owner) is not _GateBV2RetainedInputOwner:
        _fail("v2 retained-input owner nominal mismatch")
    try:
        current = _input_owner_snapshot(owner)
    except Exception:
        _fail("v2 retained-input owner provenance mismatch")
    if (
        _INPUT_OWNER_REGISTRY.get(id(owner)) != current
        or owner._token is not _INPUT_OWNER_TOKEN
        or owner._closed
    ):
        _fail("v2 retained-input owner provenance mismatch")
    try:
        for key, parent in owner.parents.items():
            directory = owner.directories[key]
            if parent.serialization_profile is None:
                directory.verify_identity()
            else:
                verify_gate_b_v2_pinned_directory(
                    directory,
                    serialization_profile=parent.serialization_profile,
                    expected_volume_id_hex=parent.volume_id_hex,
                    expected_file_id_hex=parent.file_id_hex,
                )
        if reread:
            for artifact in owner.artifacts.values():
                observed = owner.directories[artifact.parent_key].read_regular(
                    artifact.direct_child_name,
                    expected_sha256=artifact.sha256,
                    expected_size_bytes=artifact.size_bytes,
                )
                if (
                    observed.raw != artifact.raw
                    or observed.physical_identity != artifact.physical_identity
                ):
                    _fail("v2 retained input bytes or physical identity changed")
    except GateBV2RouteError:
        raise
    except Exception:
        _fail("v2 retained input verification failed closed")
    return owner


def _close_input_owner(owner: _GateBV2RetainedInputOwner) -> None:
    registered = _INPUT_OWNER_REGISTRY.get(id(owner))
    if registered is None or registered[0] is not owner:
        _fail("v2 retained-input owner close provenance mismatch")
    if registered[4] is True:
        return
    first_error: BaseException | None = None
    for _key, directory in reversed(registered[2]):
        try:
            directory.close()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    object.__setattr__(owner, "_closed", True)
    _INPUT_OWNER_REGISTRY[id(owner)] = _input_owner_snapshot(owner)
    if first_error is not None:
        _fail("v2 retained-input owner close failed closed")


def _validate_input_owner_topology(owners: tuple[_GateBV2RetainedInputOwner, ...]) -> None:
    parent_identities: dict[tuple[int, int], str] = {}
    artifact_identities: set[tuple[str, str]] = set()
    for owner in owners:
        validated = _validate_input_owner(owner, reread=True)
        for key, directory in validated.directories.items():
            identity = directory._expected_identity
            normalized = os.path.normcase(str(validated.parents[key].path))
            previous = parent_identities.get(identity)
            if previous is not None and previous != normalized:
                _fail("v2 retained input parent physical alias")
            parent_identities[identity] = normalized
        for artifact in validated.artifacts.values():
            if artifact.physical_identity in artifact_identities:
                _fail("v2 retained input artifact physical alias")
            artifact_identities.add(artifact.physical_identity)


def _open_retained_input_owner(
    pins: Mapping[str, Mapping[str, Any]],
    *,
    supplied_raws: Mapping[str, bytes] | None = None,
) -> _GateBV2RetainedInputOwner:
    if type(pins) is not dict or not pins:
        _fail("v2 retained-input inventory mismatch")
    normalized_pins: dict[str, dict[str, Any]] = {}
    parent_declarations: dict[str, dict[str, Any]] = {}
    # This complete syntactic/fixed-volume pass intentionally precedes every
    # directory or artifact open, including for the public direct planner.
    for name, raw_pin in pins.items():
        pin = dict(raw_pin)
        parent = validate_gate_b_v2_fixed_local_path(
            Path(pin["parent_absolute_path"]),
            f"{name} parent",
        )
        direct_child_name = pin["direct_child_name"]
        if (
            type(name) is not str
            or type(direct_child_name) is not str
            or _CHILD_RE.fullmatch(direct_child_name) is None
            or direct_child_name in {".", ".."}
            or ":" in direct_child_name
            or type(pin["expected_sha256"]) is not str
            or len(pin["expected_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in pin["expected_sha256"])
            or type(pin["expected_size_bytes"]) is not int
            or not 0 < pin["expected_size_bytes"] < (1 << 63)
        ):
            _fail("v2 retained-input pin mismatch")
        reference_path = parent / direct_child_name
        if "reference_path" in pin and pin["reference_path"] != reference_path:
            _fail("v2 retained-input reference path mismatch")
        key = os.path.normcase(str(parent))
        declaration = {
            "path": parent,
            "serialization_profile": pin.get("parent_serialization_profile"),
            "volume_id_hex": pin.get("parent_volume_id_hex"),
            "file_id_hex": pin.get("parent_file_id_hex"),
        }
        previous = parent_declarations.get(key)
        if previous is not None and previous != declaration:
            _fail("v2 retained-input parent identity substitution")
        parent_declarations[key] = declaration
        pin.update(
            {
                "parent_absolute_path": parent,
                "direct_child_name": direct_child_name,
                "reference_path": reference_path,
                "parent_key": key,
            }
        )
        normalized_pins[name] = pin

    opened: dict[str, GateBPinnedDirectory] = {}
    parents: dict[str, _RetainedInputParent] = {}
    artifacts: dict[str, _RetainedInputArtifact] = {}
    try:
        physical_parents: dict[tuple[int, int], str] = {}
        for key in sorted(parent_declarations):
            declaration = parent_declarations[key]
            parent = declaration["path"]
            profile = declaration["serialization_profile"]
            if profile is None:
                metadata = _verify_directory(parent, "v2 retained artifact parent")
                volume_id_hex = format(metadata.st_dev, "x")
                file_id_hex = format(metadata.st_ino, "x")
                directory = GateBPinnedDirectory.open(
                    parent,
                    expected_volume_id_hex=volume_id_hex,
                    expected_file_id_hex=file_id_hex,
                )
            else:
                volume_id_hex = declaration["volume_id_hex"]
                file_id_hex = declaration["file_id_hex"]
                directory = open_gate_b_v2_pinned_directory(
                    parent,
                    serialization_profile=profile,
                    expected_volume_id_hex=volume_id_hex,
                    expected_file_id_hex=file_id_hex,
                )
            identity = directory._expected_identity
            previous = physical_parents.get(identity)
            if previous is not None and previous != key:
                _fail("v2 retained input parent physical alias")
            physical_parents[identity] = key
            opened[key] = directory
            parents[key] = _RetainedInputParent(
                parent,
                profile,
                volume_id_hex,
                file_id_hex,
            )
        physical_artifacts: set[tuple[str, str]] = set()
        for name, pin in normalized_pins.items():
            artifact = opened[pin["parent_key"]].read_regular(
                pin["direct_child_name"],
                expected_sha256=pin["expected_sha256"],
                expected_size_bytes=pin["expected_size_bytes"],
            )
            supplied = None if supplied_raws is None else supplied_raws.get(name)
            if supplied_raws is not None and (
                type(supplied) is not bytes or artifact.raw != supplied
            ):
                _fail("v2 retained input differs from supplied bytes")
            if artifact.physical_identity in physical_artifacts:
                _fail("v2 retained input artifact physical alias")
            physical_artifacts.add(artifact.physical_identity)
            artifacts[name] = _RetainedInputArtifact(
                name,
                pin["parent_key"],
                pin["direct_child_name"],
                pin["reference_path"],
                artifact.raw,
                artifact.sha256,
                artifact.size_bytes,
                artifact.physical_identity,
            )
        owner = _GateBV2RetainedInputOwner(_token=_INPUT_OWNER_TOKEN)
        values = {
            "parents": MappingProxyType(dict(parents)),
            "directories": MappingProxyType(dict(opened)),
            "artifacts": MappingProxyType(dict(artifacts)),
            "_closed": False,
            "_token": _INPUT_OWNER_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(owner, name, value)
        _INPUT_OWNER_REGISTRY[id(owner)] = _input_owner_snapshot(owner)
        return _validate_input_owner(owner, reread=True)
    except BaseException as exc:
        for key in reversed(tuple(opened)):
            with suppress(Exception):
                opened[key].close()
        if isinstance(exc, GateBV2RouteError):
            raise
        _fail("v2 retained-input acquisition failed closed")


def _legacy_payload(
    payload: dict[str, Any],
    *,
    expected_schema: str,
    legacy_schema: str,
    extra_fields: set[str],
    label: str,
) -> dict[str, Any]:
    if payload.get("schema_version") != expected_schema:
        _fail(f"{label} schema identity mismatch")
    legacy = copy.deepcopy(payload)
    for field_name in extra_fields:
        if field_name not in legacy:
            _fail(f"{label} fields are not closed-world")
        legacy.pop(field_name)
    legacy["schema_version"] = legacy_schema
    return legacy


@dataclass(frozen=True, slots=True, init=False)
class GateBV2StoredArtifactSnapshot:
    """Nominal exact-byte snapshot joined to one pinned on-disk file identity."""

    logical_role: str
    reference_path: Path
    raw: bytes = field(repr=False)
    sha256: str
    size_bytes: int
    physical_identity: tuple[int, int]
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBV2StoredArtifactSnapshot:
        if _token is not _ARTIFACT_TOKEN:
            raise TypeError("v2 stored-artifact construction is private")
        return object.__new__(cls)


def _artifact_snapshot_tuple(snapshot: GateBV2StoredArtifactSnapshot) -> tuple[object, ...]:
    return (
        snapshot,
        snapshot.logical_role,
        snapshot.reference_path,
        snapshot.raw,
        snapshot.sha256,
        snapshot.size_bytes,
        snapshot.physical_identity,
        snapshot._token,
    )


def _validate_stored_artifact(
    snapshot: GateBV2StoredArtifactSnapshot,
) -> GateBV2StoredArtifactSnapshot:
    if type(snapshot) is not GateBV2StoredArtifactSnapshot:
        _fail("v2 stored-artifact nominal type mismatch")
    try:
        current = _artifact_snapshot_tuple(snapshot)
    except Exception:
        _fail("v2 stored-artifact provenance mismatch")
    if (
        _ARTIFACT_REGISTRY.get(id(snapshot)) != current
        or snapshot._token is not _ARTIFACT_TOKEN
        or type(snapshot.raw) is not bytes
        or type(snapshot.size_bytes) is not int
        or len(snapshot.raw) != snapshot.size_bytes
        or sha256_bytes(snapshot.raw) != snapshot.sha256
    ):
        _fail("v2 stored-artifact provenance mismatch")
    return snapshot


def _load_stored_artifact(
    raw: object,
    path: object,
    label: str,
    *,
    retained: _RetainedInputArtifact | None = None,
) -> tuple[GateBV2StoredArtifactSnapshot, dict[str, Any]]:
    if type(raw) is not bytes or type(path) is not type(Path()):
        _fail(f"{label} stored input type mismatch")
    reference = _absolute_path(str(path), f"{label} reference")
    owned = bytes(raw)
    try:
        payload = _strict_canonical_object(owned, label)
    except Exception:
        _fail(f"{label} stored-byte acquisition failed")
    if (
        type(retained) is not _RetainedInputArtifact
        or retained.reference_path != reference
        or retained.raw != owned
        or retained.sha256 != sha256_bytes(owned)
        or retained.size_bytes != len(owned)
    ):
        _fail(f"{label} retained stored-byte acquisition mismatch")
    identity = (int(retained.physical_identity[0], 16), int(retained.physical_identity[1], 16))
    snapshot = GateBV2StoredArtifactSnapshot(_token=_ARTIFACT_TOKEN)
    values = {
        "logical_role": label,
        "reference_path": reference,
        "raw": owned,
        "sha256": sha256_bytes(owned),
        "size_bytes": len(owned),
        "physical_identity": identity,
        "_token": _ARTIFACT_TOKEN,
    }
    for name, value in values.items():
        object.__setattr__(snapshot, name, value)
    _ARTIFACT_REGISTRY[id(snapshot)] = _artifact_snapshot_tuple(snapshot)
    return _validate_stored_artifact(snapshot), payload


def _validate_execution_human_and_readiness(
    *,
    approval: dict[str, Any],
    approval_hash: str,
    signature: dict[str, Any],
    signature_hash: str,
    readiness: dict[str, Any],
    descriptor: Mapping[str, Any],
    projection_hash: str,
    compatibility_request_hash: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    extra = {"projection_descriptor", _COMPATIBILITY_HASH_FIELD}
    for payload, label in (
        (approval, "v2 execution approval"),
        (signature, "v2 execution signature"),
        (readiness, "v2 execution readiness"),
    ):
        _descriptor_equal(payload.get("projection_descriptor"), descriptor, label)
        if _sha(payload.get(_COMPATIBILITY_HASH_FIELD), label) != compatibility_request_hash:
            _fail(f"{label} compatibility continuity mismatch")

    approval_legacy = _legacy_payload(
        approval,
        expected_schema=HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
        legacy_schema=HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
        extra_fields=extra,
        label="v2 execution approval record",
    )
    try:
        _validate_human_approval_record(approval_legacy)
    except GateBContractError:
        _fail("v2 execution approval policy mismatch")
    if approval_legacy["approved_roots_sha256"] != projection_hash:
        _fail("v2 execution approval projection mismatch")

    signature_legacy = _legacy_payload(
        signature,
        expected_schema=HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
        legacy_schema=HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
        extra_fields=extra,
        label="v2 execution signature record",
    )
    try:
        _validate_human_signature_record(signature_legacy, approval_legacy, approval_hash)
    except GateBContractError:
        _fail("v2 execution signature policy mismatch")
    if signature_legacy["approved_roots_sha256"] != projection_hash:
        _fail("v2 execution signature projection mismatch")

    readiness_legacy = _legacy_payload(
        readiness,
        expected_schema=READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
        legacy_schema=READINESS_AUTHORIZATION_SCHEMA_VERSION,
        extra_fields=extra,
        label="v2 execution readiness authorization",
    )
    try:
        _validate_readiness_authorization(readiness_legacy)
    except GateBContractError:
        _fail("v2 execution readiness policy mismatch")
    if (
        readiness_legacy["approval_record_sha256"] != approval_hash
        or readiness_legacy["signature_record_sha256"] != signature_hash
        or readiness_legacy["approval_record_id"] != approval_legacy["approval_record_id"]
        or readiness_legacy["approved_roots_sha256"] != projection_hash
    ):
        _fail("v2 execution readiness human-trust join mismatch")
    for field_name in (
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
    ):
        if readiness_legacy[field_name] != approval_legacy[field_name]:
            _fail("v2 execution readiness approval scope mismatch")
    return approval_legacy, signature_legacy, readiness_legacy


def _expected_output_limits() -> dict[str, int]:
    return {**OUTPUT_LIMITS, "aggregate_executor_writable": MAX_AGGREGATE_OUTPUT_BYTES}


class GateBV2RuntimeRootReference(Mapping[str, Any]):
    """Nominal adapter from a published fixed-width root to legacy runtime width."""

    __slots__ = (
        "_anchor_raw",
        "_compatibility_approval_sha256",
        "_compatibility_readiness_sha256",
        "_descriptor",
        "_fixed_root",
        "_payload",
        "_token",
    )

    def __init__(
        self,
        token: object,
        *,
        payload: Mapping[str, Any],
        fixed_root: Mapping[str, Any],
        descriptor: Mapping[str, Any],
        compatibility_approval_sha256: str,
        compatibility_readiness_sha256: str,
        anchor_raw: bytes | None,
    ) -> None:
        if token is not _ROOT_REF_TOKEN:
            raise TypeError("v2 runtime root-reference construction is private")
        object.__setattr__(self, "_payload", MappingProxyType(dict(payload)))
        object.__setattr__(self, "_fixed_root", _frozen(_plain(fixed_root)))
        object.__setattr__(self, "_descriptor", _frozen(_plain(descriptor)))
        object.__setattr__(self, "_compatibility_approval_sha256", compatibility_approval_sha256)
        object.__setattr__(
            self,
            "_compatibility_readiness_sha256",
            compatibility_readiness_sha256,
        )
        object.__setattr__(self, "_anchor_raw", anchor_raw)
        object.__setattr__(self, "_token", _ROOT_REF_TOKEN)

    def __getitem__(self, key: str) -> Any:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


def _root_ref_snapshot(ref: GateBV2RuntimeRootReference) -> tuple[object, ...]:
    return (
        ref,
        canonical_json_bytes(_plain(ref._payload)),
        canonical_json_bytes(_plain(ref._fixed_root)),
        canonical_json_bytes(_plain(ref._descriptor)),
        ref._compatibility_approval_sha256,
        ref._compatibility_readiness_sha256,
        ref._anchor_raw,
        ref._token,
    )


def validate_gate_b_v2_runtime_root_reference(
    ref: GateBV2RuntimeRootReference,
    expected_role: str,
    *,
    anchor_raw: object = _ANCHOR_NOT_PROVIDED,
) -> Mapping[str, Any]:
    """Validate the sole nominal v2 root adapter; used by the ledger dispatch."""
    if type(ref) is not GateBV2RuntimeRootReference or expected_role not in _ROOT_ROLES:
        _fail("v2 runtime root-reference nominal mismatch")
    try:
        current = _root_ref_snapshot(ref)
    except Exception:
        _fail("v2 runtime root-reference provenance mismatch")
    if _ROOT_REF_REGISTRY.get(id(ref)) != current or ref._token is not _ROOT_REF_TOKEN:
        _fail("v2 runtime root-reference provenance mismatch")
    payload = _plain(ref._payload)
    fixed = _plain(ref._fixed_root)
    if payload["root_role"] != expected_role or fixed["root_role"] != expected_role:
        _fail("v2 runtime root-reference role mismatch")
    expected_payload = copy.deepcopy(fixed)
    expected_payload["volume_id_hex"] = format(int(fixed["volume_id_hex"], 16), "x")
    expected_payload["file_id_hex"] = format(int(fixed["file_id_hex"], 16), "x")
    if canonical_json_bytes(payload) != canonical_json_bytes(expected_payload):
        _fail("v2 runtime root-reference adaptation mismatch")
    if expected_role in _ANCHOR_ROLES:
        if (
            type(ref._anchor_raw) is not bytes
            or sha256_bytes(ref._anchor_raw) != payload["anchor_sha256"]
        ):
            _fail("v2 runtime root-reference anchor provenance mismatch")
        if anchor_raw is not _ANCHOR_NOT_PROVIDED and (
            type(anchor_raw) is not bytes or anchor_raw != ref._anchor_raw
        ):
            _fail("published v2 root anchor changed")
    elif (
        ref._anchor_raw is not None
        or payload["anchor_relative_path"] is not None
        or payload["anchor_sha256"] is not None
        or anchor_raw not in {_ANCHOR_NOT_PROVIDED, None}
    ):
        _fail("v2 Test root anchor contract mismatch")
    return MappingProxyType(payload)


def _new_runtime_root_reference(
    chain: GateBV2CompatibilityTrustChain,
    role: str,
) -> GateBV2RuntimeRootReference:
    fixed = _plain(chain.roots[role])
    payload = copy.deepcopy(fixed)
    payload["volume_id_hex"] = format(int(fixed["volume_id_hex"], 16), "x")
    payload["file_id_hex"] = format(int(fixed["file_id_hex"], 16), "x")
    anchor_name = f"{role.removesuffix('_base')}_root_anchor"
    anchor_raw = None if role == "test_root" else bytes(chain._artifact_raws[anchor_name])
    ref = GateBV2RuntimeRootReference(
        _ROOT_REF_TOKEN,
        payload=payload,
        fixed_root=fixed,
        descriptor=chain.descriptor,
        compatibility_approval_sha256=chain.artifact_hashes["approval_record"],
        compatibility_readiness_sha256=chain.artifact_hashes["readiness_authorization"],
        anchor_raw=anchor_raw,
    )
    _ROOT_REF_REGISTRY[id(ref)] = _root_ref_snapshot(ref)
    validate_gate_b_v2_runtime_root_reference(ref, role)
    return ref


def _request_snapshot(request: GateBLoaderRequest) -> tuple[object, ...]:
    if type(request) is not GateBLoaderRequest or set(request.roots) != set(_ROOT_ROLES):
        _fail("v2 runtime request nominal mismatch")
    root_values = tuple(
        (
            role,
            validate_gate_b_v2_runtime_root_reference(request.roots[role], role),
            request.roots[role],
        )
        for role in _ROOT_ROLES
    )
    return (
        request,
        request.request_sha256,
        request.batch,
        request.batch.sha256,
        request.batch.raw_bytes,
        canonical_json_bytes(_plain(request.batch.payload)),
        request.batch.path,
        request.readiness,
        request.readiness.sha256,
        request.readiness._raw,
        canonical_json_bytes(_plain(request.readiness.payload)),
        request.readiness.path,
        request.execution_context,
        request.execution_context.sha256,
        request.execution_context._raw,
        canonical_json_bytes(_plain(request.execution_context.payload)),
        request.execution_context.path,
        root_values,
        request.actor_id,
        request.actor_role,
        request.attempt_ordinal,
        canonical_json_bytes(_plain(request._payload)),
        request._path,
    )


@dataclass(frozen=True, slots=True, init=False)
class GateBV2ExecutionPlan:
    """Write-free, provenance-registered production plan extending a v2 chain."""

    compatibility_chain: GateBV2CompatibilityTrustChain
    phase6_contract_bundle_evidence: ValidatedPhase6ContractBundleEvidence
    projection_descriptor: Mapping[str, Any]
    artifact_hashes: Mapping[str, str]
    roots: Mapping[str, Mapping[str, Any]]
    request: GateBLoaderRequest
    science_commit: str
    execution_route_commit: str
    active_module_sources_sha256: str
    execution_route_attestation_sha256: str
    operation_timeout_seconds: int
    process_timeout_seconds: int
    _artifacts: Mapping[str, GateBV2StoredArtifactSnapshot] = field(repr=False, compare=False)
    _input_owners: tuple[_GateBV2RetainedInputOwner, ...] = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBV2ExecutionPlan:
        if _token is not _PLAN_TOKEN:
            raise TypeError("v2 execution-plan construction is private")
        return object.__new__(cls)

    @property
    def projection(self):
        return self.compatibility_chain.projection

    @property
    def execution_binding_sha256(self) -> str:
        """Bind the receipt to the exact closed one-shot spec in this artifact model."""
        return self.artifact_hashes["one_shot_spec"]


def _plan_snapshot(plan: GateBV2ExecutionPlan) -> tuple[object, ...]:
    return (
        plan,
        plan.compatibility_chain,
        plan.phase6_contract_bundle_evidence,
        plan.phase6_contract_bundle_evidence.root_manifest_sha256,
        plan.phase6_contract_bundle_evidence.provenance_sha256,
        canonical_json_bytes(_plain(plan.projection_descriptor)),
        canonical_json_bytes(_plain(plan.artifact_hashes)),
        canonical_json_bytes(_plain(plan.roots)),
        _request_snapshot(plan.request),
        plan.science_commit,
        plan.execution_route_commit,
        plan.active_module_sources_sha256,
        plan.execution_route_attestation_sha256,
        plan.operation_timeout_seconds,
        plan.process_timeout_seconds,
        tuple((name, artifact) for name, artifact in plan._artifacts.items()),
        plan._input_owners,
        plan._closed,
        plan._token,
    )


def validate_gate_b_v2_execution_plan(plan: GateBV2ExecutionPlan) -> GateBV2ExecutionPlan:
    if type(plan) is not GateBV2ExecutionPlan:
        _fail("v2 execution-plan nominal type mismatch")
    try:
        validate_gate_b_v2_compatibility_trust_chain(plan.compatibility_chain)
        validate_phase6_contract_bundle_evidence(plan.phase6_contract_bundle_evidence)
        if plan.execution_route_attestation_sha256 != gate_b_v2_route_attestation_sha256(
            plan.science_commit,
            plan.execution_route_commit,
        ):
            _fail("v2 execution-route attestation provenance mismatch")
        current = _plan_snapshot(plan)
    except GateBV2RouteError:
        raise
    except Exception:
        _fail("v2 execution-plan provenance mismatch")
    registered = _PLAN_REGISTRY.get(id(plan))
    if (
        registered is None
        or registered[0] is not plan
        or registered[1] is not plan.compatibility_chain
        or registered[2] is not plan.phase6_contract_bundle_evidence
        or registered != current
        or plan._token is not _PLAN_TOKEN
    ):
        _fail("v2 execution-plan provenance mismatch")
    _validate_input_owner_topology(plan._input_owners)
    for snapshot in plan._artifacts.values():
        _validate_stored_artifact(snapshot)
    return plan


def close_gate_b_v2_execution_plan(plan: GateBV2ExecutionPlan) -> None:
    """Close an unprepared plan, using only its registered owner snapshot."""
    registered = _PLAN_REGISTRY.get(id(plan))
    if registered is None:
        if type(plan) is GateBV2ExecutionPlan and plan._closed and plan._token is _PLAN_TOKEN:
            return
        _fail("v2 execution-plan close provenance mismatch")
    if registered[0] is not plan:
        _fail("v2 execution-plan close provenance mismatch")
    validation_error: BaseException | None = None
    try:
        if registered != _plan_snapshot(plan) or plan._token is not _PLAN_TOKEN:
            _fail("v2 execution-plan close provenance mismatch")
    except BaseException as exc:
        validation_error = exc
    first_error: BaseException | None = None
    registered_owners = registered[-3]
    for owner in reversed(registered_owners):
        try:
            _close_input_owner(owner)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    registered_request = registered[8][0]
    if _V2_RUNTIME_REQUEST_PLANS.get(id(registered_request)) is plan:
        _V2_RUNTIME_REQUEST_PLANS.pop(id(registered_request), None)
    authorization = _V2_RESERVATION_AUTHORIZATIONS.get(id(registered_request))
    if authorization is not None and authorization[0] is registered_request:
        _V2_RESERVATION_AUTHORIZATIONS.pop(id(registered_request), None)
    object.__setattr__(plan, "_closed", True)
    _PLAN_REGISTRY.pop(id(plan), None)
    if validation_error is not None:
        _fail("v2 execution-plan close provenance mismatch")
    if first_error is not None:
        _fail("v2 execution-plan close failed closed")


def build_gate_b_v2_execution_plan(
    compatibility_chain: GateBV2CompatibilityTrustChain,
    *,
    phase6_contract_bundle_evidence: ValidatedPhase6ContractBundleEvidence,
    approval_record_raw: bytes,
    approval_record_path: Path,
    signature_record_raw: bytes,
    signature_record_path: Path,
    readiness_authorization_raw: bytes,
    readiness_authorization_path: Path,
    loader_request_raw: bytes,
    loader_request_path: Path,
    execution_context_raw: bytes,
    execution_context_path: Path,
    batch_manifest_raw: bytes,
    batch_manifest_path: Path,
    one_shot_spec_raw: bytes,
    one_shot_spec_path: Path,
    _retained_input_owner: _GateBV2RetainedInputOwner | None = None,
    _retained_input_keys: Mapping[str, str] | None = None,
    _additional_input_owners: tuple[_GateBV2RetainedInputOwner, ...] = (),
) -> GateBV2ExecutionPlan:
    """Build a retained plan; hand it to prepare or close it explicitly without writing roots."""
    created_owner: _GateBV2RetainedInputOwner | None = None
    registered_plan: GateBV2ExecutionPlan | None = None
    try:
        input_rows = (
            ("approval_record", approval_record_raw, approval_record_path, "v2 execution approval"),
            (
                "signature_record",
                signature_record_raw,
                signature_record_path,
                "v2 execution signature",
            ),
            (
                "readiness_authorization",
                readiness_authorization_raw,
                readiness_authorization_path,
                "v2 execution readiness",
            ),
            ("loader_request", loader_request_raw, loader_request_path, "v2 execution request"),
            (
                "execution_context",
                execution_context_raw,
                execution_context_path,
                "v2 execution context",
            ),
            ("batch_manifest", batch_manifest_raw, batch_manifest_path, "v2 batch manifest"),
            ("one_shot_spec", one_shot_spec_raw, one_shot_spec_path, "v2 one-shot spec"),
        )
        validated_paths: dict[str, Path] = {}
        for name, raw, path, label in input_rows:
            if type(raw) is not bytes or type(path) is not type(Path()):
                _fail(f"{label} stored input type mismatch")
            validated_paths[name] = validate_gate_b_v2_fixed_local_path(path, f"{label} path")

        chain = validate_gate_b_v2_compatibility_trust_chain(compatibility_chain)
        validate_phase6_contract_bundle_evidence(phase6_contract_bundle_evidence)
        bundle_evidence = phase6_contract_bundle_evidence
        projection = chain.projection
        descriptor = dict(gate_b_root_identity_projection_descriptor_v2(projection))
        compatibility_request_hash = chain.artifact_hashes["loader_request"]
        for role in _ROOT_ROLES:
            validate_gate_b_v2_fixed_local_path(
                Path(chain.roots[role]["absolute_path"]),
                f"v2 {role} root",
            )

        # The exact supplied bytes are already available to the public
        # planner.  Parse all embedded absolute-path declarations before the
        # first retained parent is acquired, including late request/context
        # fields that otherwise would be discovered only after earlier opens.
        for name, raw, _path, label in input_rows:
            _validate_embedded_fixed_local_paths(
                _strict_canonical_object(raw, label),
                f"v2 {name}",
            )

        supplied_raws = {name: raw for name, raw, _path, _label in input_rows}
        if _retained_input_owner is None:
            direct_pins = {
                name: {
                    "parent_absolute_path": validated_paths[name].parent,
                    "direct_child_name": validated_paths[name].name,
                    "expected_sha256": sha256_bytes(raw),
                    "expected_size_bytes": len(raw),
                    "reference_path": validated_paths[name],
                }
                for name, raw, _path, _label in input_rows
            }
            input_owner = _open_retained_input_owner(direct_pins, supplied_raws=supplied_raws)
            created_owner = input_owner
            input_keys = {name: name for name in supplied_raws}
        else:
            input_owner = _validate_input_owner(_retained_input_owner, reread=True)
            if type(_retained_input_keys) is not dict or set(_retained_input_keys) != set(
                supplied_raws
            ):
                _fail("v2 retained execution-input key inventory mismatch")
            input_keys = dict(_retained_input_keys)
            for name, raw in supplied_raws.items():
                retained = input_owner.artifacts.get(input_keys[name])
                if (
                    type(retained) is not _RetainedInputArtifact
                    or retained.reference_path != validated_paths[name]
                    or retained.raw != raw
                ):
                    _fail("v2 retained execution input continuity mismatch")
        input_owners = (*_additional_input_owners, input_owner)
        if (
            not input_owners
            or any(type(owner) is not _GateBV2RetainedInputOwner for owner in input_owners)
            or len({id(owner) for owner in input_owners}) != len(input_owners)
        ):
            _fail("v2 retained-input owner inventory mismatch")
        _validate_input_owner_topology(input_owners)

        artifacts: dict[str, GateBV2StoredArtifactSnapshot] = {}
        payloads: dict[str, dict[str, Any]] = {}
        for name, raw, path, label in input_rows:
            snapshot, payload = _load_stored_artifact(
                raw,
                path,
                label,
                retained=input_owner.artifacts[input_keys[name]],
            )
            artifacts[name] = snapshot
            payloads[name] = payload

        approval = payloads["approval_record"]
        signature = payloads["signature_record"]
        readiness = payloads["readiness_authorization"]
        context = payloads["execution_context"]
        request = payloads["loader_request"]
        spec = payloads["one_shot_spec"]
        approval_hash = artifacts["approval_record"].sha256
        signature_hash = artifacts["signature_record"].sha256
        readiness_hash = artifacts["readiness_authorization"].sha256
        context_hash = artifacts["execution_context"].sha256
        batch_hash = artifacts["batch_manifest"].sha256
        request_hash = artifacts["loader_request"].sha256

        _approval_legacy, _signature_legacy, readiness_legacy = (
            _validate_execution_human_and_readiness(
                approval=approval,
                approval_hash=approval_hash,
                signature=signature,
                signature_hash=signature_hash,
                readiness=readiness,
                descriptor=descriptor,
                projection_hash=projection.sha256,
                compatibility_request_hash=compatibility_request_hash,
            )
        )

        _descriptor_equal(context.get("projection_descriptor"), descriptor, "v2 context")
        if (
            _sha(context.get(_COMPATIBILITY_HASH_FIELD), "v2 context continuity")
            != compatibility_request_hash
            or _sha(context.get(_BUNDLE_ROOT_HASH_FIELD), "v2 context bundle root")
            != bundle_evidence.root_manifest_sha256
            or _sha(
                context.get(_BUNDLE_PROVENANCE_HASH_FIELD),
                "v2 context bundle provenance",
            )
            != bundle_evidence.provenance_sha256
        ):
            _fail("v2 execution context compatibility or bundle continuity mismatch")
        context_legacy = _legacy_payload(
            context,
            expected_schema=EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
            legacy_schema=EXECUTION_CONTEXT_SCHEMA_VERSION,
            extra_fields={
                "projection_descriptor",
                _COMPATIBILITY_HASH_FIELD,
                _BUNDLE_ROOT_HASH_FIELD,
                _BUNDLE_PROVENANCE_HASH_FIELD,
                _SCIENCE_COMMIT_FIELD,
                _ROUTE_COMMIT_FIELD,
                _ACTIVE_MODULES_HASH_FIELD,
                _ROUTE_ATTESTATION_HASH_FIELD,
            },
            label="v2 execution context",
        )
        validate_gate_b_v2_fixed_local_path(
            Path(context_legacy["repository_root"]["absolute_path"]),
            "v2 execution repository",
        )
        validate_gate_b_v2_fixed_local_path(
            Path(context_legacy["dependency_lock"]["absolute_path"]),
            "v2 execution dependency lock",
        )
        try:
            _validate_execution_context(context_legacy)
        except GateBContractError:
            _fail("v2 execution context policy mismatch")

        request_legacy = _legacy_payload(
            request,
            expected_schema=LOADER_REQUEST_V3_SCHEMA_VERSION,
            legacy_schema=LOADER_REQUEST_SCHEMA_VERSION,
            extra_fields={"operation", "projection_descriptor", _COMPATIBILITY_HASH_FIELD},
            label="v2 execution request",
        )
        _descriptor_equal(request.get("projection_descriptor"), descriptor, "v2 request")
        if (
            request.get("operation") != "execute_once"
            or _sha(request.get(_COMPATIBILITY_HASH_FIELD), "v2 request continuity")
            != compatibility_request_hash
        ):
            _fail("v2 execution request operation or continuity mismatch")
        _closed(
            request_legacy,
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
            "v2 execution request",
        )
        if request_legacy["artifact_type"] != "gate_b_test_loader_request":
            _fail("v2 execution request artifact identity mismatch")
        _timestamp(request_legacy["requested_at_utc"], "v2 execution request timestamp")
        for field_name, artifact_name in (
            ("batch_manifest", "batch_manifest"),
            ("readiness_authorization", "readiness_authorization"),
            ("execution_context", "execution_context"),
        ):
            reference = _closed(request_legacy[field_name], {"absolute_path", "sha256"}, field_name)
            artifact = artifacts[artifact_name]
            if (
                validate_gate_b_v2_fixed_local_path(
                    _absolute_path(reference["absolute_path"], field_name),
                    field_name,
                )
                != artifact.reference_path
                or _sha(reference["sha256"], field_name) != artifact.sha256
            ):
                _fail("v2 execution request artifact reference mismatch")

        request_roots = _closed(
            request_legacy["roots"], set(_ROOT_ROLES), "v2 execution request roots"
        )
        runtime_roots: dict[str, GateBV2RuntimeRootReference] = {}
        for role in _ROOT_ROLES:
            root = _closed(
                request_roots[role],
                {
                    "absolute_path",
                    "anchor_relative_path",
                    "anchor_sha256",
                    "file_id_hex",
                    "identity_scheme",
                    "root_role",
                    "volume_id_hex",
                },
                f"v2 {role} execution root",
            )
            if canonical_json_bytes(root) != canonical_json_bytes(_plain(chain.roots[role])):
                _fail("v2 execution request root differs from published compatibility root")
            runtime_roots[role] = _new_runtime_root_reference(chain, role)

        actor = _closed(request_legacy["actor"], {"actor_id", "actor_role"}, "v2 actor")
        if (
            actor["actor_role"] != "test_runner"
            or actor["actor_id"] != readiness_legacy["authorized_runner_actor_id"]
            or type(request_legacy["attempt_ordinal"]) is not int
            or request_legacy["attempt_ordinal"] != 1
        ):
            _fail("v2 execution request initial actor contract mismatch")

        batch: GateBBatchManifest = load_gate_b_batch_manifest_bytes(
            artifacts["batch_manifest"].raw,
            expected_sha256=batch_hash,
            reference_path=artifacts["batch_manifest"].reference_path,
        )
        if (
            readiness_legacy["test_batch_hash"] != batch_hash
            or readiness_legacy["approved_execution_context_sha256"] != context_hash
            or readiness_legacy["approved_implementation_commit"]
            != batch.payload["git"]["commit_oid"]
            or context_legacy["expected_implementation_commit"]
            != batch.payload["git"]["commit_oid"]
        ):
            _fail("v2 execution artifacts batch/context join mismatch")
        batch_runtime = batch.payload["runtime"]
        fingerprint = context_legacy["runtime_fingerprint"]
        runtime_pairs = {
            "python_implementation": fingerprint["python_implementation"],
            "python_version": fingerprint["python_version"],
            "machine": fingerprint["machine"],
            "os_name": fingerprint["system"],
            "os_release": fingerprint["release"],
        }
        if any(batch_runtime[name] != value for name, value in runtime_pairs.items()):
            _fail("v2 batch/context runtime projection mismatch")
        if (
            batch_runtime["dependency_lock"]["sha256"]
            != context_legacy["dependency_lock"]["sha256"]
            or batch_runtime["dependency_lock"]["size_bytes"]
            != context_legacy["dependency_lock"]["size_bytes"]
        ):
            _fail("v2 batch/context dependency-lock mismatch")

        _descriptor_equal(spec.get("projection_descriptor"), descriptor, "v2 one-shot spec")
        _closed(
            spec,
            {
                "schema_version",
                "artifact_type",
                "projection_descriptor",
                *_ARTIFACT_HASH_FIELDS,
                _SCIENCE_COMMIT_FIELD,
                _ROUTE_COMMIT_FIELD,
                _ACTIVE_MODULES_HASH_FIELD,
                _ROUTE_ATTESTATION_HASH_FIELD,
                "expected_latest_record_sha256",
                "operation_timeout_seconds",
                "process_timeout_seconds",
                "output_limits",
            },
            "v2 one-shot execution spec",
        )
        expected_limits = _expected_output_limits()
        if (
            spec["schema_version"] != ONE_SHOT_SPEC_V2_SCHEMA_VERSION
            or spec["artifact_type"] != "gate_b_one_shot_execution_spec"
            or spec["expected_latest_record_sha256"] is not None
            or type(spec["operation_timeout_seconds"]) is not int
            or spec["operation_timeout_seconds"] != 7200
            or type(spec["process_timeout_seconds"]) is not int
            or spec["process_timeout_seconds"] != 7500
            or type(spec["output_limits"]) is not dict
            or set(spec["output_limits"]) != set(expected_limits)
            or any(
                type(spec["output_limits"][name]) is not int or spec["output_limits"][name] != value
                for name, value in expected_limits.items()
            )
        ):
            _fail("v2 one-shot initial-attempt contract mismatch")
        expected_hashes = {
            _COMPATIBILITY_HASH_FIELD: compatibility_request_hash,
            _BUNDLE_ROOT_HASH_FIELD: bundle_evidence.root_manifest_sha256,
            _BUNDLE_PROVENANCE_HASH_FIELD: bundle_evidence.provenance_sha256,
            "approval_record_sha256": approval_hash,
            "signature_record_sha256": signature_hash,
            "readiness_authorization_sha256": readiness_hash,
            "ledger_root_anchor_sha256": chain.artifact_hashes["ledger_root_anchor"],
            "quarantine_root_anchor_sha256": chain.artifact_hashes["quarantine_root_anchor"],
            "loader_request_sha256": request_hash,
            "execution_context_sha256": context_hash,
            "batch_manifest_sha256": batch_hash,
        }
        if any(_sha(spec.get(name), name) != digest for name, digest in expected_hashes.items()):
            _fail("v2 one-shot artifact hash join mismatch")

        science_commit = context.get(_SCIENCE_COMMIT_FIELD)
        execution_route_commit = context.get(_ROUTE_COMMIT_FIELD)
        active_module_sources_sha256 = context.get(_ACTIVE_MODULES_HASH_FIELD)
        declared_route_attestation_sha256 = context.get(_ROUTE_ATTESTATION_HASH_FIELD)
        expected_active_modules_hash = sha256_bytes(
            canonical_json_bytes(_plain(context_legacy["active_modules"]))
        )
        expected_route_attestation_sha256 = (
            gate_b_v2_route_attestation_sha256(science_commit, execution_route_commit)
            if type(science_commit) is str
            and _OID_RE.fullmatch(science_commit) is not None
            and type(execution_route_commit) is str
            and _OID_RE.fullmatch(execution_route_commit) is not None
            and science_commit != execution_route_commit
            else None
        )
        if (
            type(science_commit) is not str
            or _OID_RE.fullmatch(science_commit) is None
            or science_commit != context_legacy["expected_implementation_commit"]
            or science_commit != batch.payload["git"]["commit_oid"]
            or type(execution_route_commit) is not str
            or _OID_RE.fullmatch(execution_route_commit) is None
            or execution_route_commit == science_commit
            or _sha(active_module_sources_sha256, "v2 active-module source hash")
            != expected_active_modules_hash
            or spec.get(_SCIENCE_COMMIT_FIELD) != science_commit
            or spec.get(_ROUTE_COMMIT_FIELD) != execution_route_commit
            or spec.get(_ACTIVE_MODULES_HASH_FIELD) != active_module_sources_sha256
            or _sha(
                declared_route_attestation_sha256,
                "v2 execution-route attestation hash",
            )
            != expected_route_attestation_sha256
            or spec.get(_ROUTE_ATTESTATION_HASH_FIELD) != declared_route_attestation_sha256
        ):
            _fail("v2 science, route, and active-module join mismatch")
        execution_route_attestation_sha256 = declared_route_attestation_sha256

        readiness_object = GateBReadinessAuthorization(
            readiness_hash,
            _frozen(readiness_legacy),
            artifacts["readiness_authorization"].raw,
            artifacts["readiness_authorization"].reference_path,
        )
        context_object = GateBExecutionContext(
            context_hash,
            _frozen(context_legacy),
            artifacts["execution_context"].raw,
            artifacts["execution_context"].reference_path,
        )
        request_object = GateBLoaderRequest(
            request_hash,
            batch,
            readiness_object,
            context_object,
            MappingProxyType(dict(runtime_roots)),
            actor["actor_id"],
            actor["actor_role"],
            1,
            _frozen(request),
            artifacts["loader_request"].reference_path,
        )
        artifact_hashes = {
            "compatibility_preflight_request": compatibility_request_hash,
            "phase6_contract_bundle_root_manifest": bundle_evidence.root_manifest_sha256,
            "phase6_contract_bundle_provenance": bundle_evidence.provenance_sha256,
            "approval_record": approval_hash,
            "signature_record": signature_hash,
            "readiness_authorization": readiness_hash,
            "ledger_root_anchor": chain.artifact_hashes["ledger_root_anchor"],
            "quarantine_root_anchor": chain.artifact_hashes["quarantine_root_anchor"],
            "loader_request": request_hash,
            "execution_context": context_hash,
            "batch_manifest": batch_hash,
            "one_shot_spec": artifacts["one_shot_spec"].sha256,
        }
        plan = GateBV2ExecutionPlan(_token=_PLAN_TOKEN)
        values = {
            "compatibility_chain": chain,
            "phase6_contract_bundle_evidence": bundle_evidence,
            "projection_descriptor": _frozen(descriptor),
            "artifact_hashes": MappingProxyType(dict(artifact_hashes)),
            "roots": chain.roots,
            "request": request_object,
            "science_commit": science_commit,
            "execution_route_commit": execution_route_commit,
            "active_module_sources_sha256": active_module_sources_sha256,
            "execution_route_attestation_sha256": execution_route_attestation_sha256,
            "operation_timeout_seconds": 7200,
            "process_timeout_seconds": 7500,
            "_artifacts": MappingProxyType(dict(artifacts)),
            "_input_owners": input_owners,
            "_closed": False,
            "_token": _PLAN_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(plan, name, value)
        _PLAN_REGISTRY[id(plan)] = _plan_snapshot(plan)
        registered_plan = plan
        validated_plan = validate_gate_b_v2_execution_plan(plan)
        _V2_RUNTIME_REQUEST_PLANS[id(plan.request)] = plan
        created_owner = None
        return validated_plan
    except GateBV2RouteError:
        if registered_plan is not None:
            with suppress(Exception):
                close_gate_b_v2_execution_plan(registered_plan)
        elif created_owner is not None:
            with suppress(Exception):
                _close_input_owner(created_owner)
        raise
    except (GateBContractError, KeyError, TypeError, ValueError, OverflowError, OSError):
        if registered_plan is not None:
            with suppress(Exception):
                close_gate_b_v2_execution_plan(registered_plan)
        elif created_owner is not None:
            with suppress(Exception):
                _close_input_owner(created_owner)
        _fail("Gate B v2 execution plan failed closed")


def is_gate_b_v2_runtime_request(value: object) -> bool:
    plan = _V2_RUNTIME_REQUEST_PLANS.get(id(value))
    return (
        type(value) is GateBLoaderRequest
        and type(plan) is GateBV2ExecutionPlan
        and plan.request is value
    )


def claim_gate_b_v2_reservation_authorization(request: GateBLoaderRequest) -> None:
    """Consume the one reserve capability minted only by route.consume()."""
    authorization = _V2_RESERVATION_AUTHORIZATIONS.pop(id(request), None)
    if (
        authorization is None
        or authorization[0] is not request
        or type(authorization[1]) is not PreparedGateBV2ExecutionRoute
    ):
        _fail("v2 reservation is not authorized by a consumed route")
    route = authorization[1]
    validated = validate_prepared_gate_b_v2_execution_route(route)
    if validated.request is not request or validated._closed or not validated._consumed:
        _fail("v2 reservation authorization provenance mismatch")


def verify_gate_b_v2_runtime_execution_environment(
    request: GateBLoaderRequest,
    context: GateBExecutionContext,
) -> GateBExecutionEvidence:
    """Resolve an exact registered request to its approved two-commit plan."""
    plan = _V2_RUNTIME_REQUEST_PLANS.get(id(request))
    if type(plan) is not GateBV2ExecutionPlan or plan.request is not request:
        _fail("v2 runtime request provenance mismatch")
    validated = validate_gate_b_v2_execution_plan(plan)
    try:
        evidence, attestation_sha256 = verify_gate_b_v2_execution_environment(
            request,
            context,
            science_commit=validated.science_commit,
            execution_route_commit=validated.execution_route_commit,
        )
    except Exception:
        _fail("v2 execution environment failed closed")
    if (
        type(evidence) is not GateBExecutionEvidence
        or evidence.execution_context_sha256 != request.execution_context.sha256
        or evidence.implementation_commit != validated.science_commit
        or evidence.active_module_sources_sha256 != validated.active_module_sources_sha256
        or attestation_sha256 != validated.execution_route_attestation_sha256
    ):
        _fail("v2 execution environment evidence join mismatch")
    return evidence


def _executor_snapshot(executor: GateBProductionExecutor) -> tuple[object, ...]:
    if type(executor) is not GateBProductionExecutor:
        _fail("v2 production executor nominal mismatch")
    validate_phase6_contract_bundle_evidence(executor._phase6_contract_bundle_evidence)
    return (
        executor,
        executor.executor_id,
        executor.executor_sha256,
        executor._batch_hash,
        executor._execution_context_sha256,
        canonical_json_bytes(_plain(executor._manifest)),
        executor._operation_timeout_seconds,
        executor._phase6_contract_bundle_evidence,
        executor._phase6_contract_bundle_evidence.provenance_sha256,
        executor._locked,
    )


@dataclass(frozen=True, slots=True, init=False)
class PreparedGateBV2ExecutionRoute:
    """Single-consumer retained-root owner for one production v2 plan."""

    plan: GateBV2ExecutionPlan
    executor: GateBProductionExecutor = field(repr=False, compare=False)
    _executor_provenance: tuple[object, ...] = field(repr=False, compare=False)
    _directories: Mapping[str, GateBPinnedDirectory] = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _consumed: bool = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> PreparedGateBV2ExecutionRoute:
        if _token is not _PREPARED_TOKEN:
            raise TypeError("v2 prepared-route construction is private")
        return object.__new__(cls)

    @property
    def request(self) -> GateBLoaderRequest:
        return self.plan.request

    def verify_pre_write(self) -> None:
        route = validate_prepared_gate_b_v2_execution_route(self)
        if route._closed or route._consumed:
            _fail("v2 prepared route is not available")
        plan = validate_gate_b_v2_execution_plan(route.plan)
        for role in _ROOT_ROLES:
            root = plan.roots[role]
            verify_gate_b_v2_pinned_directory(
                route._directories[role],
                serialization_profile=ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
                expected_volume_id_hex=root["volume_id_hex"],
                expected_file_id_hex=root["file_id_hex"],
            )
        verify_gate_b_v2_retained_root_topology(route._directories)
        for role, artifact_name in (
            ("ledger_base", "ledger_root_anchor"),
            ("quarantine_base", "quarantine_root_anchor"),
        ):
            root = plan.roots[role]
            directory = route._directories[role]
            expected_raw = plan.compatibility_chain._artifact_raws[artifact_name]
            if directory.direct_child_names() != (root["anchor_relative_path"],):
                _fail("v2 writable root changed before reservation")
            retained = directory.read_regular(
                root["anchor_relative_path"],
                expected_sha256=plan.compatibility_chain.artifact_hashes[artifact_name],
                expected_size_bytes=len(expected_raw),
            )
            if retained.raw != expected_raw:
                _fail("published v2 root anchor changed before reservation")
        try:
            evidence = verify_gate_b_v2_runtime_execution_environment(
                plan.request,
                plan.request.execution_context,
            )
        except Exception:
            _fail("v2 execution environment failed before reservation")
        if (
            type(evidence) is not GateBExecutionEvidence
            or evidence.execution_context_sha256 != plan.request.execution_context.sha256
            or evidence.implementation_commit != plan.request.batch.payload["git"]["commit_oid"]
        ):
            _fail("v2 execution environment evidence join mismatch")

    def consume(self) -> tuple[GateBLoaderRequest, GateBProductionExecutor]:
        self.verify_pre_write()
        object.__setattr__(self, "_consumed", True)
        _PREPARED_REGISTRY[id(self)] = _prepared_snapshot(self)
        if id(self.request) in _V2_RESERVATION_AUTHORIZATIONS:
            _fail("v2 reservation authorization already exists")
        _V2_RESERVATION_AUTHORIZATIONS[id(self.request)] = (self.request, self)
        return self.request, self.executor

    def close(self) -> None:
        registered = _PREPARED_REGISTRY.get(id(self))
        registered_directories = (
            dict(registered[4]) if registered is not None and registered[0] is self else {}
        )
        registered_closed = bool(
            registered is not None and registered[0] is self and registered[5] is True
        )
        if registered_closed:
            try:
                if registered != _prepared_snapshot(self) or self._token is not _PREPARED_TOKEN:
                    _fail("v2 retained-root close provenance failed closed")
            except GateBV2RouteError:
                raise
            except Exception:
                _fail("v2 retained-root close provenance failed closed")
            return
        validation_error: BaseException | None = None
        try:
            validate_prepared_gate_b_v2_execution_route(self)
        except BaseException as exc:
            validation_error = exc
        first_error: BaseException | None = None
        for role in reversed(_ROOT_ROLES):
            try:
                registered_directories[role].close()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        registered_plan = (
            registered[1] if registered is not None and registered[0] is self else None
        )
        if type(registered_plan) is GateBV2ExecutionPlan:
            try:
                close_gate_b_v2_execution_plan(registered_plan)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        object.__setattr__(self, "_closed", True)
        _PREPARED_REGISTRY[id(self)] = _prepared_snapshot(self)
        if validation_error is not None:
            _fail("v2 retained-root close provenance failed closed")
        if first_error is not None:
            _fail("v2 retained-root close failed closed")


def _prepared_snapshot(route: PreparedGateBV2ExecutionRoute) -> tuple[object, ...]:
    return (
        route,
        route.plan,
        route.executor,
        route._executor_provenance,
        tuple((role, route._directories[role]) for role in _ROOT_ROLES),
        route._closed,
        route._consumed,
        route._token,
    )


def validate_prepared_gate_b_v2_execution_route(
    route: PreparedGateBV2ExecutionRoute,
) -> PreparedGateBV2ExecutionRoute:
    if type(route) is not PreparedGateBV2ExecutionRoute:
        _fail("v2 prepared-route nominal type mismatch")
    try:
        current = _prepared_snapshot(route)
        fresh_executor = _executor_snapshot(route.executor)
    except GateBV2RouteError:
        raise
    except Exception:
        _fail("v2 prepared-route provenance mismatch")
    if (
        _PREPARED_REGISTRY.get(id(route)) is None
        or _PREPARED_REGISTRY[id(route)][0] is not route
        or _PREPARED_REGISTRY[id(route)][1] is not route.plan
        or _PREPARED_REGISTRY[id(route)][2] is not route.executor
        or any(
            registered_directory is not route._directories[role]
            for role, registered_directory in _PREPARED_REGISTRY[id(route)][4]
        )
        or _PREPARED_REGISTRY[id(route)] != current
        or fresh_executor != route._executor_provenance
        or route.executor._phase6_contract_bundle_evidence
        is not route.plan.phase6_contract_bundle_evidence
        or route._token is not _PREPARED_TOKEN
    ):
        _fail("v2 prepared-route provenance mismatch")
    validate_gate_b_v2_execution_plan(route.plan)
    return route


def prepare_gate_b_v2_execution_route(
    plan: GateBV2ExecutionPlan,
) -> PreparedGateBV2ExecutionRoute:
    """Build the exact executor, then retain exact roots without any write."""
    validated = validate_gate_b_v2_execution_plan(plan)
    try:
        executor = GateBProductionExecutor.from_request(
            validated.request,
            phase6_contract_bundle_evidence=validated.phase6_contract_bundle_evidence,
            execution_context_sha256=validated.request.execution_context.sha256,
            operation_timeout_seconds=validated.operation_timeout_seconds,
        )
        executor_provenance = _executor_snapshot(executor)
    except GateBV2RouteError:
        with suppress(Exception):
            close_gate_b_v2_execution_plan(validated)
        raise
    except Exception:
        with suppress(Exception):
            close_gate_b_v2_execution_plan(validated)
        _fail("v2 production executor construction failed closed")
    opened: dict[str, GateBPinnedDirectory] = {}
    try:
        for role in _ROOT_ROLES:
            root = validated.roots[role]
            opened[role] = open_gate_b_v2_pinned_directory(
                root["absolute_path"],
                serialization_profile=ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
                expected_volume_id_hex=root["volume_id_hex"],
                expected_file_id_hex=root["file_id_hex"],
            )
        route = PreparedGateBV2ExecutionRoute(_token=_PREPARED_TOKEN)
        values = {
            "plan": validated,
            "executor": executor,
            "_executor_provenance": executor_provenance,
            "_directories": MappingProxyType(dict(opened)),
            "_closed": False,
            "_consumed": False,
            "_token": _PREPARED_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(route, name, value)
        _PREPARED_REGISTRY[id(route)] = _prepared_snapshot(route)
        route.verify_pre_write()
        return route
    except BaseException:
        for role in reversed(_ROOT_ROLES):
            directory = opened.get(role)
            if directory is not None:
                with suppress(Exception):
                    directory.close()
        with suppress(Exception):
            close_gate_b_v2_execution_plan(validated)
        raise


def _read_v2_bootstrap_reference(
    reference: GateBV2PinnedSpecReference,
) -> tuple[bytes, _GateBV2RetainedInputOwner]:
    validated = validate_gate_b_v2_pinned_spec_reference(reference)
    owner = _open_retained_input_owner(
        {
            "bootstrap": {
                "parent_absolute_path": validated.parent_absolute_path,
                "parent_serialization_profile": validated.parent_serialization_profile,
                "parent_volume_id_hex": validated.parent_volume_id_hex,
                "parent_file_id_hex": validated.parent_file_id_hex,
                "direct_child_name": validated.direct_child_name,
                "expected_sha256": validated.expected_sha256,
                "expected_size_bytes": validated.expected_size_bytes,
            }
        }
    )
    return owner.artifacts["bootstrap"].raw, owner


def _read_v2_bootstrap_inputs(
    payload: Mapping[str, Any],
) -> tuple[dict[str, bytes], dict[str, Path], _GateBV2RetainedInputOwner]:
    pins: dict[str, Mapping[str, Any]] = {}
    pins.update(
        {f"compatibility:{name}": pin for name, pin in payload["compatibility_inputs"].items()}
    )
    pins.update({f"execution:{name}": pin for name, pin in payload["execution_inputs"].items()})
    bundle = payload["phase6_contract_bundle"]
    pins["bundle:root_manifest"] = bundle["root_manifest"]
    pins.update(
        {
            f"bundle:artifact:{item['relative_path']}": item["reference"]
            for item in bundle["artifacts"]
        }
    )
    parent_specs: dict[str, Mapping[str, Any]] = {}
    for pin in pins.values():
        key = os.path.normcase(str(pin["parent_absolute_path"]))
        previous = parent_specs.get(key)
        if previous is not None and (
            previous["parent_volume_id_hex"],
            previous["parent_file_id_hex"],
            previous["parent_serialization_profile"],
        ) != (
            pin["parent_volume_id_hex"],
            pin["parent_file_id_hex"],
            pin["parent_serialization_profile"],
        ):
            _fail("v2 bootstrap parent identity substitution")
        parent_specs[key] = pin
    owner = _open_retained_input_owner(dict(pins))
    raws = {name: owner.artifacts[name].raw for name in pins}
    paths = {name: owner.artifacts[name].reference_path for name in pins}
    return raws, paths, owner


def prepare_gate_b_v2_execution_route_from_reference(
    spec_reference: GateBV2PinnedSpecReference,
) -> PreparedGateBV2ExecutionRoute:
    """Resolve one closed bootstrap into the exact read-only plan and retained route."""
    spec_owner: _GateBV2RetainedInputOwner | None = None
    input_owner: _GateBV2RetainedInputOwner | None = None
    try:
        bootstrap_raw, spec_owner = _read_v2_bootstrap_reference(spec_reference)
        payload = _validate_bootstrap_payload(bootstrap_raw)
        raws, paths, input_owner = _read_v2_bootstrap_inputs(payload)
        _validate_input_owner_topology((spec_owner, input_owner))

        compatibility_request = _strict_canonical_object(
            raws["compatibility:compatibility_loader_request"],
            "v2 compatibility loader request",
        )
        projection = build_gate_b_preapproval_root_identity_projection_v2(
            compatibility_request["roots"]
        )
        compatibility_chain = build_gate_b_v2_compatibility_trust_chain(
            projection,
            approval_record_raw=raws["compatibility:compatibility_approval_record"],
            signature_record_raw=raws["compatibility:compatibility_signature_record"],
            readiness_authorization_raw=raws["compatibility:compatibility_readiness_authorization"],
            root_anchor_raws={
                "ledger_base": raws["compatibility:ledger_root_anchor"],
                "quarantine_base": raws["compatibility:quarantine_root_anchor"],
            },
            loader_request_raw=raws["compatibility:compatibility_loader_request"],
        )
        bundle_artifacts = tuple(
            CanonicalPhase6ContractArtifact(
                item["relative_path"],
                raws[f"bundle:artifact:{item['relative_path']}"],
                item["reference"]["expected_sha256"],
            )
            for item in payload["phase6_contract_bundle"]["artifacts"]
        )
        root_pin = payload["phase6_contract_bundle"]["root_manifest"]
        bundle_evidence = load_phase6_contract_bundle_evidence_from_canonical_artifacts(
            raws["bundle:root_manifest"],
            expected_sha256=root_pin["expected_sha256"],
            artifacts=bundle_artifacts,
        )
        execution = {
            name: (raws[f"execution:{name}"], paths[f"execution:{name}"])
            for name in _EXECUTION_INPUT_NAMES
        }
        plan = build_gate_b_v2_execution_plan(
            compatibility_chain,
            phase6_contract_bundle_evidence=bundle_evidence,
            approval_record_raw=execution["approval_record"][0],
            approval_record_path=execution["approval_record"][1],
            signature_record_raw=execution["signature_record"][0],
            signature_record_path=execution["signature_record"][1],
            readiness_authorization_raw=execution["readiness_authorization"][0],
            readiness_authorization_path=execution["readiness_authorization"][1],
            loader_request_raw=execution["loader_request"][0],
            loader_request_path=execution["loader_request"][1],
            execution_context_raw=execution["execution_context"][0],
            execution_context_path=execution["execution_context"][1],
            batch_manifest_raw=execution["batch_manifest"][0],
            batch_manifest_path=execution["batch_manifest"][1],
            one_shot_spec_raw=execution["one_shot_spec"][0],
            one_shot_spec_path=execution["one_shot_spec"][1],
            _retained_input_owner=input_owner,
            _retained_input_keys={name: f"execution:{name}" for name in _EXECUTION_INPUT_NAMES},
            _additional_input_owners=(spec_owner,),
        )
        prepared = prepare_gate_b_v2_execution_route(plan)
        input_owner = None
        spec_owner = None
        return prepared
    except GateBV2RouteError:
        raise
    except (GateBContractError, KeyError, TypeError, ValueError, OSError, OverflowError):
        _fail("Gate B v2 bootstrap failed closed")
    finally:
        for owner in (input_owner, spec_owner):
            if owner is not None:
                registered = _INPUT_OWNER_REGISTRY.get(id(owner))
                if registered is not None and registered[4] is False:
                    with suppress(Exception):
                        _close_input_owner(owner)


@dataclass(frozen=True, slots=True, init=False)
class _GateBV2DisposableFixtureAuthority:
    root: Path
    physical_identity: tuple[str, str]
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> _GateBV2DisposableFixtureAuthority:
        if _token is not _DISPOSABLE_AUTHORITY_TOKEN:
            raise TypeError("disposable v2 fixture authority construction is private")
        return object.__new__(cls)


def _authority_snapshot(authority: _GateBV2DisposableFixtureAuthority) -> tuple[object, ...]:
    return (
        authority,
        authority.root,
        authority.physical_identity,
        authority._token,
    )


def _validate_disposable_authority(
    authority: _GateBV2DisposableFixtureAuthority,
) -> _GateBV2DisposableFixtureAuthority:
    if type(authority) is not _GateBV2DisposableFixtureAuthority:
        _fail("disposable v2 fixture authority nominal mismatch")
    try:
        current = _authority_snapshot(authority)
        observed = _root_identity_payload(str(authority.root))
    except Exception:
        _fail("disposable v2 fixture authority provenance mismatch")
    if (
        _DISPOSABLE_AUTHORITY_REGISTRY.get(id(authority)) != current
        or authority._token is not _DISPOSABLE_AUTHORITY_TOKEN
        or (observed["volume_id_hex"], observed["file_id_hex"]) != authority.physical_identity
    ):
        _fail("disposable v2 fixture authority provenance mismatch")
    return authority


def _create_disposable_gate_b_v2_fixture_authority(
    parent: Path,
) -> _GateBV2DisposableFixtureAuthority:
    """Exclusively create and bind one fresh test-only directory under OS temp."""
    if type(parent) is not type(Path()):
        _fail("disposable v2 fixture parent type mismatch")
    candidate = parent.resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if candidate != temp_root and temp_root not in candidate.parents:
        _fail("disposable v2 fixture parent must be within OS temp")
    try:
        _verify_directory(candidate, "disposable v2 fixture parent")
        root = Path(tempfile.mkdtemp(prefix="gate-b-v2-", dir=candidate)).resolve()
        observed = _root_identity_payload(str(root))
    except Exception:
        _fail("disposable v2 fixture authority creation failed")
    authority = _GateBV2DisposableFixtureAuthority(_token=_DISPOSABLE_AUTHORITY_TOKEN)
    values = {
        "root": root,
        "physical_identity": (observed["volume_id_hex"], observed["file_id_hex"]),
        "_token": _DISPOSABLE_AUTHORITY_TOKEN,
    }
    for name, value in values.items():
        object.__setattr__(authority, name, value)
    _DISPOSABLE_AUTHORITY_REGISTRY[id(authority)] = _authority_snapshot(authority)
    return _validate_disposable_authority(authority)


def _legacy_request_snapshot(request: GateBLoaderRequest) -> tuple[object, ...]:
    if type(request) is not GateBLoaderRequest:
        _fail("disposable v2 fixture request nominal mismatch")
    return (
        request,
        request.request_sha256,
        request.batch,
        request.batch.sha256,
        request.batch.raw_bytes,
        canonical_json_bytes(_plain(request.batch.payload)),
        request.batch.path,
        request.readiness,
        request.readiness.sha256,
        request.readiness._raw,
        canonical_json_bytes(_plain(request.readiness.payload)),
        request.readiness.path,
        request.execution_context,
        request.execution_context.sha256,
        request.execution_context._raw,
        canonical_json_bytes(_plain(request.execution_context.payload)),
        request.execution_context.path,
        canonical_json_bytes(_plain(request.roots)),
        request.actor_id,
        request.actor_role,
        request.attempt_ordinal,
        canonical_json_bytes(_plain(request._payload)),
        request._path,
    )


def _absolute_strings(value: object) -> Iterator[Path]:
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _absolute_strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _absolute_strings(item)
    elif type(value) is str:
        path = Path(value)
        if path.is_absolute():
            yield path.resolve()


def _strict_descendant(path: Path, root: Path) -> bool:
    candidate = path.resolve()
    return candidate != root and root in candidate.parents


@dataclass(frozen=True, slots=True, init=False)
class _PreparedDisposableGateBV2FixtureRoute:
    request: GateBLoaderRequest
    executor: Any = field(repr=False, compare=False)
    authority: _GateBV2DisposableFixtureAuthority
    _request_provenance: tuple[object, ...] = field(repr=False, compare=False)
    _closed: bool = field(repr=False, compare=False)
    _consumed: bool = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> _PreparedDisposableGateBV2FixtureRoute:
        if _token is not _DISPOSABLE_ROUTE_TOKEN:
            raise TypeError("disposable v2 fixture-route construction is private")
        return object.__new__(cls)

    def verify_pre_write(self) -> None:
        route = _validate_disposable_gate_b_v2_fixture_route(self)
        if route._closed or route._consumed:
            _fail("disposable v2 fixture route is not available")
        root = route.authority.root
        for role in _ROOT_ROLES:
            reference = route.request.roots[role]
            observed = _root_identity_payload(reference["absolute_path"])
            if not _strict_descendant(Path(reference["absolute_path"]), root) or any(
                observed[name] != reference[name]
                for name in (
                    "absolute_path",
                    "volume_id_hex",
                    "file_id_hex",
                    "identity_scheme",
                )
            ):
                _fail("disposable v2 fixture root identity changed")
        for role in _ANCHOR_ROLES:
            reference = route.request.roots[role]
            names = tuple(sorted(path.name for path in Path(reference["absolute_path"]).iterdir()))
            if names != (reference["anchor_relative_path"],):
                _fail("disposable v2 writable root changed before reservation")

    def consume(self) -> tuple[GateBLoaderRequest, Any]:
        self.verify_pre_write()
        object.__setattr__(self, "_consumed", True)
        _DISPOSABLE_ROUTE_REGISTRY[id(self)] = _disposable_route_snapshot(self)
        return self.request, self.executor

    def close(self) -> None:
        _validate_disposable_gate_b_v2_fixture_route(self)
        object.__setattr__(self, "_closed", True)
        _DISPOSABLE_ROUTE_REGISTRY[id(self)] = _disposable_route_snapshot(self)


def _disposable_route_snapshot(
    route: _PreparedDisposableGateBV2FixtureRoute,
) -> tuple[object, ...]:
    return (
        route,
        route.request,
        route.executor,
        route.authority,
        route._request_provenance,
        route._closed,
        route._consumed,
        route._token,
    )


def _validate_disposable_gate_b_v2_fixture_route(
    route: _PreparedDisposableGateBV2FixtureRoute,
) -> _PreparedDisposableGateBV2FixtureRoute:
    if type(route) is not _PreparedDisposableGateBV2FixtureRoute:
        _fail("disposable v2 fixture-route nominal type mismatch")
    try:
        current = _disposable_route_snapshot(route)
        fresh_request = _legacy_request_snapshot(route.request)
        _validate_disposable_authority(route.authority)
    except GateBV2RouteError:
        raise
    except Exception:
        _fail("disposable v2 fixture-route provenance mismatch")
    if (
        _DISPOSABLE_ROUTE_REGISTRY.get(id(route)) is None
        or _DISPOSABLE_ROUTE_REGISTRY[id(route)][0] is not route
        or _DISPOSABLE_ROUTE_REGISTRY[id(route)][1] is not route.request
        or _DISPOSABLE_ROUTE_REGISTRY[id(route)][2] is not route.executor
        or _DISPOSABLE_ROUTE_REGISTRY[id(route)][3] is not route.authority
        or _DISPOSABLE_ROUTE_REGISTRY[id(route)] != current
        or fresh_request != route._request_provenance
        or route._token is not _DISPOSABLE_ROUTE_TOKEN
    ):
        _fail("disposable v2 fixture-route provenance mismatch")
    return route


def _prepare_disposable_gate_b_v2_fixture_route(
    authority: _GateBV2DisposableFixtureAuthority,
    request: GateBLoaderRequest,
    *,
    executor: Any,
) -> _PreparedDisposableGateBV2FixtureRoute:
    """Bind one request to a factory-created fresh tmp authority only."""
    validated_authority = _validate_disposable_authority(authority)
    if (
        type(request) is not GateBLoaderRequest
        or executor is None
        or id(validated_authority) in _DISPOSABLE_USED_AUTHORITIES
    ):
        _fail("disposable v2 fixture route input mismatch")
    root = validated_authority.root
    direct_paths = (
        request._path,
        request.batch.path,
        request.readiness.path,
        request.execution_context.path,
        *(Path(request.roots[role]["absolute_path"]) for role in _ROOT_ROLES),
    )
    projected_values = (
        request._payload,
        request.batch.payload,
        request.readiness.payload,
        request.execution_context.payload,
    )
    if any(not _strict_descendant(path, root) for path in direct_paths) or any(
        not _strict_descendant(path, root)
        for value in projected_values
        for path in _absolute_strings(_plain(value))
    ):
        _fail("disposable v2 fixture request escapes its authority")
    request_provenance = _legacy_request_snapshot(request)
    _DISPOSABLE_USED_AUTHORITIES.add(id(validated_authority))
    route = _PreparedDisposableGateBV2FixtureRoute(_token=_DISPOSABLE_ROUTE_TOKEN)
    values = {
        "request": request,
        "executor": executor,
        "authority": validated_authority,
        "_request_provenance": request_provenance,
        "_closed": False,
        "_consumed": False,
        "_token": _DISPOSABLE_ROUTE_TOKEN,
    }
    for name, value in values.items():
        object.__setattr__(route, name, value)
    _DISPOSABLE_ROUTE_REGISTRY[id(route)] = _disposable_route_snapshot(route)
    route.verify_pre_write()
    return route


def is_gate_b_v2_execution_route(value: object) -> bool:
    return type(value) in {
        PreparedGateBV2ExecutionRoute,
        _PreparedDisposableGateBV2FixtureRoute,
    }


def consume_gate_b_v2_execution_route(
    value: object,
) -> tuple[GateBLoaderRequest, Any]:
    if type(value) is PreparedGateBV2ExecutionRoute:
        return validate_prepared_gate_b_v2_execution_route(value).consume()
    if type(value) is _PreparedDisposableGateBV2FixtureRoute:
        return _validate_disposable_gate_b_v2_fixture_route(value).consume()
    _fail("v2 execution-route dispatcher type mismatch")


def close_gate_b_v2_execution_route(value: object) -> None:
    if type(value) is PreparedGateBV2ExecutionRoute:
        value.close()
        return
    if type(value) is _PreparedDisposableGateBV2FixtureRoute:
        _validate_disposable_gate_b_v2_fixture_route(value).close()
        return
    _fail("v2 execution-route dispatcher type mismatch")
