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
import tempfile
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from phase6.contracts import (
    ValidatedPhase6ContractBundleEvidence,
    canonical_json_bytes,
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
    _read_pinned,
    _verify_directory,
    _verify_regular,
    open_gate_b_v2_pinned_directory,
    verify_gate_b_v2_pinned_directory,
    verify_gate_b_v2_retained_root_topology,
)
from phase6.gate_b_loader import (
    GateBExecutionEvidence,
    GateBLoaderRequest,
    verify_gate_b_execution_environment,
)

HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION = "phase6-gate-b-human-approval-record-v4"
HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION = "phase6-gate-b-human-signature-record-v4"
READINESS_AUTHORIZATION_V4_SCHEMA_VERSION = "phase6-gate-b-readiness-authorization-v4"
LOADER_REQUEST_V3_SCHEMA_VERSION = "phase6-gate-b-test-loader-request-v3"
EXECUTION_CONTEXT_V2_SCHEMA_VERSION = "phase6-gate-b-execution-context-v2"
ONE_SHOT_SPEC_V2_SCHEMA_VERSION = "phase6-gate-b-one-shot-execution-spec-v2"

_ROOT_ROLES = ("ledger_base", "quarantine_base", "test_root")
_ANCHOR_ROLES = ("ledger_base", "quarantine_base")
_COMPATIBILITY_HASH_FIELD = "compatibility_preflight_request_sha256"
_BUNDLE_ROOT_HASH_FIELD = "phase6_contract_bundle_root_manifest_sha256"
_BUNDLE_PROVENANCE_HASH_FIELD = "phase6_contract_bundle_provenance_sha256"
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
_ANCHOR_NOT_PROVIDED = object()
_PLAN_REGISTRY: dict[int, tuple[object, ...]] = {}
_PREPARED_REGISTRY: dict[int, tuple[object, ...]] = {}
_ARTIFACT_REGISTRY: dict[int, tuple[object, ...]] = {}
_ROOT_REF_REGISTRY: dict[int, tuple[object, ...]] = {}
_DISPOSABLE_AUTHORITY_REGISTRY: dict[int, tuple[object, ...]] = {}
_DISPOSABLE_ROUTE_REGISTRY: dict[int, tuple[object, ...]] = {}
_DISPOSABLE_USED_AUTHORITIES: set[int] = set()


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
    *,
    reread: bool,
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
    if reread:
        try:
            before = _verify_regular(snapshot.reference_path, snapshot.logical_role)
            observed = _read_pinned(snapshot.reference_path, snapshot.logical_role)
            after = _verify_regular(snapshot.reference_path, snapshot.logical_role)
        except Exception:
            _fail("v2 stored-artifact pinned reread failed")
        identity = (before.st_dev, before.st_ino)
        if (
            identity != snapshot.physical_identity
            or (after.st_dev, after.st_ino) != identity
            or observed != snapshot.raw
        ):
            _fail("v2 stored-artifact bytes or identity changed")
    return snapshot


def _load_stored_artifact(
    raw: object,
    path: object,
    label: str,
) -> tuple[GateBV2StoredArtifactSnapshot, dict[str, Any]]:
    if type(raw) is not bytes or type(path) is not type(Path()):
        _fail(f"{label} stored input type mismatch")
    reference = _absolute_path(str(path), f"{label} reference")
    owned = bytes(raw)
    try:
        payload = _strict_canonical_object(owned, label)
        before = _verify_regular(reference, label)
        observed = _read_pinned(reference, label)
        after = _verify_regular(reference, label)
    except Exception:
        _fail(f"{label} stored-byte acquisition failed")
    identity = (before.st_dev, before.st_ino)
    if observed != owned or (after.st_dev, after.st_ino) != identity:
        _fail(f"{label} stored bytes do not match the supplied snapshot")
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
    return _validate_stored_artifact(snapshot, reread=False), payload


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
    operation_timeout_seconds: int
    process_timeout_seconds: int
    _artifacts: Mapping[str, GateBV2StoredArtifactSnapshot] = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __new__(cls, *, _token: object | None = None) -> GateBV2ExecutionPlan:
        if _token is not _PLAN_TOKEN:
            raise TypeError("v2 execution-plan construction is private")
        return object.__new__(cls)

    @property
    def projection(self):
        return self.compatibility_chain.projection


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
        plan.operation_timeout_seconds,
        plan.process_timeout_seconds,
        tuple((name, artifact) for name, artifact in plan._artifacts.items()),
        plan._token,
    )


def validate_gate_b_v2_execution_plan(plan: GateBV2ExecutionPlan) -> GateBV2ExecutionPlan:
    if type(plan) is not GateBV2ExecutionPlan:
        _fail("v2 execution-plan nominal type mismatch")
    try:
        validate_gate_b_v2_compatibility_trust_chain(plan.compatibility_chain)
        validate_phase6_contract_bundle_evidence(plan.phase6_contract_bundle_evidence)
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
    for snapshot in plan._artifacts.values():
        _validate_stored_artifact(snapshot, reread=True)
    return plan


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
) -> GateBV2ExecutionPlan:
    """Read and validate the complete execution DAG without opening or writing roots."""
    try:
        chain = validate_gate_b_v2_compatibility_trust_chain(compatibility_chain)
        validate_phase6_contract_bundle_evidence(phase6_contract_bundle_evidence)
        bundle_evidence = phase6_contract_bundle_evidence
        projection = chain.projection
        descriptor = dict(gate_b_root_identity_projection_descriptor_v2(projection))
        compatibility_request_hash = chain.artifact_hashes["loader_request"]

        artifacts: dict[str, GateBV2StoredArtifactSnapshot] = {}
        payloads: dict[str, dict[str, Any]] = {}
        for name, raw, path, label in (
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
        ):
            snapshot, payload = _load_stored_artifact(raw, path, label)
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
            },
            label="v2 execution context",
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
                _absolute_path(reference["absolute_path"], field_name) != artifact.reference_path
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
            "operation_timeout_seconds": 7200,
            "process_timeout_seconds": 7500,
            "_artifacts": MappingProxyType(dict(artifacts)),
            "_token": _PLAN_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(plan, name, value)
        _PLAN_REGISTRY[id(plan)] = _plan_snapshot(plan)
        return validate_gate_b_v2_execution_plan(plan)
    except GateBV2RouteError:
        raise
    except (GateBContractError, KeyError, TypeError, ValueError, OverflowError, OSError):
        _fail("Gate B v2 execution plan failed closed")


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
            evidence = verify_gate_b_execution_environment(
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
        return self.request, self.executor

    def close(self) -> None:
        registered = _PREPARED_REGISTRY.get(id(self))
        registered_directories = (
            dict(registered[4]) if registered is not None and registered[0] is self else {}
        )
        registered_closed = bool(
            registered is not None and registered[0] is self and registered[5] is True
        )
        validation_error: BaseException | None = None
        try:
            validate_prepared_gate_b_v2_execution_route(self)
        except BaseException as exc:
            validation_error = exc
        if registered_closed:
            if validation_error is not None:
                _fail("v2 retained-root close provenance failed closed")
            return
        first_error: BaseException | None = None
        for role in reversed(_ROOT_ROLES):
            try:
                registered_directories[role].close()
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
        raise
    except Exception:
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
        raise


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
