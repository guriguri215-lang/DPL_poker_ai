from __future__ import annotations

import copy
import inspect
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import phase6.gate_b_executor as executor_module
import phase6.gate_b_ledger as ledger_module
import phase6.gate_b_orchestrator as orchestrator
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    CALIBRATION_REFERENCE_V2_SCHEMA_VERSION,
    CLI_EXECUTION_RECEIPT_V2_SCHEMA_VERSION,
    EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
    HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
    HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
    LOADER_REQUEST_V3_SCHEMA_VERSION,
    ONE_SHOT_SPEC_V2_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
    ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
    V2_CLI_ERROR_SCHEMA_VERSION,
    V2_COMMON_PARENT_CHILDREN,
    V2_EXECUTION_BINDING_SCHEMA_VERSION,
    V2_OUTPUT_LIMITS,
    V2_ROUTE_MODULES,
    V2_SCIENCE_COMMIT,
    V2_SOURCE_CONTEXT,
    GateBBatchManifest,
    GateBContractError,
    GateBExecutionContext,
    GateBV2CompatibilityObject,
    GateBV2ExecutionBinding,
    GateBV2ExecutionContext,
    GateBV2ExecutionLoaderRequest,
    GateBV2ExecutionObject,
    GateBV2ExecutionTrustChain,
    _load_gate_b_v2_one_shot_spec_payload,
    _load_v2_loader_request,
    _v2_binding_payload,
    _v2_calibration_reference,
    _validate_v2_operational_artifact,
    load_gate_b_v2_execution_context_bytes,
)
from phase6.gate_b_ledger import (
    GateBV2AttemptReservation,
    GateBV2LedgerStore,
    GateBV2Quarantine,
)
from phase6.gate_b_loader import (
    GateBExecutorFailure,
    GateBLoaderError,
    GateBPartialEvidenceError,
)
from phase6.gate_b_orchestrator import (
    GateBPreflightError,
    GateBSpecError,
    GateBV2ExecutionReceipt,
    GateBV2PinnedSpecReference,
    PreparedGateBV2OneShotExecution,
    PreparedGateBV2TestOpen,
    _GateBV2OneShotExecutionSpec,
    _v2_join_request_to_spec,
    _v2_receipt_payload,
    _verify_gate_b_v2_science_join,
    build_gate_b_v2_pinned_spec_reference,
)
from phase6.gate_b_v2_cli import _validate_error_payload, main

_H = {
    name: f"{ordinal:064x}"
    for ordinal, name in enumerate(
        (
            "compatibility_approval_record",
            "compatibility_signature_record",
            "compatibility_readiness_authorization",
            "ledger_root_anchor",
            "quarantine_root_anchor",
            "compatibility_loader_request",
            "compatibility_readiness_materialization_spec",
            "compatibility_request_materialization_spec",
            "batch",
            "context",
            "calibration",
            "module",
            "dependency",
        ),
        start=1,
    )
}


def _root(path: Path, ordinal: int = 1) -> dict[str, object]:
    return {
        "absolute_path": str(path),
        "identity_scheme": "windows-volume-file-id-v1",
        "serialization_profile": ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
        "volume_id_hex": "00000001",
        "file_id_hex": f"{ordinal:016x}",
    }


def _pin(parent: Path, name: str, ordinal: int) -> dict[str, object]:
    return {
        "parent_absolute_path": str(parent),
        "parent_identity_scheme": "windows-volume-file-id-v1",
        "parent_serialization_profile": ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
        "parent_volume_id_hex": "00000001",
        "parent_file_id_hex": "0000000000000002",
        "direct_child_name": name,
        "expected_sha256": f"{ordinal:064x}",
        "expected_size_bytes": ordinal,
    }


def _binding(tmp_path: Path) -> dict[str, object]:
    control = tmp_path / "control"
    common = tmp_path / "common"
    calibration = {
        "schema_version": CALIBRATION_REFERENCE_V2_SCHEMA_VERSION,
        "artifact_type": "gate_b_calibration_bundle_reference",
        "root_manifest": _pin(control, "root.json", 20),
        "artifacts": [
            {
                "relative_path": "artifact.json",
                **_pin(control, "artifact.json", 21),
            }
        ],
    }
    return {
        "schema_version": V2_EXECUTION_BINDING_SCHEMA_VERSION,
        "projection_descriptor": {"schema_version": "descriptor-v2"},
        "compatibility_artifact_sha256s": {
            "approval_record": _H["compatibility_approval_record"],
            "signature_record": _H["compatibility_signature_record"],
            "readiness_authorization": _H["compatibility_readiness_authorization"],
            "ledger_root_anchor": _H["ledger_root_anchor"],
            "quarantine_root_anchor": _H["quarantine_root_anchor"],
            "loader_request": _H["compatibility_loader_request"],
        },
        "compatibility_materialization_spec_sha256s": {
            "readiness_materialization_spec": _H["compatibility_readiness_materialization_spec"],
            "request_materialization_spec": _H["compatibility_request_materialization_spec"],
        },
        "root_anchor_sha256s": {
            "ledger_base": _H["ledger_root_anchor"],
            "quarantine_base": _H["quarantine_root_anchor"],
        },
        "source_execution_context": dict(V2_SOURCE_CONTEXT),
        "test_batch_sha256": _H["batch"],
        "science_commit": V2_SCIENCE_COMMIT,
        "execution_route_commit": "e5e71ceb6570539d841b021ee1e4f4b91bc9f988",
        "execution_context_v2_sha256": _H["context"],
        "calibration_bundle_reference": calibration,
        "common_parent_topology": {
            **_root(common, 10),
            "expected_direct_children": list(V2_COMMON_PARENT_CHILDREN),
        },
        "expected_attempt_ordinal": 1,
        "expected_latest_record_sha256": None,
        "operation_timeout_seconds": 7200,
        "process_timeout_seconds": 7500,
        "output_limits": dict(V2_OUTPUT_LIMITS),
    }


def _context(tmp_path: Path, binding: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
        "artifact_type": "gate_b_execution_context",
        "created_at_utc": "2026-08-02T00:00:00Z",
        "projection_descriptor": binding["projection_descriptor"],
        "source_execution_context": dict(V2_SOURCE_CONTEXT),
        "test_batch_sha256": binding["test_batch_sha256"],
        "science_commit": V2_SCIENCE_COMMIT,
        "execution_route_commit": binding["execution_route_commit"],
        "repository_root": _root(tmp_path / "repo", 11),
        "active_route_modules": [
            {
                "module_name": name,
                "repository_relative_path": path,
                "sha256": _H["module"],
            }
            for name, path in V2_ROUTE_MODULES
        ],
        "runtime_fingerprint": {
            "python_implementation": "CPython",
            "python_version": "3.12.13",
            "python_compiler": "MSC",
            "platform": "win32",
            "system": "Windows",
            "release": "11",
            "version": "fixture",
            "machine": "AMD64",
        },
        "dependency_lock": {
            "absolute_path": str(tmp_path / "repo" / "requirements.lock"),
            "sha256": _H["dependency"],
            "size_bytes": 1,
        },
    }


def _spec(tmp_path: Path, binding: dict[str, object]) -> dict[str, object]:
    common = tmp_path / "common"
    parent = tmp_path / "control"
    names = (
        "batch_manifest",
        "source_execution_context",
        "execution_context",
        "compatibility_approval_record",
        "compatibility_signature_record",
        "compatibility_readiness_authorization",
        "ledger_root_anchor",
        "quarantine_root_anchor",
        "compatibility_loader_request",
        "compatibility_readiness_materialization_spec",
        "compatibility_request_materialization_spec",
        "execution_approval_record",
        "execution_signature_record",
        "execution_readiness_authorization",
        "execution_loader_request",
        "calibration_bundle",
    )
    roots = {
        "test_root": _root(common / "gate_b_test_v2_input", 3),
        "ledger_base": _root(common / "gate_b_test_v2_ledger", 4),
        "quarantine_base": _root(common / "gate_b_test_v2_quarantine", 5),
    }
    return {
        "schema_version": ONE_SHOT_SPEC_V2_SCHEMA_VERSION,
        "artifact_type": "gate_b_one_shot_execution_spec",
        "execution_binding": binding,
        "pinned_inputs": {
            name: _pin(parent, f"{ordinal:02d}-{name}.json", ordinal)
            for ordinal, name in enumerate(names, start=1)
        },
        "roots": roots,
        "common_parent": _root(common, 10),
        "expected_latest_record_sha256": None,
        "operation_timeout_seconds": 7200,
        "process_timeout_seconds": 7500,
        "output_limits": dict(V2_OUTPUT_LIMITS),
    }


def _reference_from_pin(pin: dict[str, object]) -> dict[str, object]:
    return {
        "absolute_path": str(
            Path(str(pin["parent_absolute_path"])) / str(pin["direct_child_name"])
        ),
        "sha256": pin["expected_sha256"],
    }


def _complete_schema_payloads(root: Path) -> dict[str, dict[str, object]]:
    binding = _binding(root)
    context = _context(root, binding)
    context_raw = canonical_json_bytes(context)
    binding["execution_context_v2_sha256"] = sha256_bytes(context_raw)
    calibration = copy.deepcopy(binding["calibration_bundle_reference"])
    calibration_raw = canonical_json_bytes(calibration)
    approval = {
        "schema_version": HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_approval_record",
        "approval_record_id": "approval-record-1",
        "approved_at_utc": "2026-08-02T00:00:01Z",
        "approver_actor_id": "human-approver-1",
        "approver_role": "human_gate_b_v2_execution_approver",
        "approval_decision": "APPROVE_INITIAL_GATE_B_V2_EXECUTION",
        "approval_scope": "initial_attempt_only",
        "execution_binding": copy.deepcopy(binding),
        "authorized_runner_actor_id": "runner-1",
        "authorized_runner_role": "test_runner",
        "authorized_ledger_manager_actor_id": "ledger-manager-1",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "release-approver-1",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "retry-approver-1",
        "designated_retry_approver_role": "retry_approver",
        "release_authorized": False,
        "retry_authorized": False,
    }
    approval_raw = canonical_json_bytes(approval)
    approval_hash = sha256_bytes(approval_raw)
    signature = {
        "schema_version": HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_signature_record",
        "signature_record_id": "signature-record-1",
        "signed_at_utc": "2026-08-02T00:00:02Z",
        "signer_actor_id": "human-attestor-1",
        "signer_role": "human_gate_b_v2_execution_attestor",
        "signature_method": "human-governance-attestation-v1",
        "attestation": "ATTEST_EXACT_GATE_B_V2_EXECUTION_APPROVAL",
        "approval_record_id": approval["approval_record_id"],
        "approval_record_sha256": approval_hash,
        "execution_binding": copy.deepcopy(binding),
    }
    signature_raw = canonical_json_bytes(signature)
    signature_hash = sha256_bytes(signature_raw)
    readiness = {
        "schema_version": READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
        "artifact_type": "gate_b_readiness_authorization",
        "authorization_id": "readiness-authorization-1",
        "authorized_at_utc": "2026-08-02T00:00:03Z",
        "approval_record_id": approval["approval_record_id"],
        "approval_record_sha256": approval_hash,
        "signature_record_sha256": signature_hash,
        "gate_b_ready": True,
        "execution_binding": copy.deepcopy(binding),
        "authorized_runner_actor_id": approval["authorized_runner_actor_id"],
        "authorized_runner_role": approval["authorized_runner_role"],
        "authorized_ledger_manager_actor_id": approval[
            "authorized_ledger_manager_actor_id"
        ],
        "authorized_ledger_manager_role": approval[
            "authorized_ledger_manager_role"
        ],
        "designated_release_approver_id": approval[
            "designated_release_approver_id"
        ],
        "designated_release_approver_role": approval[
            "designated_release_approver_role"
        ],
        "designated_retry_approver_id": approval["designated_retry_approver_id"],
        "designated_retry_approver_role": approval[
            "designated_retry_approver_role"
        ],
        "ledger_namespace_derivation": "ledger_base/<test_batch_hash>",
        "quarantine_namespace_derivation": (
            "quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>"
        ),
    }
    readiness_raw = canonical_json_bytes(readiness)
    readiness_hash = sha256_bytes(readiness_raw)
    spec = _spec(root, binding)
    pins = spec["pinned_inputs"]
    compatibility_pin_hashes = {
        "compatibility_approval_record": binding["compatibility_artifact_sha256s"][
            "approval_record"
        ],
        "compatibility_signature_record": binding["compatibility_artifact_sha256s"][
            "signature_record"
        ],
        "compatibility_readiness_authorization": binding[
            "compatibility_artifact_sha256s"
        ]["readiness_authorization"],
        "ledger_root_anchor": binding["compatibility_artifact_sha256s"][
            "ledger_root_anchor"
        ],
        "quarantine_root_anchor": binding["compatibility_artifact_sha256s"][
            "quarantine_root_anchor"
        ],
        "compatibility_loader_request": binding["compatibility_artifact_sha256s"][
            "loader_request"
        ],
        "compatibility_readiness_materialization_spec": binding[
            "compatibility_materialization_spec_sha256s"
        ]["readiness_materialization_spec"],
        "compatibility_request_materialization_spec": binding[
            "compatibility_materialization_spec_sha256s"
        ]["request_materialization_spec"],
    }
    for name, digest in compatibility_pin_hashes.items():
        pins[name]["expected_sha256"] = digest
    pin_identities = {
        "batch_manifest": (binding["test_batch_sha256"], 1),
        "source_execution_context": (
            binding["source_execution_context"]["sha256"],
            binding["source_execution_context"]["size_bytes"],
        ),
        "execution_context": (sha256_bytes(context_raw), len(context_raw)),
        "execution_approval_record": (approval_hash, len(approval_raw)),
        "execution_signature_record": (signature_hash, len(signature_raw)),
        "execution_readiness_authorization": (readiness_hash, len(readiness_raw)),
        "calibration_bundle": (sha256_bytes(calibration_raw), len(calibration_raw)),
    }
    for name, (digest, size) in pin_identities.items():
        pins[name]["expected_sha256"] = digest
        pins[name]["expected_size_bytes"] = size
    request_roots = {}
    for role, root_ref in spec["roots"].items():
        request_roots[role] = {
            "root_role": role,
            **copy.deepcopy(root_ref),
            "anchor_relative_path": (
                None if role == "test_root" else ".gate-b-root-anchor.json"
            ),
            "anchor_sha256": (
                None if role == "test_root" else binding["root_anchor_sha256s"][role]
            ),
        }
    loader_request = {
        "schema_version": LOADER_REQUEST_V3_SCHEMA_VERSION,
        "artifact_type": "gate_b_test_loader_request",
        "requested_at_utc": "2026-08-02T00:00:04Z",
        "operation": "execute_once_v2",
        "execution_binding": copy.deepcopy(binding),
        "batch_manifest": _reference_from_pin(pins["batch_manifest"]),
        "source_execution_context": _reference_from_pin(
            pins["source_execution_context"]
        ),
        "execution_context": _reference_from_pin(pins["execution_context"]),
        "compatibility_artifacts": {
            "approval_record": _reference_from_pin(
                pins["compatibility_approval_record"]
            ),
            "signature_record": _reference_from_pin(
                pins["compatibility_signature_record"]
            ),
            "readiness_authorization": _reference_from_pin(
                pins["compatibility_readiness_authorization"]
            ),
            "ledger_root_anchor": _reference_from_pin(pins["ledger_root_anchor"]),
            "quarantine_root_anchor": _reference_from_pin(
                pins["quarantine_root_anchor"]
            ),
            "loader_request": _reference_from_pin(
                pins["compatibility_loader_request"]
            ),
        },
        "compatibility_materialization_specs": {
            "readiness_materialization_spec": _reference_from_pin(
                pins["compatibility_readiness_materialization_spec"]
            ),
            "request_materialization_spec": _reference_from_pin(
                pins["compatibility_request_materialization_spec"]
            ),
        },
        "execution_approval_record": _reference_from_pin(
            pins["execution_approval_record"]
        ),
        "execution_signature_record": _reference_from_pin(
            pins["execution_signature_record"]
        ),
        "execution_readiness_authorization": _reference_from_pin(
            pins["execution_readiness_authorization"]
        ),
        "roots": request_roots,
        "common_parent_topology": copy.deepcopy(binding["common_parent_topology"]),
        "actor": {
            "actor_id": readiness["authorized_runner_actor_id"],
            "actor_role": "test_runner",
        },
        "attempt_ordinal": 1,
    }
    loader_request_raw = canonical_json_bytes(loader_request)
    pins["execution_loader_request"]["expected_sha256"] = sha256_bytes(
        loader_request_raw
    )
    pins["execution_loader_request"]["expected_size_bytes"] = len(loader_request_raw)
    receipt = {
        "schema_version": CLI_EXECUTION_RECEIPT_V2_SCHEMA_VERSION,
        "operation": "execute-once-v2",
        "status": "sealed",
        "attempt_ordinal": 1,
        "state": "SEALED",
        "projection_sha256": "1" * 64,
        "execution_binding_sha256": sha256_bytes(canonical_json_bytes(binding)),
        "loader_request_sha256": sha256_bytes(loader_request_raw),
        "execution_context_sha256": sha256_bytes(context_raw),
        "sealed_record_sha256": "2" * 64,
        "quarantine_manifest_sha256": "3" * 64,
    }
    error = {
        "schema_version": V2_CLI_ERROR_SCHEMA_VERSION,
        "operation": "execute-once-v2",
        "status": "failed",
        "error_code": "gate_b_loader_error",
    }
    return {
        V2_EXECUTION_BINDING_SCHEMA_VERSION: binding,
        EXECUTION_CONTEXT_V2_SCHEMA_VERSION: context,
        CALIBRATION_REFERENCE_V2_SCHEMA_VERSION: calibration,
        HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION: approval,
        HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION: signature,
        READINESS_AUTHORIZATION_V4_SCHEMA_VERSION: readiness,
        LOADER_REQUEST_V3_SCHEMA_VERSION: loader_request,
        ONE_SHOT_SPEC_V2_SCHEMA_VERSION: spec,
        CLI_EXECUTION_RECEIPT_V2_SCHEMA_VERSION: receipt,
        V2_CLI_ERROR_SCHEMA_VERSION: error,
    }


_GOLDEN_ROOT = Path(r"C:\gate-b-v2-fixture")
FULL_SCHEMA_GOLDENS = (
    (
        V2_EXECUTION_BINDING_SCHEMA_VERSION,
        3312,
        "a29fe7ce1b43711681220d232c7b74483e912bef3fc70b1828b0a4051da12b05",
    ),
    (
        EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
        2442,
        "dea8c0a4bf356a662d3541b7aa06c9ce3c07ae1676d2cf0f7e81e3914a784251",
    ),
    (
        CALIBRATION_REFERENCE_V2_SCHEMA_VERSION,
        977,
        "76f3d7c253f2f79082847636dec6e38fa17a0b7d2757a03b34251c619c055db4",
    ),
    (
        HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
        4156,
        "b4d31f42969343cab68b9b04ac5cd7098b480ab1d53dc15fa31a332ffac4cc68",
    ),
    (
        HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
        3855,
        "46776711fbd57a4ca727556e68b2772dbaf87c34ee2de9dfa715f5bbbf86f076",
    ),
    (
        READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
        4326,
        "6add9fa2e2daa624df9632d9ffd2aa6db197be2117e9dff25be7ef41ae0f23cb",
    ),
    (
        LOADER_REQUEST_V3_SCHEMA_VERSION,
        7901,
        "6e36ccc363735e8ea51dd80b657051493284ab11e9a91744f14ade8a7f988059",
    ),
    (
        ONE_SHOT_SPEC_V2_SCHEMA_VERSION,
        11940,
        "881cb0f1f21b86248ed8810730976c4b5445f4a7fd1a1442c24c6b96b84a6d76",
    ),
    (
        CLI_EXECUTION_RECEIPT_V2_SCHEMA_VERSION,
        697,
        "a450d3f9a2da77fdf64d4347762a559068b8566a95af0983edc55bb4f4a14a80",
    ),
    (
        V2_CLI_ERROR_SCHEMA_VERSION,
        134,
        "d3680ed1a0cf035fce1f7766a2d0e0bd0f2dae63a8f68348e182f4ae80671f48",
    ),
)


def _schema_hashes(payloads: dict[str, dict[str, object]]) -> dict[str, str]:
    return {
        "approval_record": sha256_bytes(
            canonical_json_bytes(payloads[HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION])
        ),
        "signature_record": sha256_bytes(
            canonical_json_bytes(payloads[HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION])
        ),
        "readiness_authorization": sha256_bytes(
            canonical_json_bytes(payloads[READINESS_AUTHORIZATION_V4_SCHEMA_VERSION])
        ),
    }


def _validate_complete_schema(
    schema: str,
    payload: dict[str, object],
    payloads: dict[str, dict[str, object]],
) -> None:
    raw = canonical_json_bytes(payload)
    binding = payloads[V2_EXECUTION_BINDING_SCHEMA_VERSION]
    hashes = _schema_hashes(payloads)
    if schema == V2_EXECUTION_BINDING_SCHEMA_VERSION:
        _v2_binding_payload(payload)
    elif schema == EXECUTION_CONTEXT_V2_SCHEMA_VERSION:
        load_gate_b_v2_execution_context_bytes(
            raw,
            expected_sha256=sha256_bytes(raw),
            reference_path=_GOLDEN_ROOT / "context.json",
        )
    elif schema == CALIBRATION_REFERENCE_V2_SCHEMA_VERSION:
        _v2_calibration_reference(payload)
    elif schema == HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION:
        _validate_v2_operational_artifact(payload, "approval_record", binding, hashes)
    elif schema == HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION:
        _validate_v2_operational_artifact(payload, "signature_record", binding, hashes)
    elif schema == READINESS_AUTHORIZATION_V4_SCHEMA_VERSION:
        _validate_v2_operational_artifact(
            payload, "readiness_authorization", binding, hashes
        )
    elif schema == LOADER_REQUEST_V3_SCHEMA_VERSION:
        _load_v2_loader_request(raw, sha256_bytes(raw), binding, hashes)
    elif schema == ONE_SHOT_SPEC_V2_SCHEMA_VERSION:
        _load_gate_b_v2_one_shot_spec_payload(raw, sha256_bytes(raw))
    elif schema == CLI_EXECUTION_RECEIPT_V2_SCHEMA_VERSION:
        _v2_receipt_payload(payload)
    elif schema == V2_CLI_ERROR_SCHEMA_VERSION:
        _validate_error_payload(payload)
    else:  # pragma: no cover - the closed test table is exhaustive
        raise AssertionError(schema)


def _invalid_top_level_value(value: object) -> object:
    if value is None:
        return "not-null"
    if type(value) is bool:
        return not value
    if type(value) is int:
        return -1
    if type(value) is str:
        return ""
    if type(value) is dict:
        return []
    if type(value) is list:
        return {}
    raise AssertionError(type(value))


@pytest.mark.parametrize(
    ("schema", "expected_size", "expected_sha256"), FULL_SCHEMA_GOLDENS
)
def test_each_v2_schema_has_fixed_complete_canonical_bytes_and_sha256_golden(
    schema: str, expected_size: int, expected_sha256: str
) -> None:
    payloads = _complete_schema_payloads(_GOLDEN_ROOT)
    payload = payloads[schema]
    expected = canonical_json_bytes(payload)
    assert expected.endswith(b"\n")
    assert len(expected) == expected_size
    assert sha256_bytes(expected) == expected_sha256
    assert expected == canonical_json_bytes(copy.deepcopy(payload))
    assert len(payload) > 1
    _validate_complete_schema(schema, payload, payloads)


@pytest.mark.parametrize("schema", [row[0] for row in FULL_SCHEMA_GOLDENS])
def test_each_complete_schema_rejects_missing_extra_and_every_top_level_mutation(
    schema: str,
) -> None:
    payloads = _complete_schema_payloads(_GOLDEN_ROOT)
    payload = payloads[schema]
    for field in tuple(payload):
        missing = copy.deepcopy(payload)
        del missing[field]
        with pytest.raises((GateBContractError, ValueError)):
            _validate_complete_schema(schema, missing, payloads)
        mutated = copy.deepcopy(payload)
        mutated[field] = _invalid_top_level_value(mutated[field])
        with pytest.raises((GateBContractError, ValueError)):
            _validate_complete_schema(schema, mutated, payloads)
    extra = copy.deepcopy(payload)
    extra["unexpected_field"] = None
    with pytest.raises((GateBContractError, ValueError)):
        _validate_complete_schema(schema, extra, payloads)


@pytest.mark.parametrize("schema", [row[0] for row in FULL_SCHEMA_GOLDENS])
def test_each_complete_schema_rejects_mixed_version_downgrade_and_fallback(
    schema: str,
) -> None:
    payloads = _complete_schema_payloads(_GOLDEN_ROOT)
    alternatives = (
        "phase6-gate-b-v1",
        next(row[0] for row in FULL_SCHEMA_GOLDENS if row[0] != schema),
    )
    for alternative in alternatives:
        changed = copy.deepcopy(payloads[schema])
        changed["schema_version"] = alternative
        with pytest.raises((GateBContractError, ValueError)):
            _validate_complete_schema(schema, changed, payloads)


def test_execution_family_is_exact_compatibility_subclass() -> None:
    assert GateBV2ExecutionObject.__bases__ == (GateBV2CompatibilityObject,)
    for cls in (
        GateBV2ExecutionBinding,
        GateBV2ExecutionContext,
        GateBV2ExecutionTrustChain,
        GateBV2ExecutionLoaderRequest,
        GateBV2PinnedSpecReference,
        _GateBV2OneShotExecutionSpec,
        PreparedGateBV2OneShotExecution,
        GateBV2AttemptReservation,
        PreparedGateBV2TestOpen,
        GateBV2ExecutionReceipt,
        GateBV2LedgerStore,
        GateBV2Quarantine,
    ):
        assert issubclass(cls, GateBV2ExecutionObject)


def test_exact_five_public_route_signatures() -> None:
    import phase6.gate_b_contracts as contracts

    signatures = {
        contracts.load_gate_b_v2_execution_context_bytes: (
            "(raw: 'bytes', *, expected_sha256: 'str', reference_path: 'Path') "
            "-> 'GateBV2ExecutionContext'"
        ),
        orchestrator.build_gate_b_v2_pinned_spec_reference: (
            "(*, parent_absolute_path: 'Path', parent_identity_scheme: 'str', "
            "parent_serialization_profile: 'str', parent_volume_id_hex: 'str', "
            "parent_file_id_hex: 'str', direct_child_name: 'str', "
            "expected_sha256: 'str', expected_size_bytes: 'int') "
            "-> 'GateBV2PinnedSpecReference'"
        ),
        contracts.build_gate_b_v2_execution_trust_chain: (
            "(compatibility_chain: 'GateBV2CompatibilityTrustChain', *, "
            "readiness_materialization_spec_raw: 'bytes', "
            "request_materialization_spec_raw: 'bytes', execution_context_raw: 'bytes', "
            "expected_execution_context_sha256: 'str', "
            "execution_context_reference_path: 'Path', approval_record_raw: 'bytes', "
            "signature_record_raw: 'bytes', readiness_authorization_raw: 'bytes', "
            "loader_request_raw: 'bytes', calibration_bundle_reference_raw: 'bytes', "
            "expected_calibration_bundle_reference_sha256: 'str', "
            "calibration_bundle_reference_path: 'Path') -> 'GateBV2ExecutionTrustChain'"
        ),
        orchestrator.prepare_gate_b_v2_one_shot: (
            "(spec_reference: 'GateBV2PinnedSpecReference') "
            "-> 'PreparedGateBV2OneShotExecution'"
        ),
        orchestrator.execute_gate_b_v2_once: (
            "(spec_reference: 'GateBV2PinnedSpecReference') -> 'GateBV2ExecutionReceipt'"
        ),
    }
    assert {function: str(inspect.signature(function)) for function in signatures} == signatures
    assert str(inspect.signature(orchestrator.execute_gate_b_once)) == (
        "(spec_reference: 'GateBPinnedSpecReference') -> 'Mapping[str, Any]'"
    )
    assert (
        inspect.signature(orchestrator._reserve_gate_b_v2_attempt).parameters["transition"].kind
        is inspect.Parameter.POSITIONAL_OR_KEYWORD
    )


def test_v1_executor_slots_and_factory_signatures_remain_exact() -> None:
    assert executor_module.GateBProductionExecutor.__slots__ == (
        "_batch_hash",
        "_executor_id",
        "_executor_sha256",
        "_execution_context_sha256",
        "_locked",
        "_manifest",
        "_operation_timeout_seconds",
        "_phase6_contract_bundle_evidence",
    )
    assert str(inspect.signature(executor_module.GateBProductionExecutor.__init__)) == (
        "(self, token: 'object', *, executor_id: 'str', executor_sha256: 'str', "
        "batch_hash: 'str', execution_context_sha256: 'str', "
        "manifest: 'Mapping[str, Any]', operation_timeout_seconds: 'int', "
        "phase6_contract_bundle_evidence: 'ValidatedPhase6ContractBundleEvidence') -> 'None'"
    )
    assert str(inspect.signature(executor_module.GateBProductionExecutor.from_request)) == (
        "(request: 'GateBLoaderRequest', *, "
        "phase6_contract_bundle_evidence: 'ValidatedPhase6ContractBundleEvidence', "
        "execution_context_sha256: 'str', operation_timeout_seconds: 'int' = 7200) "
        "-> 'GateBProductionExecutor'"
    )


def test_binding_is_closed_and_every_field_is_required(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    assert _v2_binding_payload(copy.deepcopy(binding)) == binding
    for field in tuple(binding):
        changed = copy.deepcopy(binding)
        del changed[field]
        with pytest.raises(GateBContractError):
            _v2_binding_payload(changed)
    changed = copy.deepcopy(binding)
    changed["extra"] = None
    with pytest.raises(GateBContractError):
        _v2_binding_payload(changed)


def test_every_binding_hash_rejects_noncanonical_substitution(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    maps = (
        "compatibility_artifact_sha256s",
        "compatibility_materialization_spec_sha256s",
        "root_anchor_sha256s",
    )
    for map_name in maps:
        for key in binding[map_name]:
            changed = copy.deepcopy(binding)
            changed[map_name][key] = "A" * 64
            with pytest.raises(GateBContractError):
                _v2_binding_payload(changed)
    changed = copy.deepcopy(binding)
    changed["root_anchor_sha256s"]["ledger_base"] = _H["quarantine_root_anchor"]
    with pytest.raises(GateBContractError):
        _v2_binding_payload(changed)


def _join_fixture() -> tuple[dict[str, object], SimpleNamespace]:
    payloads = _complete_schema_payloads(_GOLDEN_ROOT)
    spec = copy.deepcopy(payloads[ONE_SHOT_SPEC_V2_SCHEMA_VERSION])
    request = copy.deepcopy(payloads[LOADER_REQUEST_V3_SCHEMA_VERSION])
    binding = copy.deepcopy(payloads[V2_EXECUTION_BINDING_SCHEMA_VERSION])
    hashes = _schema_hashes(payloads)
    calibration_hash = sha256_bytes(
        canonical_json_bytes(payloads[CALIBRATION_REFERENCE_V2_SCHEMA_VERSION])
    )
    loader_hash = sha256_bytes(canonical_json_bytes(request))
    trust = SimpleNamespace(
        loader_request=SimpleNamespace(payload=request, sha256=loader_hash),
        binding=SimpleNamespace(payload=binding),
        artifact_hashes={
            **hashes,
            "calibration_bundle_reference": calibration_hash,
        },
    )
    return spec, trust


def test_every_one_shot_pin_hash_cross_substitution_is_rejected() -> None:
    spec, trust = _join_fixture()
    _v2_join_request_to_spec(spec, trust)
    for name in tuple(spec["pinned_inputs"]):
        changed = copy.deepcopy(spec)
        changed["pinned_inputs"][name]["expected_sha256"] = "f" * 64
        with pytest.raises(ValueError):
            _v2_join_request_to_spec(changed, trust)


def test_every_loader_reference_hash_and_each_root_join_rejects_substitution() -> None:
    spec, trust = _join_fixture()
    references = [
        ("batch_manifest",),
        ("source_execution_context",),
        ("execution_context",),
        *(
            ("compatibility_artifacts", name)
            for name in trust.loader_request.payload["compatibility_artifacts"]
        ),
        *(
            ("compatibility_materialization_specs", name)
            for name in trust.loader_request.payload["compatibility_materialization_specs"]
        ),
        ("execution_approval_record",),
        ("execution_signature_record",),
        ("execution_readiness_authorization",),
    ]
    for keys in references:
        changed_request = copy.deepcopy(trust.loader_request.payload)
        target = changed_request
        for key in keys:
            target = target[key]
        target["sha256"] = "f" * 64
        changed_trust = SimpleNamespace(
            loader_request=SimpleNamespace(
                payload=changed_request,
                sha256=trust.loader_request.sha256,
            ),
            binding=trust.binding,
            artifact_hashes=trust.artifact_hashes,
        )
        with pytest.raises(ValueError):
            _v2_join_request_to_spec(spec, changed_trust)
    for role in tuple(spec["roots"]):
        for field in tuple(spec["roots"][role]):
            changed = copy.deepcopy(spec)
            changed["roots"][role][field] = "substituted"
            with pytest.raises(ValueError):
                _v2_join_request_to_spec(changed, trust)


def test_context_stored_bytes_and_mixed_version_fail_closed(tmp_path: Path) -> None:
    payload = _context(tmp_path, _binding(tmp_path))
    raw = canonical_json_bytes(payload)
    loaded = load_gate_b_v2_execution_context_bytes(
        raw, expected_sha256=sha256_bytes(raw), reference_path=tmp_path / "context.json"
    )
    assert type(loaded) is GateBV2ExecutionContext
    for schema in ("phase6-gate-b-execution-context-v1", ONE_SHOT_SPEC_V2_SCHEMA_VERSION):
        changed = {**payload, "schema_version": schema}
        changed_raw = canonical_json_bytes(changed)
        with pytest.raises(GateBContractError):
            load_gate_b_v2_execution_context_bytes(
                changed_raw,
                expected_sha256=sha256_bytes(changed_raw),
                reference_path=tmp_path / "context.json",
            )
    with pytest.raises(GateBContractError):
        load_gate_b_v2_execution_context_bytes(
            raw + b"\n",
            expected_sha256=sha256_bytes(raw + b"\n"),
            reference_path=tmp_path / "context.json",
        )


def test_v2_science_join_rejects_commit_runtime_and_lock_substitution() -> None:
    binding = _binding(_GOLDEN_ROOT)
    route_context = _context(_GOLDEN_ROOT, binding)
    source_payload = {
        "expected_implementation_commit": V2_SCIENCE_COMMIT,
        "runtime_fingerprint": {
            "python_implementation": "CPython",
            "python_version": "3.12.13",
            "system": "Windows",
            "release": "11",
            "machine": "AMD64",
        },
        "dependency_lock": {"sha256": _H["dependency"], "size_bytes": 1},
    }
    batch_payload = {
        "git": {"commit_oid": V2_SCIENCE_COMMIT},
        "runtime": {
            "python_implementation": "CPython",
            "python_version": "3.12.13",
            "machine": "AMD64",
            "os_name": "Windows",
            "os_release": "11",
            "dependency_lock": {"sha256": _H["dependency"], "size_bytes": 1},
        },
    }

    def verify(
        *,
        changed_binding: dict[str, object] | None = None,
        changed_route: dict[str, object] | None = None,
        changed_source: dict[str, object] | None = None,
        changed_batch: dict[str, object] | None = None,
        batch_sha256: str | None = None,
        source_sha256: str | None = None,
        source_size_bytes: int | None = None,
    ) -> None:
        batch = GateBBatchManifest(
            batch_sha256 or _H["batch"],
            changed_batch or batch_payload,
            b"{}",
            Path("batch.json"),
        )
        source = GateBExecutionContext(
            source_sha256 or V2_SOURCE_CONTEXT["sha256"],
            changed_source or source_payload,
            b"x" * (source_size_bytes or V2_SOURCE_CONTEXT["size_bytes"]),
            Path("execution-context.json"),
        )
        _verify_gate_b_v2_science_join(
            batch,
            source,
            changed_binding or binding,
            changed_route or route_context,
        )

    verify()
    substitutions = []
    for target, keys, value in (
        (binding, ("science_commit",), "f" * 40),
        (binding, ("execution_route_commit",), "f" * 40),
        (route_context, ("science_commit",), "f" * 40),
        (batch_payload, ("git", "commit_oid"), "f" * 40),
        (source_payload, ("expected_implementation_commit",), "f" * 40),
        (batch_payload, ("runtime", "python_version"), "0.0.0"),
        (batch_payload, ("runtime", "dependency_lock", "sha256"), "f" * 64),
        (batch_payload, ("runtime", "dependency_lock", "size_bytes"), 2),
    ):
        changed = copy.deepcopy(target)
        cursor = changed
        for key in keys[:-1]:
            cursor = cursor[key]
        cursor[keys[-1]] = value
        substitutions.append((target, changed))
    for target, changed in substitutions:
        arguments = {}
        if target is binding:
            arguments["changed_binding"] = changed
        elif target is route_context:
            arguments["changed_route"] = changed
        elif target is source_payload:
            arguments["changed_source"] = changed
        else:
            arguments["changed_batch"] = changed
        with pytest.raises(ValueError):
            verify(**arguments)
    with pytest.raises(ValueError):
        verify(batch_sha256="f" * 64)
    with pytest.raises(ValueError):
        verify(source_sha256="f" * 64)
    with pytest.raises(ValueError):
        verify(source_size_bytes=V2_SOURCE_CONTEXT["size_bytes"] + 1)


def test_one_shot_closed_fields_and_no_downgrade(tmp_path: Path) -> None:
    payload = _spec(tmp_path, _binding(tmp_path))
    raw = canonical_json_bytes(payload)
    assert _load_gate_b_v2_one_shot_spec_payload(raw, sha256_bytes(raw)) == payload
    for field in tuple(payload):
        changed = copy.deepcopy(payload)
        del changed[field]
        changed_raw = canonical_json_bytes(changed)
        with pytest.raises(GateBContractError):
            _load_gate_b_v2_one_shot_spec_payload(changed_raw, sha256_bytes(changed_raw))
    for schema in ("phase6-gate-b-one-shot-execution-spec-v1", EXECUTION_CONTEXT_V2_SCHEMA_VERSION):
        changed = {**payload, "schema_version": schema}
        changed_raw = canonical_json_bytes(changed)
        with pytest.raises(GateBContractError):
            _load_gate_b_v2_one_shot_spec_payload(changed_raw, sha256_bytes(changed_raw))


def test_v2_cli_dispatch_is_closed_before_path_parsing(capfd: pytest.CaptureFixture[str]) -> None:
    assert main(("execute-once", "--spec-parent", r"\\server\share")) == 2
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == (
        '{"error_code":"gate_b_invalid_arguments","operation":"pre-dispatch",'
        '"schema_version":"phase6-gate-b-v2-cli-error-v1","status":"failed"}\n'
    )


def test_v2_cli_requires_each_exact_option_spelling_once_before_path_parsing(
    capfd: pytest.CaptureFixture[str],
) -> None:
    argv = (
        "execute-once-v2",
        "--spec-parent",
        r"C:\control",
        "--spec-parent-identity-scheme",
        "windows-volume-file-id-v1",
        "--spec-parent-serialization-profile",
        "windows-volume8-file16-lowerhex-v1",
        "--spec-parent-volume-id-hex",
        "00000001",
        "--spec-parent-file-id-hex",
        "0000000000000001",
        "--spec-name",
        "spec.json",
        "--expected-spec-sha256",
        "1" * 64,
        "--expected-spec-size-bytes",
        "1",
    )
    invalid_argvs = (
        (*argv, "--spec-name", "other.json"),
        (argv[0], f"--spec-parent={argv[2]}", *argv[3:]),
    )
    for invalid in invalid_argvs:
        assert main(invalid) == 2
        captured = capfd.readouterr()
        assert captured.out == ""
        assert captured.err == (
            '{"error_code":"gate_b_invalid_arguments","operation":"execute-once-v2",'
            '"schema_version":"phase6-gate-b-v2-cli-error-v1","status":"failed"}\n'
        )


def test_unc_and_named_stream_reject_before_any_retained_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestrator,
        "open_gate_b_v2_pinned_directory",
        lambda *_a, **_k: pytest.fail("I/O reached"),
    )
    for value in (Path(r"\\server\share\control"), Path(r"C:\control:stream")):
        with pytest.raises(GateBSpecError):
            build_gate_b_v2_pinned_spec_reference(
                parent_absolute_path=value,
                parent_identity_scheme="windows-volume-file-id-v1",
                parent_serialization_profile=ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
                parent_volume_id_hex="00000001",
                parent_file_id_hex="0000000000000001",
                direct_child_name="spec.json",
                expected_sha256="1" * 64,
                expected_size_bytes=1,
            )


def test_network_and_nonfixed_local_volumes_reject_before_retained_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opens = 0

    def forbidden_open(*_args, **_kwargs):
        nonlocal opens
        opens += 1
        pytest.fail("retained open reached")

    monkeypatch.setattr(orchestrator, "open_gate_b_v2_pinned_directory", forbidden_open)
    for drive_type in (2, 4, 5, 6):
        monkeypatch.setattr(
            orchestrator,
            "_v2_fixed_local_drive_type",
            lambda _root, value=drive_type: value,
        )
        with pytest.raises(GateBSpecError):
            build_gate_b_v2_pinned_spec_reference(
                parent_absolute_path=Path(r"C:\control"),
                parent_identity_scheme="windows-volume-file-id-v1",
                parent_serialization_profile=ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
                parent_volume_id_hex="00000001",
                parent_file_id_hex="0000000000000001",
                direct_child_name="spec.json",
                expected_sha256="1" * 64,
                expected_size_bytes=1,
            )
    assert opens == 0


def test_private_first_write_capability_rejects_ordinary_objects_without_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def forbidden(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        pytest.fail("durable write reached")

    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", forbidden)
    with pytest.raises(GateBPreflightError):
        orchestrator._reserve_gate_b_v2_attempt(object())
    assert calls == 0


def test_private_first_write_capability_is_single_use_and_replay_writes_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes = 0

    def append_once(*_args, **_kwargs):
        nonlocal writes
        writes += 1
        return "1" * 64

    prepared = SimpleNamespace(
        ledger_store=object(),
        trust_chain=SimpleNamespace(
            binding=SimpleNamespace(payload={"test_batch_sha256": "2" * 64})
        ),
    )
    transition = orchestrator._GateBV2WriteTransition(
        _token=orchestrator._V2_WRITE_TOKEN
    )
    transition.prepared = prepared
    transition._consumed = False
    transition._token = orchestrator._V2_WRITE_TOKEN
    orchestrator._V2_WRITE_REGISTRY[id(transition)] = (
        transition,
        prepared,
        orchestrator._V2_WRITE_TOKEN,
    )
    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append_once)
    monkeypatch.setattr(
        orchestrator,
        "_new_gate_b_v2_attempt_reservation",
        lambda **_kwargs: object(),
    )
    orchestrator._reserve_gate_b_v2_attempt(transition)
    assert writes == 1
    with pytest.raises(GateBPreflightError):
        orchestrator._reserve_gate_b_v2_attempt(transition)
    assert writes == 1


def test_retained_close_order_is_preflight_reverse_parents_common_bootstrap() -> None:
    closed: list[str] = []

    class Closer:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            closed.append(self.name)

    prepared = object.__new__(PreparedGateBV2OneShotExecution)
    quarantine = object.__new__(GateBV2Quarantine)
    ledger_store = object.__new__(GateBV2LedgerStore)
    object.__setattr__(quarantine, "_namespace", None)
    object.__setattr__(ledger_store, "_namespace", None)
    object.__setattr__(prepared, "quarantine", quarantine)
    object.__setattr__(prepared, "ledger_store", ledger_store)
    object.__setattr__(prepared, "compatibility_preflight", Closer("preflight"))
    object.__setattr__(
        prepared,
        "artifact_parents",
        (Closer("parent-a"), Closer("parent-b")),
    )
    object.__setattr__(prepared, "common_parent", Closer("common"))
    object.__setattr__(prepared, "bootstrap_parent", Closer("bootstrap"))
    object.__setattr__(prepared, "_closed", False)
    prepared.close()
    assert closed == ["preflight", "parent-b", "parent-a", "common", "bootstrap"]
    prepared.close()
    assert len(closed) == 5


def _synthetic_v2_open() -> PreparedGateBV2TestOpen:
    reservation = ledger_module._new_gate_b_v2_attempt_reservation(
        test_batch_sha256="1" * 64,
        reserved_record_sha256="2" * 64,
    )
    store = object.__new__(GateBV2LedgerStore)
    object.__setattr__(store, "_binding_sha256", "3" * 64)
    quarantine = object.__new__(GateBV2Quarantine)
    return orchestrator._prepare_gate_b_v2_test_open(
        reservation,
        ledger_store=store,
        quarantine=quarantine,
    )


def test_v2_postreserve_prepare_failure_performs_no_second_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes = 0

    def forbidden_write(*_args, **_kwargs):
        nonlocal writes
        writes += 1

    reservation = ledger_module._new_gate_b_v2_attempt_reservation(
        test_batch_sha256="1" * 64,
        reserved_record_sha256="2" * 64,
    )
    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", forbidden_write)
    with pytest.raises(GateBLoaderError):
        orchestrator._prepare_gate_b_v2_test_open(
            reservation,
            ledger_store=object(),
            quarantine=object(),
        )
    assert writes == 0


def test_v2_lifecycle_success_is_exact_started_manifest_sealed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def append(*_args, **kwargs):
        events.append(kwargs["to_state"])
        return {"STARTED": "4" * 64, "SEALED": "5" * 64}[kwargs["to_state"]]

    def manifest(*_args, **kwargs):
        events.append(f"manifest:{kwargs['status']}")
        return "6" * 64

    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append)
    monkeypatch.setattr(orchestrator, "_create_gate_b_v2_quarantine_manifest", manifest)
    monkeypatch.setattr(orchestrator, "_validate_gate_b_v2_executor", lambda *_a, **_k: object())
    opened = _synthetic_v2_open()
    assert orchestrator._open_gate_b_v2_test_input(opened, executor=object()) == (
        "4" * 64,
        "5" * 64,
        "6" * 64,
    )
    assert events == ["STARTED", "manifest:sealed", "SEALED"]
    assert opened._closed is True


def test_v2_lifecycle_executes_separate_callback_between_started_and_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class Source:
        def read(self, _maximum: int) -> bytes:
            events.append("input-eof")
            return b""

    class Executor:
        def execute(self, input_capability, output_capability):
            events.append("executor")
            assert input_capability.read_chunk(1) == b""
            output_capability.write_chunk("progress", b"progress\n")
            return None

    def append(*_args, **kwargs):
        events.append(kwargs["to_state"])
        return {"STARTED": "4" * 64, "SEALED": "5" * 64}[kwargs["to_state"]]

    def manifest(*_args, **kwargs):
        events.append(("manifest", kwargs["status"], kwargs["output_raws"]))
        return "6" * 64

    route = object.__new__(PreparedGateBV2OneShotExecution)
    object.__setattr__(route, "batch_manifest", object())
    object.__setattr__(
        route,
        "compatibility_preflight",
        SimpleNamespace(_directories={"test_root": object()}),
    )
    base = _synthetic_v2_open()
    opened = orchestrator._prepare_gate_b_v2_test_open(
        base.reservation,
        ledger_store=base.ledger_store,
        quarantine=base.quarantine,
        route=route,
    )
    sentinel = object()
    monkeypatch.setattr(orchestrator, "_validate_prepared_v2", lambda _route: None)
    monkeypatch.setattr(
        orchestrator,
        "_prepare_gate_b_v2_input_source",
        lambda *_args: sentinel,
    )
    monkeypatch.setattr(
        orchestrator,
        "_activate_gate_b_v2_input_source",
        lambda _prepared: Source(),
    )
    monkeypatch.setattr(orchestrator, "_close_gate_b_v2_input_source", lambda _prepared: None)
    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append)
    monkeypatch.setattr(orchestrator, "_create_gate_b_v2_quarantine_manifest", manifest)
    monkeypatch.setattr(
        orchestrator,
        "_validate_gate_b_v2_executor",
        lambda *_args, **_kwargs: Executor(),
    )
    orchestrator._open_gate_b_v2_test_input(opened, executor=object())
    assert events[:4] == [
        "STARTED",
        "executor",
        "input-eof",
        (
            "manifest",
            "sealed",
            {
                "stdout": b"",
                "stderr": b"",
                "progress": b"progress\n",
                "metrics": b"",
                "log": b"",
                "result": b"",
            },
        ),
    ]
    assert events[4] == "SEALED"


def test_v2_poststarted_executor_failure_preserves_bounded_output_and_failed_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class Source:
        def read(self, _maximum: int) -> bytes:
            return b""

    class Executor:
        def execute(self, input_capability, output_capability):
            assert input_capability.read_chunk(1) == b""
            output_capability.write_chunk("log", b"partial\n")
            raise GateBExecutorFailure("deterministic callback failure")

    def append(*_args, **kwargs):
        events.append(kwargs["to_state"])
        return {"STARTED": "4" * 64, "FAILED_CLOSED": "7" * 64}[
            kwargs["to_state"]
        ]

    def manifest(*_args, **kwargs):
        events.append((kwargs["status"], kwargs["output_raws"]["log"]))
        return "6" * 64

    route = object.__new__(PreparedGateBV2OneShotExecution)
    object.__setattr__(route, "batch_manifest", object())
    object.__setattr__(
        route,
        "compatibility_preflight",
        SimpleNamespace(_directories={"test_root": object()}),
    )
    base = _synthetic_v2_open()
    opened = orchestrator._prepare_gate_b_v2_test_open(
        base.reservation,
        ledger_store=base.ledger_store,
        quarantine=base.quarantine,
        route=route,
    )
    monkeypatch.setattr(orchestrator, "_validate_prepared_v2", lambda _route: None)
    monkeypatch.setattr(
        orchestrator,
        "_prepare_gate_b_v2_input_source",
        lambda *_args: object(),
    )
    monkeypatch.setattr(
        orchestrator,
        "_activate_gate_b_v2_input_source",
        lambda _prepared: Source(),
    )
    monkeypatch.setattr(orchestrator, "_close_gate_b_v2_input_source", lambda _prepared: None)
    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append)
    monkeypatch.setattr(orchestrator, "_create_gate_b_v2_quarantine_manifest", manifest)
    monkeypatch.setattr(
        orchestrator,
        "_validate_gate_b_v2_executor",
        lambda *_args, **_kwargs: Executor(),
    )
    with pytest.raises(GateBExecutorFailure):
        orchestrator._open_gate_b_v2_test_input(opened, executor=object())
    assert events == ["STARTED", ("failed_closed", b"partial\n"), "FAILED_CLOSED"]


def test_v2_lifecycle_started_failure_durably_closes_from_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def append(*_args, **kwargs):
        events.append(kwargs["to_state"])
        if kwargs["to_state"] == "STARTED":
            raise RuntimeError("known STARTED failure")
        return "7" * 64

    def manifest(*_args, **kwargs):
        events.append(f"manifest:{kwargs['status']}")
        return "6" * 64

    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append)
    monkeypatch.setattr(orchestrator, "_create_gate_b_v2_quarantine_manifest", manifest)
    monkeypatch.setattr(orchestrator, "_validate_gate_b_v2_executor", lambda *_a, **_k: object())
    with pytest.raises(GateBLoaderError):
        orchestrator._open_gate_b_v2_test_input(_synthetic_v2_open(), executor=object())
    assert events == ["STARTED", "manifest:failed_closed", "FAILED_CLOSED"]


def test_v2_lifecycle_unknown_postreserve_durability_is_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def append(*_args, **kwargs):
        events.append(kwargs["to_state"])
        raise RuntimeError("known STARTED failure")

    def manifest(*_args, **kwargs):
        events.append(f"manifest:{kwargs['status']}")
        raise RuntimeError("manifest outcome unknown")

    monkeypatch.setattr(orchestrator, "_append_gate_b_v2_state", append)
    monkeypatch.setattr(orchestrator, "_create_gate_b_v2_quarantine_manifest", manifest)
    monkeypatch.setattr(orchestrator, "_validate_gate_b_v2_executor", lambda *_a, **_k: object())
    with pytest.raises(GateBPartialEvidenceError):
        orchestrator._open_gate_b_v2_test_input(_synthetic_v2_open(), executor=object())
    assert events == ["STARTED", "manifest:failed_closed"]


def test_tmp_only_v2_lifecycle_is_reserved_started_sealed_in_derived_namespaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_root = tmp_path / "ledger"
    quarantine_root = tmp_path / "quarantine"
    ledger_root.mkdir()
    quarantine_root.mkdir()
    ledger_metadata = os.stat(ledger_root)
    quarantine_metadata = os.stat(quarantine_root)
    ledger_directory = ledger_module.GateBPinnedDirectory.open(
        ledger_root,
        expected_volume_id_hex=format(ledger_metadata.st_dev, "x"),
        expected_file_id_hex=format(ledger_metadata.st_ino, "x"),
    )
    quarantine_directory = ledger_module.GateBPinnedDirectory.open(
        quarantine_root,
        expected_volume_id_hex=format(quarantine_metadata.st_dev, "x"),
        expected_file_id_hex=format(quarantine_metadata.st_ino, "x"),
    )
    binding_sha = "1" * 64
    batch_sha = "2" * 64
    store = ledger_module._new_gate_b_v2_ledger_store(
        ledger_directory,
        binding_sha256=binding_sha,
        test_batch_sha256=batch_sha,
    )
    quarantine = ledger_module._new_gate_b_v2_quarantine(
        quarantine_directory,
        binding_sha256=binding_sha,
        test_batch_sha256=batch_sha,
    )
    monkeypatch.setattr(
        ledger_module.GateBPinnedDirectory,
        "open",
        lambda *_args, **_kwargs: pytest.fail("legacy absolute-path reopen reached"),
    )
    try:
        reserved = ledger_module._append_gate_b_v2_state(
            store,
            ordinal=1,
            from_state=None,
            to_state="RESERVED",
            previous_sha256=None,
            quarantine_manifest_sha256=None,
        )
        started = ledger_module._append_gate_b_v2_state(
            store,
            ordinal=2,
            from_state="RESERVED",
            to_state="STARTED",
            previous_sha256=reserved,
            quarantine_manifest_sha256=None,
        )
        manifest = ledger_module._create_gate_b_v2_quarantine_manifest(
            quarantine,
            status="sealed",
            started_record_sha256=started,
        )
        sealed = ledger_module._append_gate_b_v2_state(
            store,
            ordinal=3,
            from_state="STARTED",
            to_state="SEALED",
            previous_sha256=started,
            quarantine_manifest_sha256=manifest,
        )
        assert all(len(digest) == 64 for digest in (reserved, started, manifest, sealed))
        assert sorted(path.name for path in (ledger_root / batch_sha).iterdir()) == [
            "record-000001.json",
            "record-000002.json",
            "record-000003.json",
        ]
        assert sorted(
            path.name
            for path in (quarantine_root / batch_sha / "attempt-000001").iterdir()
        ) == [
            "log.jsonl",
            "metrics.json",
            "progress.jsonl",
            "quarantine-manifest.json",
            "result.json",
            "stderr.txt",
            "stdout.txt",
        ]
    finally:
        ledger_module._close_gate_b_v2_lifecycle_object(quarantine)
        ledger_module._close_gate_b_v2_lifecycle_object(store)
        quarantine_directory.close()
        ledger_directory.close()


def test_v2_private_call_graph_does_not_reuse_v1_consumers() -> None:
    source = inspect.getsource(orchestrator._execute_prepared_gate_b_v2_once)
    for forbidden in (
        "execute_gate_b_once",
        "reserve_gate_b_attempt",
        "prepare_gate_b_test_open",
        "open_gate_b_test_input",
        "GateBLoaderRequest",
    ):
        assert forbidden not in source
    assert source.index("_final_revalidate_gate_b_v2") < source.index(
        "_GateBV2WriteTransition"
    ) < source.index("_reserve_gate_b_v2_attempt")
    final_source = inspect.getsource(orchestrator._final_revalidate_gate_b_v2)
    for required in (
        "_verify_gate_b_v2_science_join",
        "_read_v2_pin",
        "load_phase6_contract_bundle_evidence_from_canonical_artifacts",
        "_validate_gate_b_v2_executor",
    ):
        assert required in final_source


def test_v2_artifacts_are_read_only_through_retained_parents() -> None:
    read_source = inspect.getsource(orchestrator._read_v2_pin)
    prepare_source = inspect.getsource(orchestrator.prepare_gate_b_v2_one_shot)
    assert "parent.read_regular(" in read_source
    for forbidden in (".read_bytes(", ".read_text(", "Path.open(", "builtins.open("):
        assert forbidden not in prepare_source


def test_loader_keeps_v2_lifecycle_ownership_outside_private_ledger_imports() -> None:
    source = inspect.getsource(__import__("phase6.gate_b_loader", fromlist=["*"]))
    for private in (
        "_append_gate_b_v2_state",
        "_create_gate_b_v2_quarantine_manifest",
        "_new_gate_b_v2_ledger_store",
        "_new_gate_b_v2_quarantine",
    ):
        assert private not in source
