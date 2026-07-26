from __future__ import annotations

import copy
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import phase6.gate_b_contracts as contracts_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACCESS_LOG_ENTRY_SCHEMA_VERSION,
    ACTIVE_MODULE_PATHS,
    ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION,
    BATCH_MANIFEST_SCHEMA_VERSION,
    COMPONENT_NAMES,
    EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
    EXECUTION_CONTEXT_SCHEMA_VERSION,
    HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
    HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
    QUARANTINE_MANIFEST_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_SCHEMA_VERSION,
    RELEASE_AUTHORIZATION_SCHEMA_VERSION,
    RETRY_AUTHORIZATION_SCHEMA_VERSION,
    ROOT_ANCHOR_SCHEMA_VERSION,
    GateBContractError,
    GateBHumanApprovalRecord,
    GateBHumanSignatureRecord,
    _canonical_reason_detail_sha256,
    _required_posix_nofollow,
    _windows_open_contract_descriptor,
    load_gate_b_batch_manifest,
    load_gate_b_execution_context,
    load_gate_b_human_approval_record_bytes,
    load_gate_b_human_signature_record_bytes,
    load_gate_b_readiness_authorization,
    load_gate_b_release_authorization,
    load_gate_b_retry_authorization,
    load_gate_b_root_anchor,
    validate_gate_b_readiness_human_trust_chain,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
COMMIT = "a" * 40
APPROVAL_HASH = "d" * 64
SIGNATURE_HASH = "e" * 64


def _fixture_path(tmp_path: Path, name: str) -> Path:
    base = tmp_path / "gate-b-fixture"
    for root_name in ("test-root", "ledger-root", "quarantine-root"):
        (base / root_name).mkdir(parents=True, exist_ok=True)
    contracts = base / "contract-artifacts"
    contracts.mkdir(exist_ok=True)
    return contracts / name


def _write(path: Path, payload: object) -> str:
    raw = canonical_json_bytes(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _component(name: str) -> dict[str, object]:
    schemas = {
        "execution_config_index": EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
        "opponent_payload_index": OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
        "selected_config_lock": "phase6-selected-config-lock-v1",
    }
    return {
        "name": name,
        "relative_path": f"components/{name}.json",
        "schema_version": schemas.get(name, f"fixture-{name}-v1"),
        "sha256": HASH_A,
        "size_bytes": 10,
    }


def batch_payload() -> dict[str, object]:
    return {
        "schema_version": BATCH_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "gate_b_test_batch_manifest",
        "created_at_utc": "2026-07-24T00:00:00Z",
        "canonicalization": {
            "allow_nan": False,
            "encoding": "utf-8",
            "ensure_ascii": True,
            "separators": [",", ":"],
            "sort_keys": True,
            "trailing_lf": True,
        },
        "git": {"branch": "main", "commit_oid": COMMIT},
        "runtime": {
            "dependency_lock": {
                "name": "dependency_lock",
                "schema_version": "phase6-production-dependency-lock-v1",
                "sha256": HASH_B,
                "size_bytes": 11,
            },
            "machine": "fixture-machine",
            "os_name": "fixture-os",
            "os_release": "fixture-release",
            "python_implementation": "CPython",
            "python_version": "3.12.0",
        },
        "components": {name: _component(name) for name in COMPONENT_NAMES},
        "selection": {
            "ablations": [],
            "comparators": [],
            "manual_override": False,
            "primary_config_id": "fixture-primary-001",
            "primary_config_sha256": HASH_C,
            "selection_report_sha256": HASH_A,
        },
        "test_input": {
            "execution_config_index_sha256": HASH_A,
            "format_id": "fixture-format-v1",
            "framing_version": "phase6-gate-b-input-framing-v1",
            "opponent_payload_index_sha256": HASH_A,
            "physical_split_id": "fixture-physical-split-v1",
            "split_id": "fixture-test-split-v1",
        },
        "coordinates": {
            "horizons": [50],
            "opponent_ids": ["fixture-opponent-001"],
            "repetition_ids": ["fixture-r001"],
            "seed_mapping": [
                {
                    "horizon": 50,
                    "opponent_id": "fixture-opponent-001",
                    "repetition_id": "fixture-r001",
                    "seed": 620001,
                }
            ],
        },
        "ledger_policy": {
            "cleanup": "never",
            "exclusive_create": True,
            "namespace_derivation": "ledger_base/<test_batch_hash>",
            "retain_partial": True,
            "states": [
                "RESERVED",
                "STARTED",
                "SEALED",
                "RELEASED",
                "FAILED_CLOSED",
                "RETRY_AUTHORIZED",
            ],
            "topology_policy_version": "phase6-gate-b-physical-topology-v1",
        },
        "quarantine_policy": {
            "exclusive_create": True,
            "namespace_derivation": ("quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>"),
            "outputs": [
                "stdout",
                "stderr",
                "progress",
                "metrics",
                "log",
                "result",
                "access_log",
            ],
            "read_before_release": False,
            "retain_partial": True,
            "stream_before_release": False,
        },
        "governance": {
            "failure_reason_map": [
                {
                    "failure_class": "execution_environment_failure",
                    "from_state": "RESERVED",
                    "reason_id": "fixture-environment",
                },
                {
                    "failure_class": "test_input_prestart_failure",
                    "from_state": "RESERVED",
                    "reason_id": "fixture-prestart",
                },
                {
                    "failure_class": "started_append_failure",
                    "from_state": "RESERVED",
                    "reason_id": "fixture-started-append",
                },
                {
                    "failure_class": "test_input_poststart_failure",
                    "from_state": "STARTED",
                    "reason_id": "fixture-poststart",
                },
                {
                    "failure_class": "executor_callback_failure",
                    "from_state": "STARTED",
                    "reason_id": "fixture-executor",
                },
            ],
            "ledger_manager_role": "ledger_manager",
            "release_approver_role": "release_approver",
            "retry_approver_role": "retry_approver",
            "role_distinctness_required": True,
            "runner_role": "test_runner",
            "technical_retry_reasons": [
                {
                    "eligible_from_states": ["RESERVED"],
                    "reason_id": "fixture-environment",
                },
                {
                    "eligible_from_states": ["RESERVED"],
                    "reason_id": "fixture-prestart",
                },
                {
                    "eligible_from_states": ["RESERVED"],
                    "reason_id": "fixture-started-append",
                },
                {
                    "eligible_from_states": ["STARTED"],
                    "reason_id": "fixture-poststart",
                },
                {
                    "eligible_from_states": ["STARTED"],
                    "reason_id": "fixture-executor",
                },
            ],
        },
    }


def readiness_payload(test_batch_hash: str, context_hash: str, roots_hash: str) -> dict:
    return {
        "schema_version": READINESS_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_readiness_authorization",
        "authorization_id": "fixture-readiness-001",
        "authorized_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": APPROVAL_HASH,
        "signature_record_sha256": SIGNATURE_HASH,
        "gate_b_ready": True,
        "test_batch_hash": test_batch_hash,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": context_hash,
        "approved_roots_sha256": roots_hash,
        "authorized_runner_actor_id": "fixture-runner",
        "authorized_runner_role": "test_runner",
        "authorized_ledger_manager_actor_id": "fixture-ledger-manager",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "fixture-release-approver",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "fixture-retry-approver",
        "designated_retry_approver_role": "retry_approver",
        "ledger_namespace_derivation": "ledger_base/<test_batch_hash>",
        "quarantine_namespace_derivation": (
            "quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>"
        ),
    }


def test_all_fourteen_schema_identities_are_distinct() -> None:
    schemas = {
        BATCH_MANIFEST_SCHEMA_VERSION,
        ATTEMPT_LEDGER_RECORD_SCHEMA_VERSION,
        QUARANTINE_MANIFEST_SCHEMA_VERSION,
        LOADER_REQUEST_SCHEMA_VERSION,
        READINESS_AUTHORIZATION_SCHEMA_VERSION,
        RELEASE_AUTHORIZATION_SCHEMA_VERSION,
        RETRY_AUTHORIZATION_SCHEMA_VERSION,
        ROOT_ANCHOR_SCHEMA_VERSION,
        OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
        EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
        EXECUTION_CONTEXT_SCHEMA_VERSION,
        ACCESS_LOG_ENTRY_SCHEMA_VERSION,
        HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
        HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
    }
    assert len(schemas) == 14


def test_load_batch_manifest_and_complete_hash(tmp_path: Path) -> None:
    path = _fixture_path(tmp_path, "batch.json")
    payload = batch_payload()
    expected = _write(path, payload)

    loaded = load_gate_b_batch_manifest(path, expected_sha256=expected)

    assert loaded.test_batch_hash == expected
    assert loaded.payload["git"]["commit_oid"] == COMMIT
    assert loaded.reason_for("executor_callback_failure", "STARTED") == "fixture-executor"
    assert "test_batch_hash" not in loaded.payload


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"unknown": True}), "closed-world"),
        (lambda value: value["coordinates"].update({"horizons": [50, 50]}), "horizons"),
        (
            lambda value: value["test_input"].update({"execution_config_index_sha256": HASH_B}),
            "index hash",
        ),
        (
            lambda value: value["selection"].update({"primary_config_sha256": HASH_A}),
            "selected-lock wrapper",
        ),
        (
            lambda value: value["governance"]["failure_reason_map"][0].update(
                {"from_state": "STARTED"}
            ),
            "map",
        ),
        (
            lambda value: value["coordinates"]["seed_mapping"][0].update({"seed": 1.5}),
            "integer",
        ),
        (
            lambda value: value.update({"created_at_utc": "2026-02-30T00:00:00Z"}),
            "RFC 3339",
        ),
        (
            lambda value: value["components"]["baseline_table"].update(
                {"relative_path": "../escape.json"}
            ),
            "safe POSIX",
        ),
        (
            lambda value: value["components"]["baseline_table"].update({"size_bytes": 1 << 63}),
            "integer domain",
        ),
    ],
)
def test_batch_manifest_rejects_closed_world_and_join_mutations(
    tmp_path: Path, mutation, message: str
) -> None:
    payload = batch_payload()
    mutation(payload)
    path = _fixture_path(tmp_path, "batch.json")
    expected = _write(path, payload)

    with pytest.raises(GateBContractError, match=message):
        load_gate_b_batch_manifest(path, expected_sha256=expected)


def test_batch_manifest_rejects_duplicate_noncanonical_and_nan(tmp_path: Path) -> None:
    variants = (
        b'{"schema_version":"x","schema_version":"y"}\n',
        b'{ "schema_version": "x" }\n',
        b'{"value":NaN}\n',
    )
    for index, raw in enumerate(variants):
        path = _fixture_path(tmp_path, f"bad-{index}.json")
        path.write_bytes(raw)
        with pytest.raises(GateBContractError):
            load_gate_b_batch_manifest(path, expected_sha256=sha256_bytes(raw))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["canonicalization"].update({"allow_nan": True}),
        lambda value: value["canonicalization"].update({"allow_nan": 0}),
        lambda value: value["canonicalization"].update({"encoding": "ascii"}),
        lambda value: value["canonicalization"].update({"ensure_ascii": False}),
        lambda value: value["canonicalization"].update({"separators": [", ", ": "]}),
        lambda value: value["canonicalization"].update({"sort_keys": False}),
        lambda value: value["canonicalization"].update({"trailing_lf": False}),
        lambda value: value["git"].update({"branch": "fixture-branch"}),
        lambda value: value["git"].update({"commit_oid": "A" * 40}),
        lambda value: value["runtime"]["dependency_lock"].update({"name": "fixture-lock"}),
        lambda value: value["runtime"]["dependency_lock"].update(
            {"schema_version": "fixture-lock-v1"}
        ),
        lambda value: value["runtime"]["dependency_lock"].update({"size_bytes": True}),
        lambda value: value["runtime"].update({"machine": ""}),
        lambda value: value["components"]["baseline_table"].update({"name": "other"}),
        lambda value: value["components"]["baseline_table"].update({"schema_version": ""}),
        lambda value: value["components"]["baseline_table"].update({"sha256": "A" * 64}),
        lambda value: value["components"]["baseline_table"].update({"size_bytes": False}),
        lambda value: value["components"]["baseline_table"].update(
            {"relative_path": "components\\baseline.json"}
        ),
        lambda value: value["selection"].update({"manual_override": True}),
        lambda value: value["selection"].update({"primary_config_id": ""}),
        lambda value: value["test_input"].update({"framing_version": "fixture-framing"}),
        lambda value: value["test_input"].update({"split_id": ""}),
        lambda value: value["coordinates"].update({"horizons": [100, 50]}),
        lambda value: value["coordinates"].update(
            {"opponent_ids": ["fixture-opponent-001", "fixture-opponent-001"]}
        ),
        lambda value: value["coordinates"].update({"repetition_ids": []}),
        lambda value: value["coordinates"].update({"seed_mapping": []}),
        lambda value: value["coordinates"]["seed_mapping"][0].update({"horizon": 50.0}),
        lambda value: value["ledger_policy"]["states"].reverse(),
        lambda value: value["ledger_policy"].update({"exclusive_create": 1}),
        lambda value: value["ledger_policy"].update({"cleanup": "automatic"}),
        lambda value: value["ledger_policy"].update(
            {"topology_policy_version": "fixture-topology"}
        ),
        lambda value: value["quarantine_policy"]["outputs"].reverse(),
        lambda value: value["quarantine_policy"].update({"read_before_release": 0}),
        lambda value: value["quarantine_policy"].update({"read_before_release": True}),
        lambda value: value["governance"].update({"role_distinctness_required": False}),
        lambda value: value["governance"].update({"runner_role": "runner"}),
        lambda value: value["governance"]["technical_retry_reasons"].append(
            copy.deepcopy(value["governance"]["technical_retry_reasons"][0])
        ),
        lambda value: value["governance"]["technical_retry_reasons"][0].update(
            {"eligible_from_states": ["STARTED"]}
        ),
        lambda value: value["governance"]["failure_reason_map"].reverse(),
        lambda value: value["governance"]["failure_reason_map"].pop(),
        lambda value: value["governance"]["failure_reason_map"][0].update(
            {"reason_id": "fixture-unknown"}
        ),
        lambda value: value.update({"created_at_utc": "2026-07-24T00:00:00.1Z"}),
    ],
)
def test_batch_manifest_nested_constant_type_and_domain_matrix(
    tmp_path: Path,
    mutation,
) -> None:
    payload = batch_payload()
    mutation(payload)
    path = _fixture_path(tmp_path, "nested-batch-mutation.json")
    digest = _write(path, payload)
    with pytest.raises(GateBContractError):
        load_gate_b_batch_manifest(path, expected_sha256=digest)


def test_direct_contract_loader_rechecks_descriptor_link_topology_after_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = _fixture_path(tmp_path, "postread-topology.json")
    digest = _write(path, batch_payload())
    original_fstat = os.fstat
    calls = 0

    def changed_after_read(descriptor: int):
        nonlocal calls
        metadata = original_fstat(descriptor)
        calls += 1
        if calls < 2:
            return metadata
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_nlink=2,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_file_attributes=getattr(metadata, "st_file_attributes", 0),
        )

    monkeypatch.setattr(os, "fstat", changed_after_read)
    with pytest.raises(GateBContractError, match="descriptor topology changed"):
        load_gate_b_batch_manifest(path, expected_sha256=digest)


def test_readiness_authorization_requires_all_three_trust_anchors(
    tmp_path: Path,
) -> None:
    payload = readiness_payload(HASH_A, HASH_B, HASH_C)
    path = _fixture_path(tmp_path, "readiness.json")
    stored_hash = _write(path, payload)
    loaded = load_gate_b_readiness_authorization(
        path,
        expected_sha256=stored_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )
    assert loaded.payload["authorized_runner_actor_id"] == "fixture-runner"

    with pytest.raises(GateBContractError, match="trust-anchor"):
        load_gate_b_readiness_authorization(
            path,
            expected_sha256=stored_hash,
            expected_approval_record_sha256="f" * 64,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )

    duplicated_actor = copy.deepcopy(payload)
    duplicated_actor["designated_retry_approver_id"] = duplicated_actor[
        "designated_release_approver_id"
    ]
    duplicate_path = _fixture_path(tmp_path, "duplicate-actor.json")
    duplicate_hash = _write(duplicate_path, duplicated_actor)
    with pytest.raises(GateBContractError, match="pairwise distinct"):
        load_gate_b_readiness_authorization(
            duplicate_path,
            expected_sha256=duplicate_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("schema_version", "fixture-readiness"),
        ("artifact_type", "fixture_readiness"),
        ("authorized_at_utc", "2026-07-24T00:00:00.1Z"),
        ("gate_b_ready", False),
        ("test_batch_hash", "A" * 64),
        ("approved_implementation_commit", "A" * 40),
        ("approved_execution_context_sha256", "A" * 64),
        ("approved_roots_sha256", "A" * 64),
        ("authorized_runner_actor_id", "Unsafe Actor"),
        ("authorized_runner_role", "runner"),
        ("authorized_ledger_manager_role", "manager"),
        ("designated_release_approver_role", "approver"),
        ("designated_retry_approver_role", "approver"),
        ("ledger_namespace_derivation", "fixture-ledger"),
        ("quarantine_namespace_derivation", "fixture-quarantine"),
    ],
)
def test_readiness_nested_binding_and_role_matrix(
    tmp_path: Path,
    field: str,
    bad_value: object,
) -> None:
    payload = readiness_payload(HASH_A, HASH_B, HASH_C)
    payload[field] = bad_value
    path = _fixture_path(tmp_path, "bad-readiness-matrix.json")
    digest = _write(path, payload)
    with pytest.raises(GateBContractError):
        load_gate_b_readiness_authorization(
            path,
            expected_sha256=digest,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


def test_release_and_retry_authorization_strict_loaders(tmp_path: Path) -> None:
    release = {
        "schema_version": RELEASE_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_release_authorization",
        "authorization_id": "fixture-release-001",
        "authorized_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": APPROVAL_HASH,
        "signature_record_sha256": SIGNATURE_HASH,
        "test_batch_hash": HASH_A,
        "attempt_ordinal": 1,
        "sealed_record_sha256": HASH_B,
        "quarantine_manifest_sha256": HASH_C,
        "access_log_sha256": "f" * 64,
        "approver_id": "fixture-release-approver",
        "approver_role": "release_approver",
        "non_disclosure_attested": True,
    }
    release_path = _fixture_path(tmp_path, "release.json")
    release_hash = _write(release_path, release)
    assert (
        load_gate_b_release_authorization(
            release_path,
            expected_sha256=release_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        ).sha256
        == release_hash
    )

    retry = {
        "schema_version": RETRY_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_retry_authorization",
        "authorization_id": "fixture-retry-001",
        "authorized_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": APPROVAL_HASH,
        "signature_record_sha256": SIGNATURE_HASH,
        "test_batch_hash": HASH_A,
        "failed_record_sha256": HASH_B,
        "failed_attempt_ordinal": 1,
        "quarantine_manifest_sha256": HASH_C,
        "access_log_sha256": "f" * 64,
        "non_disclosure_attested": True,
        "disclosure_event_detected": False,
        "technical_reason_id": "fixture-environment",
        "approver_id": "fixture-retry-approver",
        "approver_role": "retry_approver",
        "failed_runner_actor_id": "fixture-runner",
        "next_attempt_ordinal": 2,
        "unchanged_implementation_commit": COMMIT,
        "unchanged_batch_manifest_sha256": HASH_A,
        "unchanged_selection_sha256": HASH_B,
        "unchanged_coordinates_sha256": HASH_C,
    }
    retry_path = _fixture_path(tmp_path, "retry.json")
    retry_hash = _write(retry_path, retry)
    assert (
        load_gate_b_retry_authorization(
            retry_path,
            expected_sha256=retry_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        ).sha256
        == retry_hash
    )
    changed = copy.deepcopy(retry)
    changed["next_attempt_ordinal"] = 3
    bad_path = _fixture_path(tmp_path, "bad-retry.json")
    bad_hash = _write(bad_path, changed)
    with pytest.raises(GateBContractError, match="ordinal"):
        load_gate_b_retry_authorization(
            bad_path,
            expected_sha256=bad_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )

    tamper_cases = [
        ("release-role", release, "approver_role", "test_runner"),
        ("release-attestation", release, "non_disclosure_attested", False),
        ("release-ordinal", release, "attempt_ordinal", True),
        ("release-six-digit", release, "attempt_ordinal", 1000000),
        ("release-hash", release, "access_log_sha256", "A" * 64),
        ("retry-role", retry, "approver_role", "release_approver"),
        ("retry-attestation", retry, "non_disclosure_attested", False),
        ("retry-disclosure", retry, "disclosure_event_detected", True),
        ("retry-failed-ordinal", retry, "failed_attempt_ordinal", True),
        ("retry-six-digit", retry, "failed_attempt_ordinal", 999999),
        ("retry-reason", retry, "technical_reason_id", "Unsafe Reason"),
    ]
    for name, original, field, bad_value in tamper_cases:
        changed = copy.deepcopy(original)
        changed[field] = bad_value
        path = _fixture_path(tmp_path, f"{name}.json")
        digest = _write(path, changed)
        loader = (
            load_gate_b_release_authorization
            if original is release
            else load_gate_b_retry_authorization
        )
        with pytest.raises(GateBContractError):
            loader(
                path,
                expected_sha256=digest,
                expected_approval_record_sha256=APPROVAL_HASH,
                expected_signature_record_sha256=SIGNATURE_HASH,
            )


def test_root_anchor_and_execution_context_are_strict(tmp_path: Path) -> None:
    anchor_payload = {
        "schema_version": ROOT_ANCHOR_SCHEMA_VERSION,
        "artifact_type": "gate_b_root_anchor",
        "root_role": "ledger_base",
        "anchor_id": "fixture-ledger-anchor",
        "created_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_sha256": APPROVAL_HASH,
    }
    anchor_path = _fixture_path(tmp_path, "anchor.json")
    anchor_hash = _write(anchor_path, anchor_payload)
    assert (
        load_gate_b_root_anchor(
            anchor_path,
            expected_sha256=anchor_hash,
            expected_root_role="ledger_base",
            expected_approval_record_sha256=APPROVAL_HASH,
        ).payload["root_role"]
        == "ledger_base"
    )

    lock_path = _fixture_path(tmp_path, "dependency-lock.json").resolve()
    lock_path.write_bytes(b"fixture\n")
    root = tmp_path.resolve()
    metadata = root.stat()
    context = {
        "schema_version": EXECUTION_CONTEXT_SCHEMA_VERSION,
        "artifact_type": "gate_b_execution_context",
        "active_modules": [
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": HASH_A,
            }
            for module_name, relative_path in ACTIVE_MODULE_PATHS
        ],
        "created_at_utc": "2026-07-24T00:00:00Z",
        "repository_root": {
            "absolute_path": str(root),
            "file_id_hex": format(metadata.st_ino, "x"),
            "identity_scheme": (
                "windows-volume-file-id-v1"
                if __import__("os").name == "nt"
                else "posix-device-inode-v1"
            ),
            "volume_id_hex": format(metadata.st_dev, "x"),
        },
        "expected_implementation_commit": COMMIT,
        "runtime_fingerprint": {
            "python_implementation": "CPython",
            "python_version": "3.12.0",
            "python_compiler": "fixture-compiler",
            "platform": "fixture-platform",
            "system": "fixture-os",
            "release": "fixture-release",
            "version": "fixture-version",
            "machine": "fixture-machine",
        },
        "dependency_lock": {
            "absolute_path": str(lock_path),
            "sha256": sha256_bytes(lock_path.read_bytes()),
            "size_bytes": len(lock_path.read_bytes()),
        },
    }
    context_path = _fixture_path(tmp_path, "context.json")
    context_hash = _write(context_path, context)
    loaded = load_gate_b_execution_context(context_path, expected_sha256=context_hash)
    assert loaded.payload["active_modules"][0]["module_name"] == "phase6.contracts"

    reordered = copy.deepcopy(context)
    reordered["active_modules"].reverse()
    reordered_path = _fixture_path(tmp_path, "reordered-context.json")
    reordered_hash = _write(reordered_path, reordered)
    with pytest.raises(GateBContractError, match="order"):
        load_gate_b_execution_context(reordered_path, expected_sha256=reordered_hash)

    mutations = [
        lambda value: value["active_modules"].pop(),
        lambda value: value["active_modules"][0].update({"module_name": "phase6.shadow"}),
        lambda value: value["active_modules"][0].update(
            {"repository_relative_path": "../shadow.py"}
        ),
        lambda value: value["active_modules"][0].update({"sha256": "A" * 64}),
        lambda value: value["active_modules"][0].update({"unknown": True}),
        lambda value: value.update({"created_at_utc": "2026-07-24T00:00:00+00:00"}),
        lambda value: value.update({"expected_implementation_commit": "A" * 40}),
        lambda value: value["repository_root"].update({"absolute_path": "relative/root"}),
        lambda value: value["repository_root"].update({"file_id_hex": ""}),
        lambda value: value["repository_root"].update({"identity_scheme": "fixture-scheme"}),
        lambda value: value["runtime_fingerprint"].pop("machine"),
        lambda value: value["runtime_fingerprint"].update({"unknown": "fixture"}),
        lambda value: value["runtime_fingerprint"].update({"platform": ""}),
        lambda value: value["dependency_lock"].update({"absolute_path": "relative-lock.json"}),
        lambda value: value["dependency_lock"].update({"sha256": "A" * 64}),
        lambda value: value["dependency_lock"].update({"size_bytes": True}),
        lambda value: value["dependency_lock"].update({"unknown": True}),
    ]
    for index, mutation in enumerate(mutations):
        changed = copy.deepcopy(context)
        mutation(changed)
        changed_path = _fixture_path(tmp_path, f"context-matrix-{index}.json")
        changed_hash = _write(changed_path, changed)
        with pytest.raises(GateBContractError):
            load_gate_b_execution_context(changed_path, expected_sha256=changed_hash)


def test_reason_detail_digest_has_no_free_form_material() -> None:
    expected = sha256_bytes(canonical_json_bytes({"reason_id": "fixture-environment"}))
    assert _canonical_reason_detail_sha256("fixture-environment") == expected


def test_direct_contract_open_requires_posix_nofollow_and_windows_reparse_flag() -> None:
    for unavailable in (None, 0, -1, False, "O_NOFOLLOW"):
        with pytest.raises(GateBContractError, match="O_NOFOLLOW"):
            _required_posix_nofollow(unavailable)

    calls = []

    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.callback(*args)

    class FakeKernel:
        def __init__(self):
            self.CreateFileW = FakeFunction(self._create)
            self.CloseHandle = FakeFunction(lambda handle: calls.append(("close", handle.value)))

        @staticmethod
        def _create(path, access, share, _security, creation, attributes, _template):
            calls.append(("create", path, access, share, creation, attributes))
            return 1234

    converted = []
    descriptor = _windows_open_contract_descriptor(
        Path("C:/fixture/artifact.json"),
        _kernel32=FakeKernel(),
        _open_osfhandle=lambda handle, flags: converted.append((handle, flags)) or 51,
    )
    assert descriptor == 51
    create = calls[0]
    assert create[2:5] == (0x80000000, 7, 3)
    assert create[5] & 0x00200000
    assert converted[0][0] == 1234


def test_direct_contract_open_closes_windows_handle_when_fd_conversion_fails() -> None:
    closed = []

    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.callback(*args)

    kernel = SimpleNamespace(
        CreateFileW=FakeFunction(lambda *_args: 4321),
        CloseHandle=FakeFunction(lambda handle: closed.append(handle.value)),
    )
    with pytest.raises(RuntimeError, match="conversion"):
        _windows_open_contract_descriptor(
            Path("C:/fixture/artifact.json"),
            _kernel32=kernel,
            _open_osfhandle=lambda *_args: (_ for _ in ()).throw(RuntimeError("conversion")),
        )
    assert closed == [4321]


def test_public_contract_loader_uses_platform_no_follow_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = batch_payload()
    path = _fixture_path(tmp_path, "dispatch-batch.json")
    digest = _write(path, payload)
    opened = []
    original = contracts_module._open_contract_descriptor

    def observed(candidate: Path) -> int:
        opened.append(candidate)
        return original(candidate)

    monkeypatch.setattr(contracts_module, "_open_contract_descriptor", observed)
    assert load_gate_b_batch_manifest(path, expected_sha256=digest).sha256 == digest
    assert opened == [path]


def human_approval_payload() -> dict[str, object]:
    return {
        "schema_version": HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_approval_record",
        "approval_record_id": "fixture-approval-001",
        "approved_at_utc": "2026-07-26T00:00:00Z",
        "approver_actor_id": "fixture-human",
        "approver_role": "human_gate_b_approver",
        "approval_decision": "APPROVE_INITIAL_GATE_B_READINESS",
        "approval_scope": "initial_attempt_only",
        "test_batch_hash": HASH_A,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": HASH_B,
        "approved_roots_sha256": HASH_C,
        "authorized_runner_actor_id": "fixture-runner",
        "authorized_runner_role": "test_runner",
        "authorized_ledger_manager_actor_id": "fixture-ledger-manager",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "fixture-release-approver",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "fixture-retry-approver",
        "designated_retry_approver_role": "retry_approver",
        "expected_attempt_ordinal": 1,
        "release_authorized": False,
        "retry_authorized": False,
    }


def human_signature_payload(approval_hash: str) -> dict[str, object]:
    return {
        "schema_version": HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_signature_record",
        "signature_record_id": "fixture-signature-001",
        "signed_at_utc": "2026-07-26T00:00:01Z",
        "signer_actor_id": "fixture-human",
        "signer_role": "human_gate_b_attestor",
        "signature_method": "human-governance-attestation-v1",
        "attestation": "ATTEST_EXACT_GATE_B_APPROVAL_RECORD",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": approval_hash,
        "test_batch_hash": HASH_A,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": HASH_B,
        "approved_roots_sha256": HASH_C,
    }


def _strict_human_records() -> tuple[GateBHumanApprovalRecord, GateBHumanSignatureRecord]:
    approval_raw = canonical_json_bytes(human_approval_payload())
    approval = load_gate_b_human_approval_record_bytes(
        approval_raw, expected_sha256=sha256_bytes(approval_raw)
    )
    signature_raw = canonical_json_bytes(human_signature_payload(approval.sha256))
    signature = load_gate_b_human_signature_record_bytes(
        signature_raw,
        expected_sha256=sha256_bytes(signature_raw),
        approval=approval,
    )
    return approval, signature


def test_human_records_and_readiness_trust_chain_are_exact_and_side_effect_free(
    tmp_path: Path,
) -> None:
    before = tuple(tmp_path.iterdir())
    approval, signature = _strict_human_records()
    readiness = readiness_payload(HASH_A, HASH_B, HASH_C)
    readiness["approval_record_sha256"] = approval.sha256
    readiness["signature_record_sha256"] = signature.sha256

    assert approval.raw == canonical_json_bytes(human_approval_payload())
    assert approval.payload["approval_record_id"] == approval.approval_record_id
    assert signature.payload["signature_record_id"] == signature.signature_record_id
    assert signature.approval_record_id == approval.approval_record_id
    assert signature.approval_record_sha256 == approval.sha256
    assert validate_gate_b_readiness_human_trust_chain(approval, signature, readiness) is None
    assert tuple(tmp_path.iterdir()) == before
    with pytest.raises(TypeError):
        GateBHumanApprovalRecord()
    with pytest.raises(TypeError):
        GateBHumanSignatureRecord()
    with pytest.raises(TypeError):
        approval.payload["approval_record_id"] = "mutated"  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "wrong"),
        ("artifact_type", "wrong"),
        ("approval_record_id", "Unsafe ID"),
        ("approved_at_utc", "2026-07-26T00:00:00.0Z"),
        ("approver_actor_id", "fixture-runner"),
        ("approver_role", "wrong"),
        ("approval_decision", "wrong"),
        ("approval_scope", "wrong"),
        ("test_batch_hash", "A" * 64),
        ("approved_implementation_commit", "f" * 39),
        ("approved_execution_context_sha256", "A" * 64),
        ("approved_roots_sha256", "A" * 64),
        ("authorized_runner_actor_id", "fixture-ledger-manager"),
        ("authorized_runner_role", "wrong"),
        ("authorized_ledger_manager_actor_id", "fixture-runner"),
        ("authorized_ledger_manager_role", "wrong"),
        ("designated_release_approver_id", "fixture-runner"),
        ("designated_release_approver_role", "wrong"),
        ("designated_retry_approver_id", "fixture-runner"),
        ("designated_retry_approver_role", "wrong"),
        ("expected_attempt_ordinal", 2),
        ("release_authorized", True),
        ("retry_authorized", True),
    ],
)
def test_human_approval_rejects_every_policy_field_mutation(field, invalid) -> None:
    payload = human_approval_payload()
    payload[field] = invalid
    raw = canonical_json_bytes(payload)
    with pytest.raises(GateBContractError):
        load_gate_b_human_approval_record_bytes(raw, expected_sha256=sha256_bytes(raw))


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "wrong"),
        ("artifact_type", "wrong"),
        ("signature_record_id", "fixture-approval-001"),
        ("signed_at_utc", "wrong"),
        ("signer_actor_id", "fixture-runner"),
        ("signer_role", "wrong"),
        ("signature_method", "wrong"),
        ("attestation", "wrong"),
        ("approval_record_id", "fixture-other"),
        ("approval_record_sha256", "f" * 64),
        ("test_batch_hash", HASH_B),
        ("approved_implementation_commit", "b" * 40),
        ("approved_execution_context_sha256", HASH_C),
        ("approved_roots_sha256", HASH_B),
    ],
)
def test_human_signature_rejects_every_policy_or_join_mutation(field, invalid) -> None:
    approval_raw = canonical_json_bytes(human_approval_payload())
    approval = load_gate_b_human_approval_record_bytes(
        approval_raw, expected_sha256=sha256_bytes(approval_raw)
    )
    payload = human_signature_payload(approval.sha256)
    payload[field] = invalid
    raw = canonical_json_bytes(payload)
    with pytest.raises(GateBContractError):
        load_gate_b_human_signature_record_bytes(
            raw,
            expected_sha256=sha256_bytes(raw),
            approval=approval,
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("approval_record_id", "fixture-other"),
        ("approval_record_sha256", "f" * 64),
        ("signature_record_sha256", "f" * 64),
        ("test_batch_hash", HASH_B),
        ("approved_implementation_commit", "b" * 40),
        ("approved_execution_context_sha256", HASH_C),
        ("approved_roots_sha256", HASH_B),
        ("authorized_runner_actor_id", "fixture-other"),
        ("authorized_runner_role", "wrong"),
        ("authorized_ledger_manager_actor_id", "fixture-other"),
        ("authorized_ledger_manager_role", "wrong"),
        ("designated_release_approver_id", "fixture-other"),
        ("designated_release_approver_role", "wrong"),
        ("designated_retry_approver_id", "fixture-other"),
        ("designated_retry_approver_role", "wrong"),
    ],
)
def test_readiness_human_trust_chain_rejects_every_join_mutation(field, invalid) -> None:
    approval, signature = _strict_human_records()
    readiness = readiness_payload(HASH_A, HASH_B, HASH_C)
    readiness["approval_record_sha256"] = approval.sha256
    readiness["signature_record_sha256"] = signature.sha256
    readiness[field] = invalid
    with pytest.raises(GateBContractError):
        validate_gate_b_readiness_human_trust_chain(approval, signature, readiness)


def test_human_record_bytes_reject_duplicates_noncanonical_and_forgery() -> None:
    approval_payload = human_approval_payload()
    approval_raw = canonical_json_bytes(approval_payload)
    duplicate_approval = approval_raw.replace(
        b'{"approval_decision":',
        b'{"approval_decision":"APPROVE_INITIAL_GATE_B_READINESS","approval_decision":',
        1,
    )
    with pytest.raises(GateBContractError):
        load_gate_b_human_approval_record_bytes(
            duplicate_approval,
            expected_sha256=sha256_bytes(duplicate_approval),
        )
    with pytest.raises(GateBContractError):
        load_gate_b_human_approval_record_bytes(
            approval_raw + b" ",
            expected_sha256=sha256_bytes(approval_raw + b" "),
        )
    approval, signature = _strict_human_records()
    signature_payload = human_signature_payload(approval.sha256)
    signature_raw = canonical_json_bytes(signature_payload)
    duplicate_signature = signature_raw.replace(
        b'{"approval_record_id":',
        (b'{"approval_record_id":"fixture-approval-001","approval_record_id":'),
        1,
    )
    with pytest.raises(GateBContractError):
        load_gate_b_human_signature_record_bytes(
            duplicate_signature,
            expected_sha256=sha256_bytes(duplicate_signature),
            approval=approval,
        )
    with pytest.raises(GateBContractError):
        load_gate_b_human_signature_record_bytes(
            signature_raw + b" ",
            expected_sha256=sha256_bytes(signature_raw + b" "),
            approval=approval,
        )

    forged_approval = object.__new__(GateBHumanApprovalRecord)
    for name in (
        "_sha256",
        "_raw",
        "_payload",
        "_approval_record_id",
        "_loader_token",
    ):
        object.__setattr__(forged_approval, name, getattr(approval, name))
    with pytest.raises(GateBContractError, match="provenance"):
        validate_gate_b_readiness_human_trust_chain(
            forged_approval,
            signature,
            readiness_payload(HASH_A, HASH_B, HASH_C),
        )

    forged_signature = object.__new__(GateBHumanSignatureRecord)
    for name in (
        "_sha256",
        "_raw",
        "_payload",
        "_signature_record_id",
        "_approval_record_id",
        "_approval_record_sha256",
        "_loader_token",
    ):
        object.__setattr__(forged_signature, name, getattr(signature, name))
    with pytest.raises(GateBContractError, match="provenance"):
        validate_gate_b_readiness_human_trust_chain(
            approval,
            forged_signature,
            readiness_payload(HASH_A, HASH_B, HASH_C),
        )


@pytest.mark.parametrize(
    ("record_kind", "field"),
    [
        ("approval", "_raw"),
        ("approval", "_sha256"),
        ("approval", "_payload"),
        ("approval", "_approval_record_id"),
        ("approval", "_loader_token"),
        ("signature", "_raw"),
        ("signature", "_sha256"),
        ("signature", "_payload"),
        ("signature", "_signature_record_id"),
        ("signature", "_approval_record_id"),
        ("signature", "_approval_record_sha256"),
        ("signature", "_loader_token"),
    ],
)
def test_human_trust_chain_rejects_every_retained_property_mutation(
    record_kind: str,
    field: str,
) -> None:
    approval, signature = _strict_human_records()
    target = approval if record_kind == "approval" else signature
    if field == "_raw":
        invalid = target.raw + b" "
    elif field == "_sha256":
        invalid = "f" * 64
    elif field == "_payload":
        invalid = {"forged": True}
    elif field == "_loader_token":
        invalid = object()
    else:
        invalid = "fixture-forged"
    object.__setattr__(target, field, invalid)
    readiness = readiness_payload(HASH_A, HASH_B, HASH_C)
    readiness["approval_record_sha256"] = APPROVAL_HASH
    readiness["signature_record_sha256"] = SIGNATURE_HASH
    with pytest.raises(GateBContractError, match="provenance"):
        validate_gate_b_readiness_human_trust_chain(
            approval,
            signature,
            readiness,
        )
