from __future__ import annotations

import ast
import copy
import json
import multiprocessing
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import phase6.gate_b_ledger as ledger_module
import phase6.gate_b_loader as loader_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACTIVE_MODULE_PATHS,
    BATCH_MANIFEST_SCHEMA_VERSION,
    COMPONENT_NAMES,
    EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
    EXECUTION_CONTEXT_SCHEMA_VERSION,
    INPUT_FRAMING_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_SCHEMA_VERSION,
    ROOT_ANCHOR_SCHEMA_VERSION,
    SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
    TOPOLOGY_POLICY_VERSION,
    _root_identity_payload,
)
from phase6.gate_b_ledger import GateBAttemptReservation, GateBLedgerError, GateBLedgerStore
from phase6.gate_b_loader import (
    GateBApprovedExecutor,
    GateBCapabilityClosed,
    GateBExecutionEnvironmentFailure,
    GateBExecutionEvidence,
    GateBExecutorContractViolation,
    GateBExecutorFailure,
    GateBLoaderError,
    GateBLoaderRequest,
    GateBTestInputFailure,
    load_gate_b_loader_request,
    open_gate_b_test_input,
    prepare_gate_b_test_open,
    reserve_gate_b_attempt,
)

COMMIT = "a" * 40
APPROVAL_HASH = "d" * 64
SIGNATURE_HASH = "e" * 64


def _store(path: Path, payload: object) -> tuple[str, int]:
    raw = canonical_json_bytes(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw), len(raw)


def _root_ref(
    path: Path,
    role: str,
    *,
    anchor_hash: str | None,
) -> dict[str, object]:
    return {
        **_root_identity_payload(path.resolve()),
        "anchor_relative_path": (None if role == "test_root" else ".gate-b-root-anchor.json"),
        "anchor_sha256": anchor_hash,
        "root_role": role,
    }


def _failure_map() -> list[dict[str, str]]:
    return [
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
    ]


def _batch_payload(
    component_refs: dict[str, dict[str, object]],
    *,
    primary_hash: str,
    dependency_hash: str,
    dependency_size: int,
    comparators: list[dict[str, str]],
    ablations: list[dict[str, str]],
) -> dict[str, object]:
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
                "sha256": dependency_hash,
                "size_bytes": dependency_size,
            },
            "machine": "fixture-machine",
            "os_name": "fixture-os",
            "os_release": "fixture-release",
            "python_implementation": "CPython",
            "python_version": "3.12.0",
        },
        "components": component_refs,
        "selection": {
            "ablations": ablations,
            "comparators": comparators,
            "manual_override": False,
            "primary_config_id": "fixture-primary-001",
            "primary_config_sha256": primary_hash,
            "selection_report_sha256": component_refs["validation_selection_report"]["sha256"],
        },
        "test_input": {
            "execution_config_index_sha256": component_refs["execution_config_index"]["sha256"],
            "format_id": "fixture-format-v1",
            "framing_version": INPUT_FRAMING_VERSION,
            "opponent_payload_index_sha256": component_refs["opponent_payload_index"]["sha256"],
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
            "topology_policy_version": TOPOLOGY_POLICY_VERSION,
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
            "failure_reason_map": _failure_map(),
            "ledger_manager_role": "ledger_manager",
            "release_approver_role": "release_approver",
            "retry_approver_role": "retry_approver",
            "role_distinctness_required": True,
            "runner_role": "test_runner",
            "technical_retry_reasons": [
                {
                    "eligible_from_states": [entry["from_state"]],
                    "reason_id": entry["reason_id"],
                }
                for entry in _failure_map()
            ],
        },
    }


@dataclass
class _Fixture:
    request: GateBLoaderRequest
    request_path: Path
    request_hash: str
    test_root: Path
    component_paths: dict[str, Path]
    payload_path: Path
    executor_id: str
    executor_sha256: str


def _build_fixture(tmp_path: Path) -> _Fixture:
    base = tmp_path / "gate-b-fixture"
    repository_root = base / "repository-root"
    test_root = base / "test-root"
    ledger_root = base / "ledger-root"
    quarantine_root = base / "quarantine-root"
    for path in (repository_root, test_root, ledger_root, quarantine_root):
        path.mkdir(parents=True, exist_ok=True)

    for path, role in (
        (ledger_root, "ledger_base"),
        (quarantine_root, "quarantine_base"),
    ):
        _store(
            path / ".gate-b-root-anchor.json",
            {
                "schema_version": ROOT_ANCHOR_SCHEMA_VERSION,
                "artifact_type": "gate_b_root_anchor",
                "root_role": role,
                "anchor_id": f"fixture-{role}-anchor",
                "created_at_utc": "2026-07-24T00:00:00Z",
                "approval_record_sha256": APPROVAL_HASH,
            },
        )

    dependency_path = repository_root / "d.json"
    dependency_hash, dependency_size = _store(
        dependency_path,
        {
            "schema_version": "fixture-lock-v1",
            "artifact_type": "fixture_dependency_lock",
        },
    )
    selected_config = {
        "detector_confidence": "0.9",
        "epsilon": "0.1",
        "grid_version": "phase6-primary-grid-v1",
        "provider_confidence": "0.8",
        "safety_alpha": "0.05",
        "sample_floor": 10,
        "sampling_contract_sha256": "f" * 64,
    }
    primary_raw = canonical_json_bytes(selected_config)
    primary_hash = sha256_bytes(primary_raw)
    component_payloads: dict[str, dict[str, object]] = {}
    for name in COMPONENT_NAMES:
        component_payloads[name] = {
            "schema_version": f"fixture-{name}-v1",
            "artifact_type": f"fixture_{name}",
        }
    component_payloads["selected_config_lock"] = {
        "schema_version": SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
        "artifact_type": "selected_config_lock",
        "split": "validation",
        "validation_batch_manifest_sha256": "1" * 64,
        "primary_selection_report_sha256": "",
        "selected_config_count": 1,
        "selected_candidate_id": "fixture-primary-001",
        "selected_config": selected_config,
        "selected_config_sha256": primary_hash,
        "manual_override": False,
    }
    component_paths = {
        name: test_root / "c" / f"{index}.json" for index, name in enumerate(COMPONENT_NAMES)
    }
    refs: dict[str, dict[str, object]] = {}
    for name in (
        "baseline_table",
        "estimator_config",
        "evaluator",
        "execution_sampler",
        "ground_truth_extractor",
        "opponent_catalog",
        "validation_selection_report",
    ):
        digest, size = _store(component_paths[name], component_payloads[name])
        refs[name] = {
            "name": name,
            "relative_path": f"c/{COMPONENT_NAMES.index(name)}.json",
            "schema_version": component_payloads[name]["schema_version"],
            "sha256": digest,
            "size_bytes": size,
        }
    component_payloads["selected_config_lock"]["primary_selection_report_sha256"] = refs[
        "validation_selection_report"
    ]["sha256"]
    selected_hash, selected_size = _store(
        component_paths["selected_config_lock"],
        component_payloads["selected_config_lock"],
    )
    refs["selected_config_lock"] = {
        "name": "selected_config_lock",
        "relative_path": f"c/{COMPONENT_NAMES.index('selected_config_lock')}.json",
        "schema_version": SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
        "sha256": selected_hash,
        "size_bytes": selected_size,
    }

    payload_path = test_root / "p" / "o.bin"
    payload_path.parent.mkdir(parents=True)
    payload_raw = b"synthetic-opponent-payload"
    payload_path.write_bytes(payload_raw)
    component_payloads["opponent_payload_index"] = {
        "schema_version": OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
        "artifact_type": "gate_b_opponent_payload_index",
        "format_id": "fixture-format-v1",
        "physical_split_id": "fixture-physical-split-v1",
        "split_id": "fixture-test-split-v1",
        "opponents": [
            {
                "opponent_id": "fixture-opponent-001",
                "relative_path": "p/o.bin",
                "sha256": sha256_bytes(payload_raw),
                "size_bytes": len(payload_raw),
            }
        ],
    }
    opponent_index_hash, opponent_index_size = _store(
        component_paths["opponent_payload_index"],
        component_payloads["opponent_payload_index"],
    )
    refs["opponent_payload_index"] = {
        "name": "opponent_payload_index",
        "relative_path": f"c/{COMPONENT_NAMES.index('opponent_payload_index')}.json",
        "schema_version": OPPONENT_PAYLOAD_INDEX_SCHEMA_VERSION,
        "sha256": opponent_index_hash,
        "size_bytes": opponent_index_size,
    }
    indexed_configs = {}
    for group_name, config_id, name, relative_path in (
        ("comparators", "fixture-comparator-001", "fixture-comparator", "k/c.json"),
        ("ablations", "fixture-ablation-001", "fixture-ablation", "k/a.json"),
    ):
        config_path = test_root.joinpath(*relative_path.split("/"))
        config_payload = {
            "schema_version": "fixture-indexed-config-v1",
            "artifact_type": "fixture_indexed_config",
            "config_id": config_id,
        }
        config_hash, config_size = _store(config_path, config_payload)
        indexed_configs[group_name] = {
            "config_id": config_id,
            "name": name,
            "relative_path": relative_path,
            "schema_version": "fixture-indexed-config-v1",
            "sha256": config_hash,
            "size_bytes": config_size,
        }
    component_payloads["execution_config_index"] = {
        "schema_version": EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
        "artifact_type": "gate_b_execution_config_index",
        "estimator_config_sha256": refs["estimator_config"]["sha256"],
        "selected_config_lock_sha256": selected_hash,
        "primary": {
            "config_id": "fixture-primary-001",
            "derivation": ("canonical_json_bytes(selected_config_lock#/selected_config)"),
            "name": "primary",
            "sha256": primary_hash,
            "size_bytes": len(primary_raw),
            "source_component_sha256": selected_hash,
        },
        "comparators": [indexed_configs["comparators"]],
        "ablations": [indexed_configs["ablations"]],
    }
    execution_index_hash, execution_index_size = _store(
        component_paths["execution_config_index"],
        component_payloads["execution_config_index"],
    )
    refs["execution_config_index"] = {
        "name": "execution_config_index",
        "relative_path": f"c/{COMPONENT_NAMES.index('execution_config_index')}.json",
        "schema_version": EXECUTION_CONFIG_INDEX_SCHEMA_VERSION,
        "sha256": execution_index_hash,
        "size_bytes": execution_index_size,
    }
    ordered_refs = {name: refs[name] for name in COMPONENT_NAMES}

    batch_path = base / "b.json"
    batch_hash, _batch_size = _store(
        batch_path,
        _batch_payload(
            ordered_refs,
            primary_hash=primary_hash,
            dependency_hash=dependency_hash,
            dependency_size=dependency_size,
            comparators=[
                {
                    key: indexed_configs["comparators"][key]
                    for key in ("config_id", "name", "sha256")
                }
            ],
            ablations=[
                {key: indexed_configs["ablations"][key] for key in ("config_id", "name", "sha256")}
            ],
        ),
    )
    context_path = base / "c.json"
    context_hash, _context_size = _store(
        context_path,
        {
            "schema_version": EXECUTION_CONTEXT_SCHEMA_VERSION,
            "artifact_type": "gate_b_execution_context",
            "active_modules": [
                {
                    "module_name": module_name,
                    "repository_relative_path": relative_path,
                    "sha256": f"{index + 1:x}" * 64,
                }
                for index, (module_name, relative_path) in enumerate(ACTIVE_MODULE_PATHS)
            ],
            "created_at_utc": "2026-07-24T00:00:00Z",
            "repository_root": _root_identity_payload(repository_root.resolve()),
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
                "absolute_path": str(dependency_path.resolve()),
                "sha256": dependency_hash,
                "size_bytes": dependency_size,
            },
        },
    )
    ledger_anchor_hash = sha256_bytes((ledger_root / ".gate-b-root-anchor.json").read_bytes())
    quarantine_anchor_hash = sha256_bytes(
        (quarantine_root / ".gate-b-root-anchor.json").read_bytes()
    )
    roots = {
        "ledger_base": _root_ref(ledger_root, "ledger_base", anchor_hash=ledger_anchor_hash),
        "quarantine_base": _root_ref(
            quarantine_root,
            "quarantine_base",
            anchor_hash=quarantine_anchor_hash,
        ),
        "test_root": _root_ref(test_root, "test_root", anchor_hash=None),
    }
    roots_hash = sha256_bytes(canonical_json_bytes(roots))
    readiness_path = base / "a.json"
    readiness_hash, _readiness_size = _store(
        readiness_path,
        {
            "schema_version": READINESS_AUTHORIZATION_SCHEMA_VERSION,
            "artifact_type": "gate_b_readiness_authorization",
            "authorization_id": "fixture-readiness-001",
            "authorized_at_utc": "2026-07-24T00:00:00Z",
            "approval_record_id": "fixture-approval-001",
            "approval_record_sha256": APPROVAL_HASH,
            "signature_record_sha256": SIGNATURE_HASH,
            "gate_b_ready": True,
            "test_batch_hash": batch_hash,
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
        },
    )
    request_path = base / "x.json"
    request_hash, _request_size = _store(
        request_path,
        {
            "schema_version": LOADER_REQUEST_SCHEMA_VERSION,
            "artifact_type": "gate_b_test_loader_request",
            "requested_at_utc": "2026-07-24T00:00:00Z",
            "batch_manifest": {
                "absolute_path": str(batch_path.resolve()),
                "sha256": batch_hash,
            },
            "readiness_authorization": {
                "absolute_path": str(readiness_path.resolve()),
                "sha256": readiness_hash,
            },
            "execution_context": {
                "absolute_path": str(context_path.resolve()),
                "sha256": context_hash,
            },
            "roots": roots,
            "actor": {
                "actor_id": "fixture-runner",
                "actor_role": "test_runner",
            },
            "attempt_ordinal": 1,
        },
    )
    request = load_gate_b_loader_request(
        request_path,
        expected_sha256=request_hash,
        expected_readiness_authorization_sha256=readiness_hash,
        expected_readiness_approval_record_sha256=APPROVAL_HASH,
        expected_readiness_signature_record_sha256=SIGNATURE_HASH,
    )
    sampler = ordered_refs["execution_sampler"]
    return _Fixture(
        request,
        request_path,
        request_hash,
        test_root,
        component_paths,
        payload_path,
        str(sampler["schema_version"]),
        str(sampler["sha256"]),
    )


def _evidence(request: GateBLoaderRequest) -> GateBExecutionEvidence:
    return GateBExecutionEvidence(
        request.execution_context.sha256,
        COMMIT,
        "a" * 64,
        "b" * 64,
        "c" * 64,
    )


class _DrainExecutor:
    def __init__(self, fixture: _Fixture) -> None:
        self.executor_id = fixture.executor_id
        self.executor_sha256 = fixture.executor_sha256
        self.stream = bytearray()
        self.input_capability = None
        self.output_capability = None

    def execute(self, input_capability, quarantine_outputs) -> None:
        self.input_capability = input_capability
        self.output_capability = quarantine_outputs
        while True:
            chunk = input_capability.read_chunk(7)
            if not chunk:
                break
            self.stream.extend(chunk)
        quarantine_outputs.write_chunk("result", b"{}")


class _SpawnDrainExecutor:
    def __init__(self, executor_id: str, executor_sha256: str) -> None:
        self.executor_id = executor_id
        self.executor_sha256 = executor_sha256

    def execute(self, input_capability, quarantine_outputs) -> None:
        while input_capability.read_chunk(7):
            pass
        quarantine_outputs.write_chunk("result", b"{}")


class _ShortWriteHandle:
    def __init__(self, handle) -> None:
        self.handle = handle

    def write(self, data: bytes) -> int:
        partial = data[:-1]
        self.handle.write(partial)
        return len(partial)

    def flush(self) -> None:
        self.handle.flush()

    def fileno(self) -> int:
        return self.handle.fileno()


def _prepare_open_worker(
    request_path: str,
    request_hash: str,
    readiness_hash: str,
    reserved_record_sha256: str,
    start_event,
    results,
) -> None:
    request = load_gate_b_loader_request(
        request_path,
        expected_sha256=request_hash,
        expected_readiness_authorization_sha256=readiness_hash,
        expected_readiness_approval_record_sha256=APPROVAL_HASH,
        expected_readiness_signature_record_sha256=SIGNATURE_HASH,
    )
    store = GateBLedgerStore(request)
    reserved_record = store.load_chain()[-1]
    reservation = GateBAttemptReservation(
        request.batch.test_batch_hash,
        request.attempt_ordinal,
        reserved_record_sha256,
        "RESERVED",
        reserved_record,
        store.directory,
    )
    events: list[str] = []
    original_open = loader_module._PinnedInput.open_first_unverified_at.__func__
    original_started = loader_module._append_started
    original_pin = loader_module._PinnedInput.pin_identity

    def open_first(cls, root_descriptor, root, relative):
        events.append("os_open")
        return original_open(cls, root_descriptor, root, relative)

    def append_started(*args, **kwargs):
        events.append("started_append")
        return original_started(*args, **kwargs)

    def pin_identity(self):
        events.append("descriptor_probe")
        return original_pin(self)

    loader_module.verify_gate_b_execution_environment = lambda loaded_request, _context: _evidence(
        loaded_request
    )
    loader_module._PinnedInput.open_first_unverified_at = classmethod(open_first)
    loader_module._append_started = append_started
    loader_module._PinnedInput.pin_identity = pin_identity
    start_event.wait(timeout=30)
    try:
        prepared = prepare_gate_b_test_open(request, reservation)
        sampler = request.batch.payload["components"]["execution_sampler"]
        receipt = open_gate_b_test_input(
            prepared,
            executor=_SpawnDrainExecutor(
                str(sampler["schema_version"]),
                str(sampler["sha256"]),
            ),
        )
        results.put(("winner", events, receipt.state))
    except (GateBLedgerError, GateBLoaderError) as exc:
        results.put(("rejected", events, type(exc).__name__))


def _frame_headers(raw: bytes) -> list[dict[str, Any]]:
    offset = 0
    headers = []
    while offset < len(raw):
        header_size = struct.unpack(">Q", raw[offset : offset + 8])[0]
        offset += 8
        header_raw = raw[offset : offset + header_size]
        offset += header_size
        header = json.loads(header_raw)
        data_size = struct.unpack(">Q", raw[offset : offset + 8])[0]
        offset += 8
        assert data_size == header["size_bytes"]
        payload = raw[offset : offset + data_size]
        offset += data_size
        assert sha256_bytes(payload) == header["sha256"]
        headers.append(header)
    return headers


def _open_with_fake_environment(
    monkeypatch: pytest.MonkeyPatch,
    fixture: _Fixture,
    executor: GateBApprovedExecutor,
):
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)
    return open_gate_b_test_input(prepared, executor=executor)


def test_loader_request_joins_all_explicit_roots_and_has_sanitized_repr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    request = fixture.request

    assert request.batch.test_batch_hash == request.readiness.payload["test_batch_hash"]
    assert (
        request.execution_context.sha256
        == request.readiness.payload["approved_execution_context_sha256"]
    )
    assert set(request.roots) == {"ledger_base", "quarantine_base", "test_root"}
    assert str(tmp_path) not in repr(request)
    request_payload = json.loads(fixture.request_path.read_bytes())
    monkeypatch.setattr(
        Path,
        "home",
        classmethod(lambda _cls: (_ for _ in ()).throw(AssertionError("home discovery forbidden"))),
    )
    monkeypatch.setattr(
        loader_module.os,
        "getenv",
        lambda *_args: (_ for _ in ()).throw(AssertionError("environment discovery forbidden")),
    )
    reloaded = load_gate_b_loader_request(
        fixture.request_path,
        expected_sha256=fixture.request_hash,
        expected_readiness_authorization_sha256=request_payload["readiness_authorization"][
            "sha256"
        ],
        expected_readiness_approval_record_sha256=APPROVAL_HASH,
        expected_readiness_signature_record_sha256=SIGNATURE_HASH,
    )
    assert reloaded.request_sha256 == fixture.request_hash


@pytest.mark.parametrize(
    "attack",
    [
        "alternate_copied_root",
        "case_alias",
        "short_name_alias",
        "physical_symlink_alias",
        "missing_anchor",
        "recreated_anchor",
        "rename_replacement",
    ],
)
def test_loader_request_rejects_ledger_namespace_alias_and_anchor_matrix(
    tmp_path: Path,
    attack: str,
) -> None:
    fixture = _build_fixture(tmp_path)
    payload = json.loads(fixture.request_path.read_bytes())
    readiness_hash = payload["readiness_authorization"]["sha256"]
    ledger_ref = payload["roots"]["ledger_base"]
    ledger_root = Path(ledger_ref["absolute_path"])
    anchor_path = ledger_root / ".gate-b-root-anchor.json"
    anchor_raw = anchor_path.read_bytes()
    if attack == "alternate_copied_root":
        alternate = ledger_root.with_name("ledger-root-copy")
        alternate.mkdir()
        (alternate / anchor_path.name).write_bytes(anchor_raw)
        payload["roots"]["ledger_base"] = _root_ref(
            alternate,
            "ledger_base",
            anchor_hash=sha256_bytes(anchor_raw),
        )
    elif attack == "case_alias":
        ledger_ref["absolute_path"] = str(ledger_root).swapcase()
    elif attack == "short_name_alias":
        ledger_ref["absolute_path"] = str(ledger_root.with_name("LEDGER~1"))
    elif attack == "physical_symlink_alias":
        alias = ledger_root.with_name("ledger-root-alias")
        try:
            os.symlink(ledger_root, alias, target_is_directory=True)
        except (OSError, PermissionError):
            capability = "unsupported_by_host_or_privilege"
        else:
            capability = "available"
        assert capability in {"available", "unsupported_by_host_or_privilege"}
        ledger_ref["absolute_path"] = str(alias)
    elif attack == "missing_anchor":
        anchor_path.rename(anchor_path.with_name("missing-anchor.json"))
    elif attack == "recreated_anchor":
        anchor_path.write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": ROOT_ANCHOR_SCHEMA_VERSION,
                    "artifact_type": "gate_b_root_anchor",
                    "root_role": "ledger_base",
                    "anchor_id": "fixture-recreated-anchor",
                    "created_at_utc": "2026-07-24T00:00:00Z",
                    "approval_record_sha256": "f" * 64,
                }
            )
        )
    else:
        moved = ledger_root.with_name("ledger-root-moved")
        ledger_root.rename(moved)
        ledger_root.mkdir()
        (ledger_root / anchor_path.name).write_bytes(anchor_raw)
    request_hash, _size = _store(fixture.request_path, payload)
    with pytest.raises(GateBLoaderError):
        load_gate_b_loader_request(
            fixture.request_path,
            expected_sha256=request_hash,
            expected_readiness_authorization_sha256=readiness_hash,
            expected_readiness_approval_record_sha256=APPROVAL_HASH,
            expected_readiness_signature_record_sha256=SIGNATURE_HASH,
        )


def test_loader_request_rejects_attempt_outside_six_digit_namespace(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    payload = json.loads(fixture.request_path.read_bytes())
    payload["attempt_ordinal"] = 1000000
    request_hash, _size = _store(fixture.request_path, payload)
    with pytest.raises(GateBLoaderError, match="six-digit"):
        load_gate_b_loader_request(
            fixture.request_path,
            expected_sha256=request_hash,
            expected_readiness_authorization_sha256=payload["readiness_authorization"]["sha256"],
            expected_readiness_approval_record_sha256=APPROVAL_HASH,
            expected_readiness_signature_record_sha256=SIGNATURE_HASH,
        )


@pytest.mark.parametrize(
    "relative",
    [
        "configs/\u00e9.json",
        "configs/control\u0001.json",
        "https://fixture.invalid/input.json",
    ],
)
def test_indexed_relative_path_requires_printable_ascii_posix_grammar(
    relative: str,
) -> None:
    with pytest.raises(GateBTestInputFailure, match="unsafe"):
        loader_module._child(Path("synthetic-root"), relative)


@pytest.mark.parametrize(
    "relative",
    [
        "./v/python.exe",
        "v//python.exe",
        "v:stream",
        "https://fixture.invalid/python.exe",
        "v/\u00e9.exe",
        "v/control\u0001.exe",
    ],
)
def test_dependency_lock_relative_paths_require_canonical_posix_grammar(
    relative: str,
) -> None:
    with pytest.raises(
        (GateBLoaderError, GateBExecutionEnvironmentFailure),
        match="canonical|ASCII",
    ):
        loader_module._canonical_repository_relative_path(relative, "locked executable")


def test_selected_config_count_rejects_json_boolean(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    payload = json.loads(
        fixture.component_paths["selected_config_lock"].read_bytes().decode("utf-8")
    )
    primary_raw = canonical_json_bytes(payload["selected_config"])
    payload["selected_config_count"] = True
    with pytest.raises(GateBTestInputFailure, match="identity"):
        loader_module._validate_selected_lock(fixture.request, payload)
    index = json.loads(
        fixture.component_paths["execution_config_index"].read_bytes().decode("utf-8")
    )
    index["primary"]["size_bytes"] = float(len(primary_raw))
    with pytest.raises(GateBLoaderError, match="positive integer"):
        loader_module._validate_execution_index(fixture.request, index, primary_raw)


def test_gate_b_implementation_imports_only_public_cross_module_names() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    modules = (
        repository_root / "src" / "phase6" / "gate_b_contracts.py",
        repository_root / "src" / "phase6" / "gate_b_ledger.py",
        repository_root / "src" / "phase6" / "gate_b_loader.py",
    )
    forbidden_modules = {"phase6.gate_b_contracts", "phase6.gate_b_ledger"}
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        private_imports = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module in forbidden_modules
            for alias in node.names
            if alias.name.startswith("_")
        ]
        assert private_imports == []


def test_public_loader_error_graph_is_path_free(tmp_path: Path) -> None:
    secret_path = (
        tmp_path / "gate-b-fixture" / "test-root" / "fixture-secret-sentinel.json"
    ).resolve()
    with pytest.raises(GateBLoaderError) as caught:
        load_gate_b_loader_request(
            secret_path,
            expected_sha256="a" * 64,
            expected_readiness_authorization_sha256="b" * 64,
            expected_readiness_approval_record_sha256=APPROVAL_HASH,
            expected_readiness_signature_record_sha256=SIGNATURE_HASH,
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert str(secret_path) not in str(caught.value)
    assert str(secret_path) not in repr(caught.value)


def test_success_frames_every_component_and_allows_result_after_eof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    sibling = fixture.test_root / "unindexed.json"
    sibling.write_bytes(b"must-not-open")
    opened = []
    original_open = loader_module._PinnedInput.open_unread_at.__func__

    def track_open(cls, root_descriptor, root, relative):
        opened.append(root.joinpath(*relative.split("/")))
        return original_open(cls, root_descriptor, root, relative)

    monkeypatch.setattr(loader_module._PinnedInput, "open_unread_at", classmethod(track_open))
    executor = _DrainExecutor(fixture)
    receipt = _open_with_fake_environment(monkeypatch, fixture, executor)
    headers = _frame_headers(bytes(executor.stream))

    assert receipt.state == "SEALED"
    assert [header["name"] for header in headers[1:11]] == list(COMPONENT_NAMES)
    assert [header["frame_type"] for header in headers] == (
        ["batch_context"] + ["component"] * 10 + ["config"] * 3 + ["opponent_payload"]
    )
    assert (
        Path(fixture.request.roots["quarantine_base"]["absolute_path"])
        / fixture.request.batch.test_batch_hash
        / "attempt-000001"
        / "result.json"
    ).read_bytes() == b"{}"
    assert sibling not in opened
    with pytest.raises(GateBCapabilityClosed):
        executor.output_capability.write_chunk("result", b"x")
    with pytest.raises(GateBCapabilityClosed):
        executor.input_capability.read_chunk(1)


def test_first_payload_open_is_immediately_followed_by_started(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    events: list[str] = []
    original_open = loader_module._PinnedInput.open_first_unverified_at.__func__
    original_started = loader_module._append_started
    original_pin = loader_module._PinnedInput.pin_identity

    def open_first(cls, root_descriptor, root, relative):
        events.append("os_open")
        return original_open(cls, root_descriptor, root, relative)

    def append_started(*args, **kwargs):
        events.append("started_append")
        return original_started(*args, **kwargs)

    def pin_identity(self):
        events.append("descriptor_probe")
        return original_pin(self)

    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified_at",
        classmethod(open_first),
    )
    monkeypatch.setattr(loader_module, "_append_started", append_started)
    monkeypatch.setattr(loader_module._PinnedInput, "pin_identity", pin_identity)
    executor = _DrainExecutor(fixture)
    _open_with_fake_environment(monkeypatch, fixture, executor)

    assert events[:3] == ["os_open", "started_append", "descriptor_probe"]


def test_reserved_record_tamper_after_first_open_prevents_started_and_payload_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    first_payload_handle = None
    first_payload_verified = False
    first_payload_bytes_read = False
    original_open = loader_module._PinnedInput.open_first_unverified_at.__func__
    original_verify = loader_module._PinnedInput.verify
    original_started = loader_module._append_started
    original_os_read = os.read

    def track_first_open(cls, root_descriptor, root, relative):
        nonlocal first_payload_handle
        first_payload_handle = original_open(cls, root_descriptor, root, relative)
        return first_payload_handle

    def track_verify(self, *args, **kwargs):
        nonlocal first_payload_verified
        if self is first_payload_handle:
            first_payload_verified = True
        return original_verify(self, *args, **kwargs)

    def track_os_read(descriptor, size):
        nonlocal first_payload_bytes_read
        if first_payload_handle is not None and descriptor == first_payload_handle.descriptor:
            first_payload_bytes_read = True
        return original_os_read(descriptor, size)

    def tamper_then_append(*args, **kwargs):
        store = kwargs["store"]
        record_path = store.directory / "record-000001.json"
        raw = record_path.read_bytes()
        tampered = raw.replace(
            b"fixture-ledger-manager",
            b"fixture-ledger-managex",
        )
        assert len(tampered) == len(raw)
        with record_path.open("r+b") as handle:
            handle.seek(0)
            assert handle.write(tampered) == len(tampered)
            handle.flush()
            os.fsync(handle.fileno())
        return original_started(*args, **kwargs)

    class TrackingExecutor(_DrainExecutor):
        def __init__(self, source_fixture):
            super().__init__(source_fixture)
            self.called = False

        def execute(self, input_capability, quarantine_outputs) -> None:
            self.called = True
            super().execute(input_capability, quarantine_outputs)

    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified_at",
        classmethod(track_first_open),
    )
    monkeypatch.setattr(loader_module._PinnedInput, "verify", track_verify)
    monkeypatch.setattr(loader_module, "_append_started", tamper_then_append)
    monkeypatch.setattr(os, "read", track_os_read)
    executor = TrackingExecutor(fixture)

    with pytest.raises((GateBLedgerError, GateBLoaderError)):
        _open_with_fake_environment(monkeypatch, fixture, executor)

    store = GateBLedgerStore(fixture.request)
    assert first_payload_handle is not None
    assert first_payload_verified is False
    assert first_payload_bytes_read is False
    assert executor.called is False
    assert not (store.directory / "record-000002.json").exists()
    assert json.loads((store.directory / "record-000001.json").read_bytes())["to_state"] == (
        "RESERVED"
    )


@pytest.mark.parametrize("mode", ["success", "prestart_failure", "poststart_failure"])
def test_manifest_seal_occurs_only_after_every_test_input_handle_is_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    fixture = _build_fixture(tmp_path)
    tracked = []
    original_unread = loader_module._PinnedInput.open_unread_at.__func__
    original_first = loader_module._PinnedInput.open_first_unverified_at.__func__
    original_seal = loader_module.GateBQuarantine.seal

    def track_unread(cls, root_descriptor, root, relative):
        handle = original_unread(cls, root_descriptor, root, relative)
        tracked.append(handle)
        return handle

    def track_first(cls, root_descriptor, root, relative):
        handle = original_first(cls, root_descriptor, root, relative)
        tracked.append(handle)
        return handle

    def assert_closed_before_seal(self, *args, **kwargs):
        assert tracked
        assert all(handle._closed for handle in tracked)
        return original_seal(self, *args, **kwargs)

    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_unread_at",
        classmethod(track_unread),
    )
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified_at",
        classmethod(track_first),
    )
    monkeypatch.setattr(loader_module.GateBQuarantine, "seal", assert_closed_before_seal)
    if mode == "prestart_failure":
        fixture.component_paths["baseline_table"].write_bytes(b"tampered")
    elif mode == "poststart_failure":
        fixture.payload_path.write_bytes(b"tampered")

    if mode == "success":
        receipt = _open_with_fake_environment(
            monkeypatch,
            fixture,
            _DrainExecutor(fixture),
        )
        assert receipt.state == "SEALED"
    else:
        monkeypatch.setattr(
            loader_module,
            "verify_gate_b_execution_environment",
            lambda request, _context: _evidence(request),
        )
        reservation = reserve_gate_b_attempt(
            fixture.request,
            expected_latest_record_sha256=None,
        )
        prepared = prepare_gate_b_test_open(fixture.request, reservation)
        with pytest.raises(GateBTestInputFailure):
            open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))


def test_operational_loader_uses_pinned_root_child_adapters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_unread",
        classmethod(
            lambda *_args: (_ for _ in ()).throw(AssertionError("path-only open must not be used"))
        ),
    )
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified",
        classmethod(
            lambda *_args: (_ for _ in ()).throw(
                AssertionError("path-only first open must not be used")
            )
        ),
    )
    receipt = _open_with_fake_environment(monkeypatch, fixture, _DrainExecutor(fixture))
    assert receipt.state == "SEALED"


def test_multiprocess_prepare_open_has_one_payload_opener_and_started_order(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_prepare_open_worker,
            args=(
                str(fixture.request_path),
                fixture.request_hash,
                fixture.request.readiness.sha256,
                reservation.reserved_record_sha256,
                start_event,
                results,
            ),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    start_event.set()
    outcomes = [results.get(timeout=60) for _index in range(2)]
    for process in processes:
        process.join(timeout=60)
        assert process.exitcode == 0

    winner = [outcome for outcome in outcomes if outcome[0] == "winner"]
    rejected = [outcome for outcome in outcomes if outcome[0] == "rejected"]
    assert len(winner) == 1
    assert winner[0][1] == ["os_open", "started_append", "descriptor_probe"]
    assert winner[0][2] == "SEALED"
    assert len(rejected) == 1
    assert rejected[0][1] == []
    assert [record.to_state for record in GateBLedgerStore(fixture.request).load_chain()] == [
        "RESERVED",
        "STARTED",
        "SEALED",
    ]


def test_prepare_is_single_use_and_opens_no_test_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    opened = []
    original_open = loader_module._PinnedInput.open_unread_at.__func__
    original_first = loader_module._PinnedInput.open_first_unverified_at.__func__

    def track_open(cls, root_descriptor, root, relative):
        opened.append(root.joinpath(*relative.split("/")))
        return original_open(cls, root_descriptor, root, relative)

    def track_first(cls, root_descriptor, root, relative):
        opened.append(root.joinpath(*relative.split("/")))
        return original_first(cls, root_descriptor, root, relative)

    monkeypatch.setattr(loader_module._PinnedInput, "open_unread_at", classmethod(track_open))
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified_at",
        classmethod(track_first),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)
    assert opened == []
    prepared.close()
    replacement = prepare_gate_b_test_open(fixture.request, reservation)
    assert opened == []
    replacement.close()


def test_lock_identity_is_rechecked_before_any_test_child_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)
    child_verification_called = False

    def reject_lock_identity() -> None:
        raise GateBLedgerError("namespace lock descriptor/path identity mismatch")

    def track_child_verification(*_args, **_kwargs):
        nonlocal child_verification_called
        child_verification_called = True
        raise AssertionError("Test child verification must not run")

    monkeypatch.setattr(prepared._lock, "verify_identity", reject_lock_identity)
    monkeypatch.setattr(loader_module, "_verify_nonpayload_inputs", track_child_verification)
    with pytest.raises(GateBTestInputFailure, match="prestart"):
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    assert child_verification_called is False


def test_prepared_root_handle_blocks_or_rejects_namespace_replacement_before_child_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)
    moved = fixture.test_root.with_name("test-root-moved")
    opened = []
    try:
        fixture.test_root.rename(moved)
    except OSError:
        prepared.close()
        result = "rename_blocked_by_pinned_handle"
    else:
        fixture.test_root.mkdir()
        (fixture.test_root / "replacement-sentinel.txt").write_bytes(b"must-not-open")
        monkeypatch.setattr(
            loader_module,
            "verify_gate_b_execution_environment",
            lambda request, _context: _evidence(request),
        )
        monkeypatch.setattr(
            loader_module._PinnedInput,
            "open_unread_at",
            classmethod(
                lambda _cls, _descriptor, root, relative: opened.append(
                    root.joinpath(*relative.split("/"))
                )
            ),
        )
        with pytest.raises(GateBTestInputFailure):
            open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
        assert opened == []
        result = "replacement_rejected_before_child_open"
    assert result in {
        "rename_blocked_by_pinned_handle",
        "replacement_rejected_before_child_open",
    }


def test_quarantine_base_replacement_during_create_never_reaches_test_or_callback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)
    quarantine_base = Path(fixture.request.roots["quarantine_base"]["absolute_path"])
    moved = quarantine_base.with_name("quarantine-root-moved")
    anchor_raw = (quarantine_base / ".gate-b-root-anchor.json").read_bytes()
    original_claim_exists = ledger_module._namespace_claim_exists
    race_result = []
    test_child_opened = False

    def replace_base_during_create(path, *, base_descriptor=None):
        if path.parent == quarantine_base and not race_result:
            try:
                quarantine_base.rename(moved)
            except OSError:
                race_result.append("rename_blocked_by_pinned_handle")
                raise GateBLedgerError("fixture replacement was blocked") from None
            quarantine_base.mkdir()
            (quarantine_base / ".gate-b-root-anchor.json").write_bytes(anchor_raw)
            race_result.append("replacement_installed")
        return original_claim_exists(path, base_descriptor=base_descriptor)

    def track_test_child(*_args, **_kwargs):
        nonlocal test_child_opened
        test_child_opened = True
        raise AssertionError("Test child must not open after quarantine-base replacement")

    class TrackingExecutor(_DrainExecutor):
        def __init__(self, source_fixture):
            super().__init__(source_fixture)
            self.called = False

        def execute(self, input_capability, quarantine_outputs) -> None:
            self.called = True
            super().execute(input_capability, quarantine_outputs)

    executor = TrackingExecutor(fixture)
    monkeypatch.setattr(ledger_module, "_namespace_claim_exists", replace_base_during_create)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    monkeypatch.setattr(
        loader_module,
        "_verify_nonpayload_inputs",
        track_test_child,
    )
    with pytest.raises((GateBLedgerError, GateBLoaderError)):
        open_gate_b_test_input(prepared, executor=executor)
    assert race_result in [
        ["rename_blocked_by_pinned_handle"],
        ["replacement_installed"],
    ]
    assert test_child_opened is False
    assert executor.called is False


@pytest.mark.parametrize("unavailable", [-1, 0, False])
def test_loader_operational_posix_open_paths_reject_unavailable_nofollow(
    monkeypatch: pytest.MonkeyPatch,
    unavailable: object,
) -> None:
    class FakePosixOs:
        name = "posix"
        O_NOFOLLOW = unavailable
        O_DIRECTORY = 0x10000
        O_RDONLY = 0

        def __init__(self) -> None:
            self.open_calls = []
            self.closed = []
            self.supports_dir_fd = {self.open}

        def open(self, *args, **kwargs):
            self.open_calls.append((args, kwargs))
            raise AssertionError("open must not run without O_NOFOLLOW")

        def dup(self, descriptor):
            return descriptor + 100

        def close(self, descriptor):
            self.closed.append(descriptor)

    fake_os = FakePosixOs()
    monkeypatch.setattr(loader_module, "os", fake_os)
    with pytest.raises(GateBLedgerError, match="O_NOFOLLOW"):
        loader_module._posix_openat("fixture", 0, 0o600, 17)
    with pytest.raises(GateBLedgerError, match="O_NOFOLLOW"):
        loader_module._posix_open_directory(Path("/fixture"))
    with pytest.raises(GateBLedgerError, match="O_NOFOLLOW"):
        loader_module._open_child_from_root(17, Path("/fixture"), "child/artifact.json")
    assert fake_os.open_calls == []
    assert fake_os.closed == [117]


@pytest.mark.parametrize("unavailable", [-1, 0, False])
def test_loader_operational_child_open_rejects_unavailable_directory_flag(
    monkeypatch: pytest.MonkeyPatch,
    unavailable: object,
) -> None:
    class FakePosixOs:
        name = "posix"
        O_NOFOLLOW = 0x20000
        O_DIRECTORY = unavailable
        O_RDONLY = 0

        def __init__(self) -> None:
            self.open_calls = []
            self.closed = []
            self.supports_dir_fd = {self.open}

        def open(self, *args, **kwargs):
            self.open_calls.append((args, kwargs))
            raise AssertionError("open must not run without O_DIRECTORY")

        def dup(self, descriptor):
            return descriptor + 100

        def close(self, descriptor):
            self.closed.append(descriptor)

    fake_os = FakePosixOs()
    monkeypatch.setattr(loader_module, "os", fake_os)
    with pytest.raises(GateBLedgerError, match="O_DIRECTORY"):
        loader_module._posix_open_directory(Path("/fixture"))
    with pytest.raises(GateBLedgerError, match="O_DIRECTORY"):
        loader_module._open_child_from_root(17, Path("/fixture"), "child/artifact.json")
    assert fake_os.open_calls == []
    assert fake_os.closed == [117]


@pytest.mark.parametrize("unavailable", [-1, 0, False])
def test_loader_operational_identity_reopen_rejects_unavailable_nofollow_before_open(
    monkeypatch: pytest.MonkeyPatch,
    unavailable: object,
) -> None:
    metadata = SimpleNamespace(
        st_mode=0o100000,
        st_nlink=1,
        st_dev=7,
        st_ino=11,
        st_size=2,
        st_file_attributes=0,
    )

    class FakePosixOs:
        name = "posix"
        O_NOFOLLOW = unavailable
        O_RDONLY = 0
        SEEK_SET = 0

        def __init__(self) -> None:
            self.open_calls = []
            self.read_calls = 0
            self.supports_dir_fd = {self.open}

        def open(self, *args, **kwargs):
            self.open_calls.append((args, kwargs))
            raise AssertionError("identity reopen must not run without O_NOFOLLOW")

        def lseek(self, _descriptor, _offset, _whence):
            return 0

        def read(self, _descriptor, _size):
            self.read_calls += 1
            return b"ok" if self.read_calls == 1 else b""

        def fstat(self, _descriptor):
            return metadata

    fake_os = FakePosixOs()
    monkeypatch.setattr(loader_module, "os", fake_os)
    pinned = loader_module._PinnedInput(
        Path("/fixture/artifact.json"),
        31,
        2,
        "",
        (7, 11),
        (17,),
        "artifact.json",
    )
    with pytest.raises(GateBTestInputFailure, match="identity-reopened"):
        pinned.verify(
            expected_size=2,
            expected_sha256=sha256_bytes(b"ok"),
            canonical=False,
        )
    assert fake_os.open_calls == []


def test_environment_failure_opens_no_test_child_and_stays_prestart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    opened = []
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda *_args: (_ for _ in ()).throw(GateBExecutionEnvironmentFailure("fixture rejection")),
    )
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_unread_at",
        classmethod(
            lambda _cls, _root_descriptor, root, relative: opened.append(
                root.joinpath(*relative.split("/"))
            )
        ),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)

    with pytest.raises(GateBExecutionEnvironmentFailure, match="failed closed") as caught:
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    assert opened == []
    assert str(fixture.test_root) not in str(caught.value)
    assert GateBLedgerStore(fixture.request).load_chain()[-1].from_state == "RESERVED"


@pytest.mark.parametrize(
    ("probe", "bad_value"),
    [
        ("branch", "topic"),
        ("head", "b" * 40),
        ("local", "b" * 40),
        ("cached", "b" * 40),
        ("divergence", "1 0"),
        ("dirty", "?? fixture"),
        ("staged", "fixture.py"),
        ("index_lock", ""),
        ("index_lock_dangling", ""),
    ],
)
def test_environment_git_probe_rejects_every_state_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    probe: str,
    bad_value: str,
) -> None:
    fixture = _build_fixture(tmp_path)
    request = fixture.request
    root = Path(request.execution_context.payload["repository_root"]["absolute_path"])
    (root / ".git").mkdir()
    outputs = {
        "branch": "main",
        "head": COMMIT,
        "local": COMMIT,
        "cached": COMMIT,
        "divergence": "0 0",
        "dirty": "",
        "staged": "",
    }
    if probe == "index_lock":
        (root / ".git" / "index.lock").write_bytes(b"")
    elif probe == "index_lock_dangling":
        monkeypatch.setattr(
            loader_module,
            "_path_entry_present_no_follow",
            lambda path: path.name == "index.lock",
        )
    else:
        outputs[probe] = bad_value

    def fake_git(_root, *arguments, text=True):
        del text
        commands = {
            ("rev-parse", "--git-dir"): str(root / ".git"),
            ("rev-parse", "--git-path", "index"): str(root / "index"),
            ("branch", "--show-current"): outputs["branch"],
            ("rev-parse", "HEAD"): outputs["head"],
            ("rev-parse", "refs/heads/main"): outputs["local"],
            ("rev-parse", "refs/remotes/origin/main"): outputs["cached"],
            (
                "rev-list",
                "--left-right",
                "--count",
                "main...refs/remotes/origin/main",
            ): outputs["divergence"],
            ("status", "--porcelain=v1", "--untracked-files=all"): outputs["dirty"],
            ("diff", "--cached", "--name-only"): outputs["staged"],
        }
        return commands[arguments]

    monkeypatch.setattr(loader_module, "_run_git", fake_git)
    monkeypatch.setattr(loader_module, "_file_snapshot", lambda _path: (1, 2, 3, 4, "a" * 64))
    monkeypatch.setattr(loader_module, "_module_sources", lambda *_args: [])
    monkeypatch.setattr(
        loader_module,
        "_runtime_fingerprint",
        lambda: dict(request.execution_context.payload["runtime_fingerprint"]),
    )
    monkeypatch.setattr(
        loader_module,
        "_verify_dependency_lock",
        lambda *_args: request.execution_context.payload["dependency_lock"]["sha256"],
    )

    with pytest.raises(GateBExecutionEnvironmentFailure, match="state drifted"):
        loader_module.verify_gate_b_execution_environment(request, request.execution_context)


def test_index_lock_presence_uses_lstat_for_dangling_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []
    path = Path("C:/fixture/.git/index.lock")
    monkeypatch.setattr(
        loader_module,
        "_lstat",
        lambda candidate: observed.append(candidate) or SimpleNamespace(),
    )
    assert loader_module._path_entry_present_no_follow(path) is True
    assert observed == [path]

    monkeypatch.setattr(
        loader_module,
        "_lstat",
        lambda _candidate: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert loader_module._path_entry_present_no_follow(path) is False


def test_rebound_canonical_helper_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(loader_module, "canonical_json_bytes", lambda _value: b"not-canonical")
    with pytest.raises(GateBExecutionEnvironmentFailure, match="helper binding"):
        loader_module._verify_helper_bindings()


def _synthetic_module_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    base = tmp_path / "gate-b-fixture"
    for root_name in ("test-root", "ledger-root", "quarantine-root"):
        (base / root_name).mkdir(parents=True, exist_ok=True)
    root = base / "repository-root"
    entries = []
    modules = {}
    paths = {}
    for index, (module_name, relative_path) in enumerate(ACTIVE_MODULE_PATHS):
        path = root / relative_path
        raw = f"# fixture module {index}\n".encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        source_loader = loader_module.importlib.machinery.SourceFileLoader(
            module_name,
            str(path),
        )
        module = SimpleNamespace(
            __name__=module_name,
            __package__="phase6",
            __file__=str(path.resolve()),
            __spec__=SimpleNamespace(
                loader=source_loader,
                origin=str(path.resolve()),
            ),
        )
        monkeypatch.setitem(loader_module.sys.modules, module_name, module)
        entries.append(
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": sha256_bytes(raw),
            }
        )
        modules[module_name] = module
        paths[module_name] = path
    context = SimpleNamespace(
        payload={
            "active_modules": entries,
            "expected_implementation_commit": COMMIT,
        }
    )

    def fake_git(_root, *arguments, text=True):
        del text
        relative_path = arguments[-1].split(":", 1)[1]
        return (root / relative_path).read_bytes()

    monkeypatch.setattr(loader_module, "_run_git", fake_git)
    monkeypatch.setattr(loader_module, "_verify_helper_bindings", lambda: None)
    return root, context, modules, paths


def test_module_sources_exact_four_source_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, context, _modules, _paths = _synthetic_module_fixture(monkeypatch, tmp_path)
    evidence = loader_module._module_sources(root, context)
    assert evidence == context.payload["active_modules"]
    assert sha256_bytes(canonical_json_bytes(evidence)) == sha256_bytes(
        canonical_json_bytes(context.payload["active_modules"])
    )


@pytest.mark.parametrize(
    "attack",
    [
        "package",
        "loader",
        "origin",
        "file",
        "alternate_checkout",
        "shadow",
        "zip",
        "wheel",
        "pyc",
        "context_hash",
        "git_blob",
        "same_version_different_bytes",
    ],
)
def test_module_sources_reject_identity_and_provenance_matrix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    attack: str,
) -> None:
    root, context, modules, paths = _synthetic_module_fixture(monkeypatch, tmp_path)
    module_name, _relative_path = ACTIVE_MODULE_PATHS[0]
    module = modules[module_name]
    path = paths[module_name]
    if attack == "package":
        module.__package__ = "fixture-shadow"
    elif attack in {"loader", "zip", "wheel", "pyc"}:
        module.__spec__.loader = object()
    elif attack == "origin":
        module.__spec__.origin = str(path.with_name("other-origin.py"))
    elif attack == "file":
        module.__file__ = str(path.with_name("other-file.py"))
    elif attack in {"alternate_checkout", "shadow"}:
        alternate = tmp_path / "gate-b-fixture" / "alternate-checkout" / path.name
        alternate.parent.mkdir(parents=True, exist_ok=True)
        alternate.write_bytes(path.read_bytes())
        module.__spec__.origin = str(alternate.resolve())
        module.__file__ = str(alternate.resolve())
    elif attack == "context_hash":
        context.payload["active_modules"][0]["sha256"] = "f" * 64
    elif attack == "git_blob":
        monkeypatch.setattr(
            loader_module,
            "_run_git",
            lambda *_args, **_kwargs: b"different-git-blob\n",
        )
    else:
        path.write_bytes(b"# same version, different bytes\n")
        monkeypatch.setattr(
            loader_module,
            "_run_git",
            lambda _root, *arguments, **_kwargs: (
                root / arguments[-1].split(":", 1)[1]
            ).read_bytes(),
        )
    with pytest.raises(GateBExecutionEnvironmentFailure):
        loader_module._module_sources(root, context)


def test_helper_binding_rejects_wrong_declaring_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = loader_module.sys.modules["phase6.contracts"].sha256_bytes
    monkeypatch.setattr(helper, "__module__", "fixture.shadow")
    with pytest.raises(GateBExecutionEnvironmentFailure, match="helper binding"):
        loader_module._verify_helper_bindings()


def test_dependency_lock_binds_complete_runtime_and_rejects_unknown_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture_base = tmp_path / "gate-b-fixture"
    for root_name in ("test-root", "ledger-root", "quarantine-root"):
        (fixture_base / root_name).mkdir(parents=True, exist_ok=True)
    root = fixture_base / "repository-root"
    venv_executable = root / "v" / "python.exe"
    base_executable = root / "b" / "python.exe"
    pyvenv = root / "pyvenv.cfg"
    site_packages = root / "site"
    for path, raw in (
        (venv_executable, b"venv-python"),
        (base_executable, b"base-python"),
        (pyvenv, b"home = fixture\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    site_packages.mkdir()
    runtime = {
        "compiler": "fixture-compiler",
        "implementation": "CPython",
        "platform": "fixture-platform",
        "version": "3.12.0",
    }
    lock_payload = {
        "schema_version": "phase6-production-dependency-lock-v1",
        "lock_scope": "complete-installed-environment-snapshot",
        "distributions": [
            {"name": "fixture-a", "version": "1.0"},
            {"name": "fixture-b", "version": "2.0"},
        ],
        "project": {
            "git_commit": COMMIT,
            "name": "fixture-project",
            "repository_path": ".",
            "source": "repository",
            "version": "1.0",
        },
        "python": {
            "base_executable_path": str(base_executable.resolve()),
            "base_executable_sha256": sha256_bytes(base_executable.read_bytes()),
            "compiler": runtime["compiler"],
            "implementation": runtime["implementation"],
            "platform": runtime["platform"],
            "pyvenv_cfg_path": "pyvenv.cfg",
            "pyvenv_cfg_sha256": sha256_bytes(pyvenv.read_bytes()),
            "site_packages_path": "site",
            "venv_executable_path": "v/python.exe",
            "venv_executable_sha256": sha256_bytes(venv_executable.read_bytes()),
            "version": runtime["version"],
        },
    }
    lock_path = root / "d.json"
    lock_hash, lock_size = _store(lock_path, lock_payload)
    context = SimpleNamespace(
        payload={
            "dependency_lock": {
                "absolute_path": str(lock_path.resolve()),
                "sha256": lock_hash,
                "size_bytes": lock_size,
            },
            "expected_implementation_commit": COMMIT,
        }
    )
    monkeypatch.setattr(loader_module.sys, "executable", str(venv_executable))
    monkeypatch.setattr(loader_module.sys, "_base_executable", str(base_executable))
    monkeypatch.setattr(loader_module.sys, "prefix", str(root))
    monkeypatch.setattr(
        loader_module.sysconfig,
        "get_path",
        lambda name: str(site_packages) if name == "purelib" else "",
    )
    monkeypatch.setattr(loader_module.platform, "python_compiler", lambda: runtime["compiler"])
    monkeypatch.setattr(
        loader_module.platform, "python_implementation", lambda: runtime["implementation"]
    )
    monkeypatch.setattr(loader_module.platform, "platform", lambda: runtime["platform"])
    monkeypatch.setattr(loader_module.platform, "python_version", lambda: runtime["version"])
    monkeypatch.setattr(
        loader_module.importlib.metadata,
        "version",
        lambda _name: "1.0",
    )
    monkeypatch.setattr(
        loader_module,
        "_installed_distributions",
        lambda _name: [
            {"name": "fixture-a", "version": "1.0"},
            {"name": "fixture-b", "version": "2.0"},
        ],
    )

    assert loader_module._verify_dependency_lock(root, context) == lock_hash

    bad = copy.deepcopy(lock_payload)
    bad["unknown"] = True
    bad_hash, bad_size = _store(lock_path, bad)
    context.payload["dependency_lock"].update({"sha256": bad_hash, "size_bytes": bad_size})
    with pytest.raises(GateBExecutionEnvironmentFailure, match="dependency lock verification"):
        loader_module._verify_dependency_lock(root, context)

    variants = []

    def variant(name, mutation):
        changed = copy.deepcopy(lock_payload)
        mutation(changed)
        variants.append((name, changed))

    variant("schema", lambda value: value.update({"schema_version": "fixture-wrong"}))
    variant("scope", lambda value: value.update({"lock_scope": "fixture-partial"}))
    variant("project-field", lambda value: value["project"].pop("source"))
    variant("project-commit", lambda value: value["project"].update({"git_commit": "b" * 40}))
    variant("project-version", lambda value: value["project"].update({"version": "9.0"}))
    variant("project-path", lambda value: value["project"].update({"repository_path": ".."}))
    variant("distribution-missing", lambda value: value["distributions"].pop())
    variant(
        "distribution-extra",
        lambda value: value["distributions"].append({"name": "fixture-c", "version": "3.0"}),
    )
    variant(
        "distribution-duplicate",
        lambda value: value["distributions"].append(copy.deepcopy(value["distributions"][0])),
    )
    variant("distribution-order", lambda value: value["distributions"].reverse())
    variant(
        "distribution-field",
        lambda value: value["distributions"][0].update({"unknown": True}),
    )
    for field, bad_value in (
        ("compiler", "fixture-other-compiler"),
        ("implementation", "FixturePython"),
        ("platform", "fixture-other-platform"),
        ("version", "9.9.9"),
        ("base_executable_path", str((root / "other-base.exe").resolve())),
        ("base_executable_sha256", "f" * 64),
        ("pyvenv_cfg_path", "../pyvenv.cfg"),
        ("pyvenv_cfg_path", "./pyvenv.cfg"),
        ("pyvenv_cfg_sha256", "f" * 64),
        ("site_packages_path", "../site"),
        ("site_packages_path", "site//packages"),
        ("venv_executable_path", "../python.exe"),
        ("venv_executable_path", "v:stream"),
        ("venv_executable_path", "https://fixture.invalid/python.exe"),
        ("venv_executable_sha256", "f" * 64),
    ):
        variant(
            f"python-{field}",
            lambda value, field=field, bad_value=bad_value: value["python"].update(
                {field: bad_value}
            ),
        )
    for _name, changed in variants:
        changed_hash, changed_size = _store(lock_path, changed)
        context.payload["dependency_lock"].update(
            {"sha256": changed_hash, "size_bytes": changed_size}
        )
        with pytest.raises(GateBExecutionEnvironmentFailure):
            loader_module._verify_dependency_lock(root, context)

    baseline_hash, baseline_size = _store(lock_path, lock_payload)
    context.payload["dependency_lock"].update(
        {
            "absolute_path": str(lock_path.resolve()),
            "sha256": "f" * 64,
            "size_bytes": baseline_size,
        }
    )
    with pytest.raises(GateBExecutionEnvironmentFailure):
        loader_module._verify_dependency_lock(root, context)
    context.payload["dependency_lock"].update(
        {
            "absolute_path": str(lock_path.resolve()),
            "sha256": baseline_hash,
            "size_bytes": baseline_size + 1,
        }
    )
    with pytest.raises(GateBExecutionEnvironmentFailure):
        loader_module._verify_dependency_lock(root, context)

    nonregular = root / "lock-directory"
    nonregular.mkdir()
    context.payload["dependency_lock"].update(
        {
            "absolute_path": str(nonregular.resolve()),
            "sha256": baseline_hash,
            "size_bytes": baseline_size,
        }
    )
    with pytest.raises(GateBExecutionEnvironmentFailure):
        loader_module._verify_dependency_lock(root, context)

    missing = root / "missing-lock.json"
    context.payload["dependency_lock"]["absolute_path"] = str(missing.resolve())
    with pytest.raises(GateBExecutionEnvironmentFailure):
        loader_module._verify_dependency_lock(root, context)

    _store(lock_path, lock_payload)
    alias = root / "dependency-lock-hardlink.json"
    try:
        os.link(lock_path, alias)
        capability = "available"
    except PermissionError:
        capability = "insufficient_privilege"
    except OSError:
        capability = "unsupported_by_host_fs"
    assert capability in {
        "available",
        "unsupported_by_host_fs",
        "insufficient_privilege",
    }
    if capability == "available":
        context.payload["dependency_lock"].update(
            {
                "absolute_path": str(alias.resolve()),
                "sha256": sha256_bytes(alias.read_bytes()),
                "size_bytes": len(alias.read_bytes()),
            }
        )
        with pytest.raises(GateBExecutionEnvironmentFailure):
            loader_module._verify_dependency_lock(root, context)
    else:
        context.payload["dependency_lock"].update(
            {
                "absolute_path": str(lock_path.resolve()),
                "sha256": sha256_bytes(lock_path.read_bytes()),
                "size_bytes": len(lock_path.read_bytes()),
            }
        )
        monkeypatch.setattr(
            loader_module,
            "_read_pinned",
            lambda *_args: (_ for _ in ()).throw(
                GateBLedgerError("required aliased-lock primitive failed closed")
            ),
        )
        with pytest.raises(GateBExecutionEnvironmentFailure):
            loader_module._verify_dependency_lock(root, context)


@pytest.mark.parametrize("component_name", COMPONENT_NAMES)
def test_component_tamper_fails_before_started(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, component_name: str
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    fixture.component_paths[component_name].write_bytes(b"tampered")
    prepared = prepare_gate_b_test_open(fixture.request, reservation)

    with pytest.raises(GateBTestInputFailure, match="prestart") as caught:
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    latest = GateBLedgerStore(fixture.request).load_chain()[-1]
    assert (latest.from_state, latest.to_state) == ("RESERVED", "FAILED_CLOSED")
    assert latest.payload["reason_id"] == "fixture-prestart"


def test_first_payload_open_failure_never_creates_started(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    monkeypatch.setattr(
        loader_module._PinnedInput,
        "open_first_unverified_at",
        classmethod(
            lambda _cls, _root_descriptor, _root, _relative: (_ for _ in ()).throw(
                GateBTestInputFailure("synthetic open failure")
            )
        ),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)

    with pytest.raises(GateBTestInputFailure, match="prestart"):
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == ["RESERVED", "FAILED_CLOSED"]
    assert chain[-1].payload["reason_id"] == "fixture-prestart"


def test_proven_absent_started_append_failure_closes_from_reserved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    monkeypatch.setattr(
        loader_module,
        "_append_started",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            loader_module.GateBLedgerError("synthetic append failure")
        ),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    prepared = prepare_gate_b_test_open(fixture.request, reservation)

    with pytest.raises(loader_module.GateBLoaderError, match="STARTED append"):
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == ["RESERVED", "FAILED_CLOSED"]
    assert chain[-1].payload["reason_id"] == "fixture-started-append"


def test_payload_tamper_fails_after_started_and_binds_started_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    reservation = reserve_gate_b_attempt(fixture.request, expected_latest_record_sha256=None)
    fixture.payload_path.write_bytes(b"tampered")
    prepared = prepare_gate_b_test_open(fixture.request, reservation)

    with pytest.raises(GateBTestInputFailure, match="poststart"):
        open_gate_b_test_input(prepared, executor=_DrainExecutor(fixture))
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == [
        "RESERVED",
        "STARTED",
        "FAILED_CLOSED",
    ]
    assert chain[-1].payload["reason_id"] == "fixture-poststart"


def test_pinned_child_reopen_blocks_or_rejects_path_swap(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    ref = fixture.request.batch.payload["components"]["baseline_table"]
    root_descriptor = loader_module._open_directory_descriptor(fixture.test_root)
    handle = loader_module._PinnedInput.open_unread_at(
        root_descriptor,
        fixture.test_root,
        ref["relative_path"],
    )
    moved = target.with_name("baseline-table-moved.json")
    try:
        target.rename(moved)
    except OSError:
        result = "swap_blocked_by_pinned_handle"
    else:
        target.write_bytes(moved.read_bytes())
        with pytest.raises(GateBTestInputFailure, match="substituted"):
            handle.verify(
                expected_size=ref["size_bytes"],
                expected_sha256=ref["sha256"],
                canonical=True,
            )
        result = "replacement_identity_rejected"
    finally:
        handle.close()
        os.close(root_descriptor)
    assert result in {
        "swap_blocked_by_pinned_handle",
        "replacement_identity_rejected",
    }


def test_verified_input_frames_read_only_the_frozen_approved_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    ref = fixture.request.batch.payload["components"]["baseline_table"]
    handle = loader_module._PinnedInput.open_unread(target)
    try:
        approved = handle.verify(
            expected_size=ref["size_bytes"],
            expected_sha256=ref["sha256"],
            canonical=True,
        )
        monkeypatch.setattr(
            loader_module.os,
            "read",
            lambda *_args, **_kwargs: b"unapproved-same-process-reread",
        )
        handle.reset()
        first = handle.read(7)
        second = handle.read(len(approved))
        assert first + second == approved
        assert handle.read(1) == b""
    finally:
        handle.close()


def test_hardlink_capability_is_rejected_or_fails_closed_with_fake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    alias = target.parent / "hardlink.json"
    try:
        os.link(target, alias)
        capability = "available"
    except PermissionError:
        capability = "insufficient_privilege"
    except OSError:
        capability = "unsupported_by_host_fs"
    assert capability in {
        "available",
        "unsupported_by_host_fs",
        "insufficient_privilege",
    }
    if capability == "available":
        with pytest.raises(GateBTestInputFailure, match="single-link"):
            loader_module._PinnedInput.open_unread(target)
    else:
        monkeypatch.setattr(
            loader_module,
            "_open_existing_descriptor",
            lambda _path: (_ for _ in ()).throw(
                loader_module.GateBLedgerError("required hardlink primitive failed closed")
            ),
        )
        with pytest.raises(GateBTestInputFailure, match="failed closed"):
            loader_module._PinnedInput.open_unread(target)


def test_hardlink_added_after_open_is_rejected_on_postread_revalidation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    ref = fixture.request.batch.payload["components"]["baseline_table"]
    root_descriptor = loader_module._open_directory_descriptor(fixture.test_root)
    handle = loader_module._PinnedInput.open_unread_at(
        root_descriptor,
        fixture.test_root,
        ref["relative_path"],
    )
    alias = target.parent / "post-open-hardlink.json"
    try:
        try:
            os.link(target, alias)
            capability = "available"
        except PermissionError:
            capability = "insufficient_privilege"
        except OSError:
            capability = "unsupported_by_host_fs"
        assert capability in {
            "available",
            "unsupported_by_host_fs",
            "insufficient_privilege",
        }
        if capability != "available":
            original_fstat = loader_module.os.fstat

            def fake_fstat(descriptor):
                metadata = original_fstat(descriptor)
                if descriptor == handle.descriptor:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_nlink=2,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_size=metadata.st_size,
                        st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                    )
                return metadata

            monkeypatch.setattr(loader_module.os, "fstat", fake_fstat)
        with pytest.raises(GateBTestInputFailure, match="single-link"):
            handle.verify(
                expected_size=ref["size_bytes"],
                expected_sha256=ref["sha256"],
                canonical=True,
            )
    finally:
        handle.close()
        os.close(root_descriptor)


def test_symlink_capability_is_rejected_or_fails_closed_with_fake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    alias = target.parent / "symlink.json"
    try:
        os.symlink(target, alias)
        capability = "available"
    except PermissionError:
        capability = "insufficient_privilege"
    except OSError:
        capability = "unsupported_by_host_fs"
    assert capability in {
        "available",
        "unsupported_by_host_fs",
        "insufficient_privilege",
    }
    if capability == "available":
        with pytest.raises(GateBTestInputFailure):
            loader_module._PinnedInput.open_unread(alias)
    else:
        monkeypatch.setattr(
            loader_module,
            "_open_existing_descriptor",
            lambda _path: (_ for _ in ()).throw(
                loader_module.GateBLedgerError("required symlink primitive failed closed")
            ),
        )
        with pytest.raises(GateBTestInputFailure, match="failed closed"):
            loader_module._PinnedInput.open_unread(target)


def test_ads_capability_result_and_fake_dispatch_are_non_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = _build_fixture(tmp_path)
    target = fixture.component_paths["baseline_table"]
    if os.name != "nt":
        capability = "platform_not_applicable"
    else:
        try:
            Path(f"{target}:fixture-stream").write_bytes(b"ads")
            capability = "available"
        except PermissionError:
            capability = "insufficient_privilege"
        except OSError:
            capability = "unsupported_by_host_fs"
    assert capability in {
        "available",
        "platform_not_applicable",
        "unsupported_by_host_fs",
        "insufficient_privilege",
    }
    if capability == "available":
        with pytest.raises(GateBTestInputFailure, match="single-link"):
            loader_module._PinnedInput.open_unread(target)
    else:
        monkeypatch.setattr(
            loader_module,
            "_windows_stream_names",
            lambda _path: ("::$DATA", ":fixture:$DATA"),
        )
        with pytest.raises(GateBTestInputFailure, match="single-link"):
            loader_module._PinnedInput.open_unread(target)


@pytest.mark.parametrize("failed_event", ["input_eof", "output_write"])
def test_callback_log_storage_failure_claims_no_complete_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed_event: str
) -> None:
    fixture = _build_fixture(tmp_path)
    original_append = loader_module._AccessLog.append

    def fail_selected(self, event_type, **kwargs):
        if event_type == failed_event:
            raise loader_module.GateBPartialEvidenceError("synthetic access-log durability failure")
        return original_append(self, event_type, **kwargs)

    monkeypatch.setattr(loader_module._AccessLog, "append", fail_selected)

    class CatchingExecutor(_DrainExecutor):
        def execute(self, input_capability, quarantine_outputs):
            try:
                while input_capability.read_chunk(1048576):
                    pass
                quarantine_outputs.write_chunk("result", b"{}")
            except loader_module.GateBPartialEvidenceError:
                return None

    with pytest.raises(loader_module.GateBPartialEvidenceError, match="storage failed"):
        _open_with_fake_environment(monkeypatch, fixture, CatchingExecutor(fixture))
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == ["RESERVED", "STARTED"]
    attempt = (
        Path(fixture.request.roots["quarantine_base"]["absolute_path"])
        / fixture.request.batch.test_batch_hash
        / "attempt-000001"
    )
    assert not (attempt / "quarantine-manifest.json").exists()


def test_short_access_log_write_returns_no_acknowledgement_or_complete_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    original_access = loader_module.GateBQuarantine.access_log_handle

    def short_access(self):
        return _ShortWriteHandle(original_access(self))

    monkeypatch.setattr(loader_module.GateBQuarantine, "access_log_handle", short_access)
    with pytest.raises(loader_module.GateBPartialEvidenceError) as caught:
        _open_with_fake_environment(monkeypatch, fixture, _DrainExecutor(fixture))
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert [record.to_state for record in GateBLedgerStore(fixture.request).load_chain()] == [
        "RESERVED"
    ]


def test_short_output_write_returns_no_acknowledgement_or_complete_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    original_writable = loader_module.GateBQuarantine.writable_handle

    def short_result(self, name):
        handle = original_writable(self, name)
        return _ShortWriteHandle(handle) if name == "result" else handle

    monkeypatch.setattr(loader_module.GateBQuarantine, "writable_handle", short_result)
    with pytest.raises(loader_module.GateBPartialEvidenceError) as caught:
        _open_with_fake_environment(monkeypatch, fixture, _DrainExecutor(fixture))
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert [record.to_state for record in GateBLedgerStore(fixture.request).load_chain()] == [
        "RESERVED",
        "STARTED",
    ]


@pytest.mark.parametrize(
    "mode",
    [
        "early_none",
        "non_none",
        "raised",
        "caught_repeated_eof",
        "uncaught_repeated_eof",
        "invalid_post_eof_output",
    ],
)
def test_executor_contract_failures_never_seal_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    fixture = _build_fixture(tmp_path)

    class InvalidExecutor(_DrainExecutor):
        def execute(self, input_capability, quarantine_outputs):
            if mode == "early_none":
                return None
            if mode == "raised":
                raise RuntimeError("synthetic-secret-sentinel")
            if mode == "non_none":
                while input_capability.read_chunk(1048576):
                    pass
                return "not-none"
            while input_capability.read_chunk(1048576):
                pass
            if mode == "uncaught_repeated_eof":
                input_capability.read_chunk(1)
            if mode == "invalid_post_eof_output":
                with pytest.raises(GateBExecutorContractViolation):
                    quarantine_outputs.write_chunk("access_log", b"x")
                return None
            with pytest.raises(GateBExecutorContractViolation):
                input_capability.read_chunk(1)
            return None

    with pytest.raises(GateBExecutorFailure, match="failed closed") as caught:
        _open_with_fake_environment(monkeypatch, fixture, InvalidExecutor(fixture))
    assert "synthetic-secret-sentinel" not in str(caught.value)
    assert str(fixture.test_root) not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    latest = GateBLedgerStore(fixture.request).load_chain()[-1]
    assert (latest.from_state, latest.to_state) == ("STARTED", "FAILED_CLOSED")
    assert latest.payload["reason_id"] == "fixture-executor"


def test_request_rejects_root_hash_drift_without_default_discovery(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path)
    payload = json.loads(fixture.request_path.read_bytes())
    changed = copy.deepcopy(payload)
    changed["roots"]["test_root"]["file_id_hex"] = "1"
    bad_path = fixture.request_path.parent / "bad-request.json"
    bad_hash, _bad_size = _store(bad_path, changed)

    with pytest.raises(Exception, match="physical identity"):
        load_gate_b_loader_request(
            bad_path,
            expected_sha256=bad_hash,
            expected_readiness_authorization_sha256=payload["readiness_authorization"]["sha256"],
            expected_readiness_approval_record_sha256=APPROVAL_HASH,
            expected_readiness_signature_record_sha256=SIGNATURE_HASH,
        )
