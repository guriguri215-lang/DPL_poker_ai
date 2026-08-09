"""Synthetic-only tests for pinned Gate B orchestration."""

from __future__ import annotations

import ast
import copy
import importlib.metadata
import inspect
import io
import json
import os
import platform as platform_module
import stat
import sys
import sysconfig
import textwrap
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import MappingProxyType, SimpleNamespace
from typing import Literal

import pytest
from test_gate_b_contracts import _v2_chain_fixture
from test_gate_b_contracts import batch_payload as _contract_batch_payload
from test_gate_b_executor import _build_genuine_evidence
from test_gate_b_loader import (
    _build_fixture as _build_loader_fixture,
)
from test_gate_b_loader import (
    _evidence as _loader_evidence,
)

import phase6.gate_b_ledger as ledger_module
import phase6.gate_b_loader as loader_module
import phase6.gate_b_orchestrator as orchestrator
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACTIVE_MODULE_PATHS,
    DEPENDENCY_LOCK_SCHEMA_VERSION,
    EXECUTION_CONTEXT_SCHEMA_VERSION,
    HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
    HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
    LOADER_REQUEST_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_SCHEMA_VERSION,
    ROOT_ANCHOR_SCHEMA_VERSION,
    _root_identity_payload,
    build_gate_b_preapproval_root_identity_projection,
)
from phase6.gate_b_executor import GateBDeadlineExceeded, GateBExecutorError
from phase6.gate_b_ledger import (
    GateBLedgerError,
    GateBLedgerStore,
    GateBPinnedDirectory,
)
from phase6.gate_b_loader import (
    GateBLoaderError,
    GateBLoaderRequest,
    GateBPartialEvidenceError,
)
from phase6.gate_b_orchestrator import (
    READINESS_SPEC_V2_SCHEMA,
    REQUEST_SPEC_V2_SCHEMA,
    GateBMaterializationError,
    GateBPinnedSpecReference,
    GateBPreflightError,
    GateBSpecError,
    GateBV2CompatibilityMaterializationSpecs,
    execute_gate_b_once,
    materialize_gate_b_readiness,
    prepare_gate_b_v2_compatibility,
    validate_gate_b_v2_compatibility_materialization_specs,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
COMMIT = "d" * 40


@pytest.fixture
def tmp_path(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    root = tmp_path_factory.getbasetemp().resolve()
    case_parent = root / "c"
    case_parent.mkdir(parents=True, exist_ok=True)
    case = case_parent / sha256_bytes(request.node.nodeid.encode("utf-8"))[:12]
    resolved_case = case.resolve(strict=False)
    if root not in resolved_case.parents:
        raise AssertionError("synthetic test case escapes the authorized root")
    resolved_case.mkdir(parents=False, exist_ok=False)
    return resolved_case


def _store(path: Path, payload: object) -> tuple[str, int]:
    raw = payload if type(payload) is bytes else canonical_json_bytes(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw), len(raw)


def _v2_specs_fixture():
    fixture = _v2_chain_fixture()
    hashes = dict(fixture.chain.artifact_hashes)
    readiness = {
        "schema_version": READINESS_SPEC_V2_SCHEMA,
        "artifact_type": "gate_b_readiness_materialization_spec",
        "projection_descriptor": fixture.descriptor,
        "approval_record_sha256": hashes["approval_record"],
        "signature_record_sha256": hashes["signature_record"],
        "readiness_authorization_sha256": hashes["readiness_authorization"],
    }
    readiness_raw = canonical_json_bytes(readiness)
    request = {
        "schema_version": REQUEST_SPEC_V2_SCHEMA,
        "artifact_type": "gate_b_request_materialization_spec",
        "projection_descriptor": fixture.descriptor,
        "approval_record_sha256": hashes["approval_record"],
        "signature_record_sha256": hashes["signature_record"],
        "readiness_authorization_sha256": hashes["readiness_authorization"],
        "root_anchor_sha256s": {
            "ledger_base": hashes["ledger_root_anchor"],
            "quarantine_base": hashes["quarantine_root_anchor"],
        },
        "loader_request_sha256": hashes["loader_request"],
    }
    request_raw = canonical_json_bytes(request)
    specs = validate_gate_b_v2_compatibility_materialization_specs(
        fixture.chain,
        readiness_spec_raw=readiness_raw,
        expected_readiness_spec_sha256=sha256_bytes(readiness_raw),
        request_spec_raw=request_raw,
        expected_request_spec_sha256=sha256_bytes(request_raw),
    )
    return SimpleNamespace(
        chain_fixture=fixture,
        readiness=readiness,
        readiness_raw=readiness_raw,
        request=request,
        request_raw=request_raw,
        specs=specs,
    )


def _identity(path: Path) -> tuple[str, str]:
    metadata = path.stat()
    return format(metadata.st_dev, "x"), format(metadata.st_ino, "x")


def _artifact_reference(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    volume_id, file_id = _identity(path.parent)
    return {
        "parent_absolute_path": str(path.parent.resolve()),
        "parent_volume_id_hex": volume_id,
        "parent_file_id_hex": file_id,
        "direct_child_name": path.name,
        "expected_sha256": sha256_bytes(raw),
        "expected_size_bytes": len(raw),
    }


def _output_reference(path: Path) -> dict[str, object]:
    volume_id, file_id = _identity(path.parent)
    return {
        "parent_absolute_path": str(path.parent.resolve()),
        "parent_volume_id_hex": volume_id,
        "parent_file_id_hex": file_id,
        "direct_child_name": path.name,
    }


def _directory_reference(path: Path) -> dict[str, str]:
    volume_id, file_id = _identity(path)
    return {
        "absolute_path": str(path.resolve()),
        "volume_id_hex": volume_id,
        "file_id_hex": file_id,
    }


def _spec_reference(path: Path) -> GateBPinnedSpecReference:
    reference = _artifact_reference(path)
    return GateBPinnedSpecReference(
        Path(reference["parent_absolute_path"]),
        reference["parent_volume_id_hex"],
        reference["parent_file_id_hex"],
        reference["direct_child_name"],
        reference["expected_sha256"],
        reference["expected_size_bytes"],
    )


def _approval_payload() -> dict[str, object]:
    return {
        "schema_version": HUMAN_APPROVAL_RECORD_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_approval_record",
        "approval_record_id": "synthetic-approval-001",
        "approved_at_utc": "2026-07-26T00:00:00Z",
        "approver_actor_id": "synthetic-human",
        "approver_role": "human_gate_b_approver",
        "approval_decision": "APPROVE_INITIAL_GATE_B_READINESS",
        "approval_scope": "initial_attempt_only",
        "test_batch_hash": HASH_A,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": HASH_B,
        "approved_roots_sha256": HASH_C,
        "authorized_runner_actor_id": "synthetic-runner",
        "authorized_runner_role": "test_runner",
        "authorized_ledger_manager_actor_id": "synthetic-ledger-manager",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "synthetic-release-approver",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "synthetic-retry-approver",
        "designated_retry_approver_role": "retry_approver",
        "expected_attempt_ordinal": 1,
        "release_authorized": False,
        "retry_authorized": False,
    }


def _signature_payload(approval_sha256: str) -> dict[str, object]:
    return {
        "schema_version": HUMAN_SIGNATURE_RECORD_SCHEMA_VERSION,
        "artifact_type": "gate_b_human_signature_record",
        "signature_record_id": "synthetic-signature-001",
        "signed_at_utc": "2026-07-26T00:00:01Z",
        "signer_actor_id": "synthetic-human",
        "signer_role": "human_gate_b_attestor",
        "signature_method": "human-governance-attestation-v1",
        "attestation": "ATTEST_EXACT_GATE_B_APPROVAL_RECORD",
        "approval_record_id": "synthetic-approval-001",
        "approval_record_sha256": approval_sha256,
        "test_batch_hash": HASH_A,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": HASH_B,
        "approved_roots_sha256": HASH_C,
    }


def _readiness_payload(approval_sha256: str, signature_sha256: str) -> dict[str, object]:
    return {
        "schema_version": READINESS_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_readiness_authorization",
        "authorization_id": "synthetic-readiness-001",
        "authorized_at_utc": "2026-07-26T00:00:02Z",
        "approval_record_id": "synthetic-approval-001",
        "approval_record_sha256": approval_sha256,
        "signature_record_sha256": signature_sha256,
        "gate_b_ready": True,
        "test_batch_hash": HASH_A,
        "approved_implementation_commit": COMMIT,
        "approved_execution_context_sha256": HASH_B,
        "approved_roots_sha256": HASH_C,
        "authorized_runner_actor_id": "synthetic-runner",
        "authorized_runner_role": "test_runner",
        "authorized_ledger_manager_actor_id": "synthetic-ledger-manager",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "synthetic-release-approver",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "synthetic-retry-approver",
        "designated_retry_approver_role": "retry_approver",
        "ledger_namespace_derivation": "ledger_base/<test_batch_hash>",
        "quarantine_namespace_derivation": (
            "quarantine_base/<test_batch_hash>/attempt-<ordinal:06d>"
        ),
    }


def _human_files(base: Path) -> tuple[Path, Path, dict[str, object]]:
    approval_path = base / "approval.json"
    approval_hash, _size = _store(approval_path, _approval_payload())
    signature_path = base / "signature.json"
    signature_hash, _size = _store(signature_path, _signature_payload(approval_hash))
    readiness = _readiness_payload(approval_hash, signature_hash)
    return approval_path, signature_path, readiness


def test_readiness_materialization_uses_real_pinned_api_and_exact_bytes(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "synthetic-authority"
    specs = tmp_path / "synthetic-specs"
    output = tmp_path / "synthetic-output"
    for path in (authority, specs, output):
        path.mkdir(parents=True)
    approval_path, signature_path, readiness = _human_files(authority)
    output_path = output / "readiness.json"
    spec_path = specs / "readiness-spec.json"
    _store(
        spec_path,
        {
            "schema_version": orchestrator.READINESS_SPEC_SCHEMA,
            "artifact_type": "gate_b_readiness_materialization_spec",
            "output": _output_reference(output_path),
            "approval_record": _artifact_reference(approval_path),
            "signature_record": _artifact_reference(signature_path),
            "authorization_payload": readiness,
        },
    )

    result = materialize_gate_b_readiness(_spec_reference(spec_path))

    assert dict(result) == {
        "schema_version": "phase6-gate-b-cli-materialization-receipt-v1",
        "operation": "materialize-readiness",
        "status": "created",
    }
    assert output_path.read_bytes() == canonical_json_bytes(readiness)


def test_readiness_failure_creates_no_output_and_spec_identity_is_pinned(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "synthetic-authority"
    specs = tmp_path / "synthetic-specs"
    output = tmp_path / "synthetic-output"
    for path in (authority, specs, output):
        path.mkdir(parents=True)
    approval_path, signature_path, readiness = _human_files(authority)
    readiness["authorized_runner_actor_id"] = "synthetic-human"
    output_path = output / "readiness.json"
    spec_path = specs / "readiness-spec.json"
    _store(
        spec_path,
        {
            "schema_version": orchestrator.READINESS_SPEC_SCHEMA,
            "artifact_type": "gate_b_readiness_materialization_spec",
            "output": _output_reference(output_path),
            "approval_record": _artifact_reference(approval_path),
            "signature_record": _artifact_reference(signature_path),
            "authorization_payload": readiness,
        },
    )
    reference = _spec_reference(spec_path)

    with pytest.raises(GateBMaterializationError):
        materialize_gate_b_readiness(reference)
    assert not output_path.exists()

    wrong = GateBPinnedSpecReference(
        reference.parent_absolute_path,
        reference.parent_volume_id_hex,
        "f" * 16,
        reference.direct_child_name,
        reference.expected_sha256,
        reference.expected_size_bytes,
    )
    with pytest.raises(GateBSpecError):
        materialize_gate_b_readiness(wrong)


def _readiness_spec_fixture(
    tmp_path: Path,
) -> tuple[GateBPinnedSpecReference, Path, bytes]:
    authority = tmp_path / "synthetic-authority"
    specs = tmp_path / "synthetic-specs"
    output = tmp_path / "synthetic-output"
    for path in (authority, specs, output):
        path.mkdir(parents=True)
    approval_path, signature_path, readiness = _human_files(authority)
    output_path = output / "readiness.json"
    spec_path = specs / "readiness-spec.json"
    _store(
        spec_path,
        {
            "schema_version": orchestrator.READINESS_SPEC_SCHEMA,
            "artifact_type": "gate_b_readiness_materialization_spec",
            "output": _output_reference(output_path),
            "approval_record": _artifact_reference(approval_path),
            "signature_record": _artifact_reference(signature_path),
            "authorization_payload": readiness,
        },
    )
    return _spec_reference(spec_path), output_path, canonical_json_bytes(readiness)


@pytest.mark.parametrize(
    "failure_stage",
    ["create-collision", "create-failure", "parent-replacement"],
)
def test_readiness_materialization_fails_closed_for_output_races_and_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    reference, output_path, expected_raw = _readiness_spec_fixture(tmp_path)
    original_create = loader_module.GateBPinnedDirectory.create_regular
    replacement_parent = None
    if failure_stage == "create-collision":
        output_path.write_bytes(b"synthetic-existing-output")
    elif failure_stage == "create-failure":
        monkeypatch.setattr(
            loader_module.GateBPinnedDirectory,
            "create_regular",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                GateBLedgerError("synthetic durability failure")
            ),
        )
    else:
        original_parent = output_path.parent
        replacement_parent = original_parent.with_name("synthetic-output-retained")
        original_parent.rename(replacement_parent)
        original_parent.mkdir()

    with pytest.raises(GateBMaterializationError):
        materialize_gate_b_readiness(reference)

    if failure_stage == "create-collision":
        assert output_path.read_bytes() == b"synthetic-existing-output"
    elif failure_stage == "create-failure":
        assert not output_path.exists()
        monkeypatch.setattr(
            loader_module.GateBPinnedDirectory,
            "create_regular",
            original_create,
        )
    else:
        assert replacement_parent is not None
        assert not output_path.exists()
        assert not (replacement_parent / output_path.name).exists()
    assert expected_raw.endswith(b"\n")


@dataclass(frozen=True, slots=True)
class ComponentPlan:
    component_plan_id: str
    materializer: Literal["readiness", "request", "one_shot"]
    operation: Literal["read", "create", "directory"]
    role: str
    ancestor_chain: tuple[Path, ...]
    action: Literal[
        "read_regular",
        "create_regular",
        "open",
        "verify_identity",
        "direct_child_names",
    ]
    source_mode: Literal[
        "named_acquisition",
        "retained_directory",
        "exclusive_create",
    ]
    consumer_sequence: tuple[str, ...]
    checkpoint_sequence: tuple[str, ...]
    allowed_faults: tuple[str, ...]
    allowed_timings: tuple[str, ...]
    terminal_consumer: str
    typed_key: tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class ComponentRegistry:
    plans: tuple[ComponentPlan, ...]
    valid_typed_keys: frozenset[tuple[str, str, str, str]]
    invalid_role_action_keys: tuple[tuple[str, str], ...]

    def __iter__(self):
        return iter(self.plans)

    def __len__(self) -> int:
        return len(self.plans)

    def __getitem__(self, index):
        return self.plans[index]


@dataclass(frozen=True, slots=True)
class DetectorBinding:
    component_plan_id: str
    occurrence: int
    checkpoint: str
    check: str
    action: str
    read_source: Literal["named", "retained"]


@dataclass(frozen=True, slots=True)
class MutationEdge:
    platform: Literal["posix", "windows"]
    component_plan_id: str
    occurrence: int
    selected_ancestor_index: int
    checkpoint: str
    fault: str
    changed_fields: tuple[str, ...]
    adapter_id: str | None
    remaining_consumer_suffix: tuple[str, ...]
    candidate_detector: DetectorBinding | None
    candidate_retained_neutralization_suffix: tuple[str, ...]
    disposition: str


@dataclass(frozen=True, slots=True)
class ConsumerOccurrenceEvidence:
    token: str
    materializer: str
    component_plan_id: str | None
    occurrence: int
    action: str
    checkpoint_reached: str | None
    logical_role: str | None
    bundle_slot_role: str | None
    source_kind: str
    reference_path: Path | None
    parent_reference_path: Path | None
    physical_identity: tuple[str, str] | None
    parent_physical_identity: tuple[str, str] | None
    selected_ancestor_index: int | None
    selected_ancestor_path: Path | None
    selected_ancestor_pre_identity: tuple[str, str] | None
    selected_ancestor_post_identity: tuple[str, str] | None
    named_read_delta: int
    retained_read_delta: int
    named_write_delta: int
    retained_write_delta: int
    mutation_observed: bool
    detector_check: str | None
    terminal_observation: str | None
    handles_opened: int
    handles_closed: int


class ConsumerEvidenceRecorder:
    def __init__(self) -> None:
        self._records: list[ConsumerOccurrenceEvidence] = []

    @property
    def records(self) -> tuple[ConsumerOccurrenceEvidence, ...]:
        return tuple(self._records)

    def append(self, record: ConsumerOccurrenceEvidence) -> None:
        if self._records and (
            record.materializer,
            record.component_plan_id,
            record.occurrence,
            record.token,
        ) == (
            self._records[-1].materializer,
            self._records[-1].component_plan_id,
            self._records[-1].occurrence,
            self._records[-1].token,
        ):
            raise AssertionError("duplicate consumer occurrence evidence")
        self._records.append(record)


@dataclass(slots=True)
class RealRouteContext:
    platform: Literal["posix", "windows"]
    state: _InjectedPinnedPlatformState
    selected_plan: ComponentPlan
    selected_occurrence: int
    selected_ancestor_index: int

    def __post_init__(self) -> None:
        if self.selected_occurrence <= 0:
            raise AssertionError("route occurrence must be positive")
        if not 0 <= self.selected_ancestor_index < len(self.selected_plan.ancestor_chain):
            raise AssertionError("selected ancestor is outside the frozen plan")

    @property
    def target_parent(self) -> Path:
        return self.selected_plan.ancestor_chain[-1]

    @property
    def selected_ancestor_path(self) -> Path:
        return self.selected_plan.ancestor_chain[self.selected_ancestor_index]

    @property
    def direct_child_name(self) -> str | None:
        if self.selected_plan.action in {"read_regular", "create_regular"}:
            digest = sha256_bytes(self.selected_plan.component_plan_id.encode("utf-8"))
            return f"artifact-{digest[:12]}.json"
        return None

    @property
    def reference_path(self) -> Path:
        if self.direct_child_name is None:
            return self.target_parent
        return self.target_parent / self.direct_child_name

    @property
    def canonical_raw(self) -> bytes:
        return canonical_json_bytes(
            {
                "component_plan_id": self.selected_plan.component_plan_id,
                "logical_role": self.selected_plan.role,
                "reference_path": self.reference_path.as_posix(),
            }
        )

    def identity_for(self, path: Path, *, mutated: bool = False) -> tuple[str, str]:
        digest = sha256_bytes(str(path).encode("utf-8"))
        if mutated:
            digest = sha256_bytes(f"mutated:{digest}".encode("ascii"))
        volume = digest[:16].lstrip("0") or "0"
        file_id = digest[16:32].lstrip("0") or "0"
        return volume, file_id


@dataclass(frozen=True, slots=True)
class MatrixEvidence:
    edge: MutationEdge
    adapter_invocation_count: int
    mutation_applied: bool
    pre_state_digest: str
    post_state_digest: str
    terminal: str
    production_trace: tuple[str, ...]
    consumer_occurrences: tuple[ConsumerOccurrenceEvidence, ...]

    @property
    def named_reads(self) -> int:
        return sum(item.named_read_delta for item in self.consumer_occurrences)

    @property
    def retained_reads(self) -> int:
        return sum(item.retained_read_delta for item in self.consumer_occurrences)

    @property
    def named_writes(self) -> int:
        return sum(item.named_write_delta for item in self.consumer_occurrences)

    @property
    def retained_writes(self) -> int:
        return sum(item.retained_write_delta for item in self.consumer_occurrences)


class _InjectedPinnedPlatformState:
    platform: Literal["posix", "windows"]

    def __init__(self, fields: tuple[str, ...]) -> None:
        self.baseline = {field: "baseline" for field in fields}
        self.current = dict(self.baseline)
        self.adapter_invocations = 0
        self.named_reads = 0
        self.retained_reads = 0
        self.production_trace: tuple[str, ...] = ()
        self.adapter_trace_prefix: tuple[str, ...] | None = None

    def apply_adapter(self, edge: MutationEdge) -> None:
        if self.adapter_invocations:
            raise AssertionError("adapter invoked more than once")
        self.adapter_invocations += 1
        for field in edge.changed_fields:
            self.current[field] = (
                "mutated",
                self.platform,
                edge.adapter_id,
                field,
            )

    def changed(self, field: str) -> bool:
        return self.current.get(field) != self.baseline.get(field)


class _InjectedPosixPlatformState(_InjectedPinnedPlatformState):
    platform = "posix"


class _InjectedWindowsPlatformState(_InjectedPinnedPlatformState):
    platform = "windows"


class _EmptyScan:
    def __enter__(self):
        return ()

    def __exit__(self, *_args):
        return False


class _ProductionPinnedProbe:
    def __init__(
        self,
        route: RealRouteContext,
        *,
        edge: MutationEdge | None,
    ) -> None:
        self.route = route
        self.state = route.state
        self.action = route.selected_plan.action
        self.edge = edge
        self.trace: list[str] = []
        self.first_changed_field_check: str | None = None
        self.changed_fields_consumed: set[str] = set()
        self._injection_index = (
            None
            if edge is None
            else _EXPECTED_CHECKPOINT_STARTS[self.action][
                _CHECKPOINTS[self.action].index(edge.checkpoint)
            ]
        )
        self._identity_count = 0
        self._existing_open_count = 0
        self._metadata_count = 0
        self._read_count = 0
        self._stream_count = 0
        self._descriptor_sequence = 700
        self._descriptor_info: dict[int, tuple[str, object]] = {
            700: ("directory", route.target_parent)
        }
        self._read_complete: set[int] = set()
        self._directory_final_paths: dict[int, str] = {}

    def observe(self, check: str, fields: frozenset[str]) -> None:
        if check in self.trace:
            return
        if (
            self.edge is not None
            and self._injection_index == len(self.trace)
            and self.state.adapter_invocations == 0
        ):
            self.state.adapter_trace_prefix = tuple(self.trace)
            self.state.apply_adapter(self.edge)
        self.trace.append(check)
        changed = {
            field
            for field in fields
            if self.state.current.get(field) != self.state.baseline.get(field)
        }
        if changed:
            self.changed_fields_consumed.update(changed)
            if self.first_changed_field_check is None:
                self.first_changed_field_check = check

    def finish_operation(self) -> None:
        if self.edge is not None and self.state.adapter_invocations == 0:
            if self._injection_index != len(self.trace):
                raise AssertionError("production primitive did not reach injection checkpoint")
            self.state.adapter_trace_prefix = tuple(self.trace)
            self.state.apply_adapter(self.edge)

    def next_descriptor(self, kind: str, detail: object) -> int:
        self._descriptor_sequence += 1
        descriptor = self._descriptor_sequence
        self._descriptor_info[descriptor] = (kind, detail)
        return descriptor

    def identity_checks(self) -> tuple[str, ...]:
        return {
            "read_regular": (
                "initial_parent_identity",
                "intermediate_parent_identity",
                "final_parent_identity",
            ),
            "create_regular": (
                (
                    "initial_parent_identity",
                    "post_write_parent_identity",
                    "parent_durability",
                    "final_parent_identity",
                )
                if self.state.platform == "windows"
                else (
                    "initial_parent_identity",
                    "post_write_parent_identity",
                    "final_parent_identity",
                )
            ),
            "verify_identity": (
                "complete_target_ancestor_identity",
                "final_identity_comparison",
            ),
            "direct_child_names": (
                "initial_identity",
                "final_identity",
            ),
            "open": ("open_target_ancestor_identity",),
        }[self.action]

    def observe_identity(self) -> None:
        checks = self.identity_checks()
        if self.action == "verify_identity":
            for check in checks:
                self.observe(check, frozenset({"parent_identity", "target_identity"}))
            return
        check = checks[min(self._identity_count, len(checks) - 1)]
        self._identity_count += 1
        fields = {"parent_identity", "target_identity"}
        if self.action == "open":
            fields.add("ancestor_route")
        self.observe(check, frozenset(fields))

    def observe_existing_open(self) -> tuple[str, str]:
        if self.action == "read_regular":
            values = (
                ("first_no_follow_child_open", "first"),
                ("second_no_follow_child_reopen", "reopened"),
            )
        else:
            values = (("no_follow_child_reopen", "reopened"),)
        check, phase = values[self._existing_open_count]
        self._existing_open_count += 1
        self.observe(
            check,
            frozenset(
                {"child_id", "child_reparse", "reopen_availability"}
                if phase == "first"
                else {"reopen_availability"}
            ),
        )
        return check, phase

    def observe_new_open(self) -> None:
        self.observe(
            "exclusive_no_follow_create",
            frozenset({"child_existence", "child_reparse"}),
        )

    def observe_streams(self) -> None:
        checks = (
            ("first_child_ads", "reopened_child_ads")
            if self.action == "read_regular"
            else ("created_child_ads", "reopened_child_ads")
        )
        check = checks[self._stream_count]
        self._stream_count += 1
        self.observe(check, frozenset({"child_streams"}))

    def regular_metadata(self, phase: str):
        if self.action == "read_regular":
            checks = (
                ("first_child_metadata",),
                ("post_read_metadata", "expected_identity_size_hash"),
                ("reopened_child_metadata",),
            )
        else:
            checks = (
                ("created_child_metadata", "created_size_comparison"),
                ("reopened_child_metadata",),
            )
        for check in checks[self._metadata_count]:
            fields = {
                "expected_identity_size_hash": frozenset(
                    {"child_id", "child_bytes", "child_link_count", "child_size"}
                ),
                "created_size_comparison": frozenset({"child_size"}),
            }.get(
                check,
                frozenset(
                    {
                        "child_id",
                        "child_reparse",
                        "child_link_count",
                        "child_size",
                        "reopen_identity",
                    }
                ),
            )
            self.observe(check, fields)
        self._metadata_count += 1
        volume_hex, file_hex = self.route.identity_for(self.route.reference_path)
        identity = (int(volume_hex, 16), int(file_hex, 16))
        if self.state.changed("child_id"):
            volume_hex, file_hex = self.route.identity_for(
                self.route.reference_path,
                mutated=True,
            )
            identity = (
                int(volume_hex, 16),
                int(file_hex, 16) + (1 if phase == "reopened" else 0),
            )
        if phase == "reopened" and self.state.changed("reopen_identity"):
            identity = (identity[0], identity[1] + 2)
        raw = self.route.canonical_raw
        size = len(raw) + 1 if self.state.changed("child_size") else len(raw)
        link_count = 2 if self.state.changed("child_link_count") else 1
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=link_count,
            st_dev=identity[0],
            st_ino=identity[1],
            st_size=size,
            st_file_attributes=(0x400 if self.state.changed("child_reparse") else 0),
        )

    def read_raw(self, phase: str) -> bytes:
        if self.action == "read_regular":
            checks = (
                ("first_raw_read",),
                ("reopened_raw_read", "reopened_identity_bytes_hash"),
            )
        else:
            checks = (("reopened_raw_read", "reopened_identity_bytes_hash"),)
        for check in checks[self._read_count]:
            self.observe(
                check,
                (
                    frozenset({"child_bytes"})
                    if check == "first_raw_read"
                    else frozenset({"reopen_identity", "reopen_bytes"})
                ),
            )
        self._read_count += 1
        if phase == "reopened" and self.state.changed("reopen_bytes"):
            return self.route.canonical_raw + b"r"
        if self.state.changed("child_bytes"):
            return self.route.canonical_raw + b"m"
        return self.route.canonical_raw


class _FakeDriveType:
    argtypes: object = None
    restype: object = None

    def __init__(
        self,
        state: _InjectedPinnedPlatformState,
        *,
        namespace_visible: bool,
    ) -> None:
        self._state = state
        self._namespace_visible = namespace_visible

    def __call__(self, _root: str) -> int:
        return 4 if self._namespace_visible and self._state.changed("volume_class") else 3


def _run_production_primitive(
    route: RealRouteContext,
    plan: ComponentPlan,
    *,
    occurrence: int,
    edge: MutationEdge | None = None,
    recorder: ConsumerEvidenceRecorder,
) -> tuple[tuple[str, ...], str | None, GateBLedgerError | None]:
    if plan is not route.selected_plan or occurrence != route.selected_occurrence:
        raise AssertionError("actual primitive call differs from frozen plan occurrence")
    if edge is not None and (
        edge.component_plan_id != plan.component_plan_id
        or edge.occurrence != occurrence
        or edge.selected_ancestor_index != route.selected_ancestor_index
    ):
        raise AssertionError("mutation edge differs from frozen route binding")
    state = route.state
    action = plan.action
    probe = _ProductionPinnedProbe(route, edge=edge)
    file_flush_count = 0
    descriptor_phases: dict[int, str] = {}
    volume_guid = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"
    namespace_visible = edge is None or edge.checkpoint == "before_acquire"

    def fake_fsync(descriptor: int) -> None:
        nonlocal file_flush_count
        check = "file_flush" if file_flush_count == 0 else "parent_durability"
        file_flush_count += 1
        fields = (
            frozenset({"file_durability"})
            if check == "file_flush"
            else frozenset({"parent_durability", "parent_identity"})
        )
        probe.observe(check, fields)
        if (
            check == "file_flush"
            and state.changed("file_durability")
            or check == "parent_durability"
            and state.changed("parent_durability")
        ):
            raise OSError(f"modeled {check} failure")
        if descriptor not in probe._descriptor_info:
            raise AssertionError("unknown fsync descriptor")

    def fake_close(descriptor: int) -> None:
        info = probe._descriptor_info.get(descriptor)
        if action == "create_regular" and info is not None and info[0] == "new":
            probe.observe("created_descriptor_close", frozenset())

    def fake_scandir(_path):
        probe.observe("retained_enumeration", frozenset())
        return _EmptyScan()

    def fake_listdir(_descriptor):
        probe.observe("retained_enumeration", frozenset())
        return []

    def fake_directory_metadata(*, target: bool) -> SimpleNamespace:
        path = route.target_parent if target else route.selected_ancestor_path
        volume_hex, file_hex = route.identity_for(path)
        identity = (int(volume_hex, 16), int(file_hex, 16))
        if target and (
            state.changed("parent_identity")
            or state.changed("target_identity")
            or state.changed("ancestor_route")
            and action == "open"
        ):
            volume_hex, file_hex = route.identity_for(path, mutated=True)
            identity = (int(volume_hex, 16), int(file_hex, 16))
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_nlink=1,
            st_dev=identity[0],
            st_ino=identity[1],
            st_size=0,
            st_file_attributes=0,
        )

    def fake_fstat(descriptor: int):
        kind, detail = probe._descriptor_info[descriptor]
        if kind == "directory":
            if state.platform == "posix" or (
                state.platform == "windows" and action == "open" and detail == route.target_parent
            ):
                probe.observe_identity()
            return fake_directory_metadata(target=detail == route.target_parent)
        phase = descriptor_phases[descriptor]
        return probe.regular_metadata(phase)

    def fake_read(descriptor: int, _count: int) -> bytes:
        if descriptor in probe._read_complete:
            return b""
        probe._read_complete.add(descriptor)
        return probe.read_raw(descriptor_phases[descriptor])

    def fake_write(_descriptor: int, view: memoryview) -> int:
        probe.observe("exact_complete_write", frozenset({"write_count", "child_size"}))
        if state.changed("write_count"):
            return 0
        return len(view)

    def fake_posix_directory_open(path: Path) -> int:
        probe.observe(
            "acquisition_namespace_classification",
            frozenset(
                {
                    "ancestor_route",
                    "namespace_route",
                    "namespace_class",
                    "volume_class",
                    "stable_namespace",
                }
            ),
        )
        probe._descriptor_info[700] = ("directory", path)
        return 700

    def fake_existing_open(_name: str, *_args, **_kwargs) -> int:
        _check, phase = probe.observe_existing_open()
        if state.changed("reopen_availability") and phase == "reopened":
            raise OSError("modeled reopen failure")
        descriptor = probe.next_descriptor("existing", phase)
        descriptor_phases[descriptor] = phase
        return descriptor

    def fake_new_open(_name: str, *_args, **_kwargs) -> int:
        probe.observe_new_open()
        if state.changed("child_existence"):
            raise FileExistsError("modeled exclusive-create collision")
        descriptor = probe.next_descriptor("new", "created")
        descriptor_phases[descriptor] = "created"
        return descriptor

    def fake_os_open(name: str, flags: int, *_args, **_kwargs) -> int:
        if flags & 0x40:
            return fake_new_open(name)
        return fake_existing_open(name)

    def fake_windows_open(
        path: Path,
        *,
        access: int,
        creation: int,
        share: int,
        directory: bool = False,
    ) -> int:
        del access, share
        if directory:
            if action == "open":
                probe.observe(
                    "acquisition_namespace_classification",
                    frozenset(
                        {
                            "ancestor_route",
                            "namespace_route",
                            "namespace_class",
                            "volume_class",
                            "stable_namespace",
                        }
                    ),
                )
            text = str(path)
            matching_descriptor = next(
                (
                    existing
                    for existing, final_path in probe._directory_final_paths.items()
                    if final_path == text
                ),
                None,
            )
            if matching_descriptor is not None:
                directory_detail = probe._descriptor_info[matching_descriptor][1]
            elif Path(path) == route.target_parent or text.rstrip("\\").endswith(
                route.target_parent.name
            ):
                directory_detail = route.target_parent
            else:
                directory_detail = Path(path)
            descriptor = probe.next_descriptor(
                "directory",
                directory_detail,
            )
            if text.startswith("\\\\?\\Volume{"):
                final_path = text
            else:
                relative = text[3:] if len(text) >= 3 and text[1:3] == ":\\" else text
                final_path = volume_guid + relative.lstrip("\\")
            probe._directory_final_paths[descriptor] = final_path
            return descriptor
        if creation == 1:
            return fake_new_open(str(path))
        return fake_existing_open(str(path))

    def fake_final_path(descriptor: int) -> str:
        baseline = probe._directory_final_paths[descriptor]
        if (
            action == "open"
            and state.changed("ancestor_route")
            and not baseline.rstrip("\\").endswith("typed-model")
        ):
            return volume_guid + "substituted-ancestor"
        if action == "open" and namespace_visible and state.changed("namespace_class"):
            return "\\\\server\\share\\substituted"
        if (
            action == "open"
            and namespace_visible
            and (state.changed("namespace_route") or state.changed("stable_namespace"))
        ):
            return "C:\\substituted"
        return baseline

    def fake_stream_names(_path: Path) -> tuple[str, ...]:
        probe.observe_streams()
        return ("::$DATA", ":attacker:$DATA") if state.changed("child_streams") else ("::$DATA",)

    original_verify_windows_chain = ledger_module._verify_windows_pinned_chain
    original_verify_child_streams = GateBPinnedDirectory._verify_child_streams

    def modeled_verify_windows_chain(chain) -> None:
        probe.observe_identity()
        original_verify_windows_chain(chain)

    def modeled_verify_child_streams(self, name: str) -> None:
        if state.platform == "posix":
            probe.observe_streams()
            return
        original_verify_child_streams(self, name)

    fake_os = SimpleNamespace(
        name="nt" if state.platform == "windows" else "posix",
        O_RDONLY=0,
        O_RDWR=2,
        O_CREAT=0x40,
        O_EXCL=0x80,
        O_NOFOLLOW=0x20000,
        fstat=fake_fstat,
        fsync=fake_fsync,
        close=fake_close,
        open=fake_os_open,
        read=fake_read,
        write=fake_write,
        scandir=fake_scandir,
        listdir=fake_listdir,
    )
    fake_os.supports_dir_fd = {fake_os.open}
    modeled_open_path = route.target_parent
    if state.platform == "windows":
        modeled_open_path = PureWindowsPath("C:/") / PureWindowsPath(
            *route.target_parent.relative_to(_MATRIX_ROOT).parts
        )
    failure: GateBLedgerError | None = None
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(ledger_module, "os", fake_os)
            if state.platform == "windows":
                patch.setattr(ledger_module, "Path", PureWindowsPath)
            patch.setattr(ledger_module, "_posix_open_directory", fake_posix_directory_open)
            patch.setattr(ledger_module, "_windows_create_file_descriptor", fake_windows_open)
            patch.setattr(ledger_module, "_windows_final_path_from_descriptor", fake_final_path)
            patch.setattr(ledger_module, "_windows_stream_names", fake_stream_names)
            patch.setattr(
                ledger_module,
                "_verify_windows_pinned_chain",
                modeled_verify_windows_chain,
            )
            patch.setattr(
                GateBPinnedDirectory,
                "_verify_child_streams",
                modeled_verify_child_streams,
            )
            patch.setattr(
                ledger_module.ctypes,
                "WinDLL",
                lambda *_args, **_kwargs: SimpleNamespace(
                    GetDriveTypeW=_FakeDriveType(
                        state,
                        namespace_visible=namespace_visible,
                    )
                ),
                raising=False,
            )
            if action == "open":
                opened = GateBPinnedDirectory.open(
                    modeled_open_path,
                    expected_volume_id_hex=route.identity_for(route.target_parent)[0],
                    expected_file_id_hex=route.identity_for(route.target_parent)[1],
                )
                opened.close()
            else:
                pinned = object.__new__(GateBPinnedDirectory)
                pinned._path = route.target_parent
                pinned._stable_path = route.target_parent
                pinned._descriptor = 700
                identity = route.identity_for(route.target_parent)
                pinned._expected_identity = (int(identity[0], 16), int(identity[1], 16))
                pinned._windows_chain = (
                    (
                        ledger_module._PinnedWindowsDirectoryHandle(
                            descriptor=700,
                            physical_identity=pinned._expected_identity,
                            final_path=volume_guid + "typed-model",
                        ),
                    )
                    if state.platform == "windows"
                    else ()
                )
                pinned._closed = False
                if state.platform == "windows":
                    probe._directory_final_paths[700] = volume_guid + "typed-model"
                if action == "read_regular":
                    pinned.read_regular(
                        route.direct_child_name,
                        expected_sha256=sha256_bytes(route.canonical_raw),
                        expected_size_bytes=len(route.canonical_raw),
                    )
                elif action == "create_regular":
                    pinned.create_regular(route.direct_child_name, route.canonical_raw)
                elif action == "verify_identity":
                    pinned.verify_identity()
                elif action == "direct_child_names":
                    pinned.direct_child_names()
                else:
                    raise AssertionError("unknown production primitive")
                pinned.close()
            probe.finish_operation()
    except GateBLedgerError as exc:
        failure = exc
    selected_path = route.selected_ancestor_path
    selected_pre = route.identity_for(selected_path)
    selected_post = route.identity_for(
        selected_path,
        mutated=edge is not None and state.adapter_invocations == 1,
    )
    source_kind = {
        "named_acquisition": "named",
        "retained_directory": "retained",
        "exclusive_create": "exclusive-create",
    }[plan.source_mode]
    after_injection_observed = (
        edge is None
        or probe._injection_index is not None
        and probe._injection_index < len(probe.trace)
    )
    recorder.append(
        ConsumerOccurrenceEvidence(
            token=f"{plan.component_plan_id}@{occurrence}",
            materializer=plan.materializer,
            component_plan_id=plan.component_plan_id,
            occurrence=occurrence,
            action=plan.action,
            checkpoint_reached=(
                edge.checkpoint if edge is not None else plan.checkpoint_sequence[-1]
            ),
            logical_role=plan.role,
            bundle_slot_role=None,
            source_kind=source_kind,
            reference_path=route.reference_path,
            parent_reference_path=route.target_parent,
            physical_identity=route.identity_for(route.reference_path),
            parent_physical_identity=route.identity_for(route.target_parent),
            selected_ancestor_index=route.selected_ancestor_index,
            selected_ancestor_path=selected_path,
            selected_ancestor_pre_identity=selected_pre,
            selected_ancestor_post_identity=selected_post,
            named_read_delta=int(
                after_injection_observed and plan.source_mode == "named_acquisition"
            ),
            retained_read_delta=int(
                after_injection_observed
                and plan.source_mode in {"retained_directory", "exclusive_create"}
            ),
            named_write_delta=0,
            retained_write_delta=int(
                after_injection_observed and plan.source_mode == "exclusive_create"
            ),
            mutation_observed=edge is not None and state.adapter_invocations == 1,
            detector_check=probe.first_changed_field_check,
            terminal_observation=(type(failure).__name__ if failure is not None else None),
            handles_opened=1,
            handles_closed=1,
        )
    )
    return tuple(probe.trace), probe.first_changed_field_check, failure


_MATRIX_ROOT = (
    Path(__file__).resolve().parents[2] / ".tmp_gate_b_retained_byte_typed_matrix_successor"
)
_FAULTS = (
    "ancestor-substitution",
    "child-replacement",
    "child-reparse-symlink",
    "child-hardlink-physical-alias",
    "windows-ads",
    "parent-identity-change",
    "create-collision",
    "partial-write",
    "file-flush-failure",
    "parent-flush-failure",
    "reopen-failure",
    "reopen-identity-mismatch",
    "reopen-byte-mismatch",
    "wrong-target-volume-file-id",
    "windows-drive-alias",
    "windows-unc-path",
    "windows-network-volume",
    "windows-volume-guid-unavailable",
)
_WINDOWS_ONLY = {
    "windows-ads",
    "windows-drive-alias",
    "windows-unc-path",
    "windows-network-volume",
    "windows-volume-guid-unavailable",
}
_NAMESPACE_FAULTS = {
    "ancestor-substitution",
    "windows-drive-alias",
    "windows-unc-path",
    "windows-network-volume",
    "windows-volume-guid-unavailable",
}
_CHILD_FAULTS = {
    "child-replacement",
    "child-reparse-symlink",
    "child-hardlink-physical-alias",
    "windows-ads",
}
_CREATE_FAULTS = {
    "create-collision",
    "partial-write",
    "file-flush-failure",
    "parent-flush-failure",
}
_REOPEN_FAULTS = {
    "reopen-failure",
    "reopen-identity-mismatch",
    "reopen-byte-mismatch",
}
_CHECKPOINTS = {
    "read_regular": (
        "before_parent_identity_check",
        "after_parent_identity_check_before_child_open",
        "after_child_open_before_content_check",
        "after_content_check_before_reopen",
        "after_reopen_before_final_parent_check",
        "after_final_parent_check",
    ),
    "create_regular": (
        "before_parent_identity_check",
        "after_parent_identity_check_before_exclusive_open",
        "after_exclusive_open_before_write",
        "after_write_before_file_flush",
        "after_file_flush_before_parent_durability",
        "after_parent_durability_before_reopen",
        "after_reopen_before_final_parent_check",
        "after_final_parent_check",
    ),
    "open": (
        "before_acquire",
        "after_acquire_before_open_identity_check",
        "after_open_identity_check",
    ),
    "verify_identity": (
        "before_identity_check",
        "during_identity_check",
        "after_final_identity_check",
    ),
    "direct_child_names": (
        "before_initial_identity_check",
        "after_initial_check_before_enumeration",
        "after_enumeration_before_final_identity_check",
        "after_final_identity_check",
    ),
}
_EXPECTED_PRIMITIVE_TRACES = MappingProxyType(
    {
        "read_regular": (
            "initial_parent_identity",
            "first_no_follow_child_open",
            "first_child_metadata",
            "first_child_ads",
            "first_raw_read",
            "post_read_metadata",
            "expected_identity_size_hash",
            "intermediate_parent_identity",
            "second_no_follow_child_reopen",
            "reopened_child_metadata",
            "reopened_raw_read",
            "reopened_identity_bytes_hash",
            "reopened_child_ads",
            "final_parent_identity",
        ),
        "create_regular": (
            "initial_parent_identity",
            "exclusive_no_follow_create",
            "exact_complete_write",
            "file_flush",
            "created_child_metadata",
            "created_size_comparison",
            "created_child_ads",
            "post_write_parent_identity",
            "created_descriptor_close",
            "parent_durability",
            "no_follow_child_reopen",
            "reopened_child_metadata",
            "reopened_raw_read",
            "reopened_identity_bytes_hash",
            "reopened_child_ads",
            "final_parent_identity",
        ),
        "open": (
            "acquisition_namespace_classification",
            "open_target_ancestor_identity",
        ),
        "verify_identity": (
            "complete_target_ancestor_identity",
            "final_identity_comparison",
        ),
        "direct_child_names": (
            "initial_identity",
            "retained_enumeration",
            "final_identity",
        ),
    }
)
_EXPECTED_CHECKPOINT_STARTS = MappingProxyType(
    {
        "read_regular": (0, 1, 2, 7, 12, 14),
        "create_regular": (0, 1, 2, 3, 4, 10, 14, 16),
        "open": (0, 1, 2),
        "verify_identity": (0, 1, 2),
        "direct_child_names": (0, 1, 2, 3),
    }
)
_DERIVED = {
    "read_regular": ("read", "retained_directory"),
    "create_regular": ("create", "exclusive_create"),
    "open": ("directory", "named_acquisition"),
    "verify_identity": ("directory", "retained_directory"),
    "direct_child_names": ("directory", "retained_directory"),
}
_FAULT_FIELDS = {
    "ancestor-substitution": ("ancestor_route",),
    "child-replacement": ("child_id", "child_bytes"),
    "child-reparse-symlink": ("child_reparse",),
    "child-hardlink-physical-alias": ("child_link_count", "child_id"),
    "windows-ads": ("child_streams",),
    "parent-identity-change": ("parent_identity",),
    "create-collision": ("child_existence", "child_bytes"),
    "partial-write": ("write_count", "child_size"),
    "file-flush-failure": ("file_durability",),
    "parent-flush-failure": ("parent_durability",),
    "reopen-failure": ("reopen_availability",),
    "reopen-identity-mismatch": ("reopen_identity",),
    "reopen-byte-mismatch": ("reopen_bytes",),
    "wrong-target-volume-file-id": ("target_identity",),
    "windows-drive-alias": ("namespace_route",),
    "windows-unc-path": ("namespace_class",),
    "windows-network-volume": ("volume_class",),
    "windows-volume-guid-unavailable": ("stable_namespace",),
}
_ACTION_FIELDS = {
    "open": {
        "ancestor_route",
        "parent_identity",
        "target_identity",
        "namespace_route",
        "namespace_class",
        "volume_class",
        "stable_namespace",
    },
    "verify_identity": {
        "parent_identity",
        "target_identity",
    },
    "direct_child_names": {
        "parent_identity",
        "target_identity",
    },
    "read_regular": {
        "parent_identity",
        "target_identity",
        "child_id",
        "child_bytes",
        "child_reparse",
        "child_link_count",
        "child_streams",
        "reopen_availability",
        "reopen_identity",
        "reopen_bytes",
    },
    "create_regular": {
        "parent_identity",
        "target_identity",
        "child_id",
        "child_bytes",
        "child_reparse",
        "child_link_count",
        "child_streams",
        "child_existence",
        "write_count",
        "child_size",
        "file_durability",
        "parent_durability",
        "reopen_availability",
        "reopen_identity",
        "reopen_bytes",
    },
}
_SEMANTIC_CONSUMER_SOURCES = MappingProxyType(
    {
        "parse-spec": "immutable",
        "strict-human-trust": "immutable",
        "readiness-bytes-loader": "immutable",
        "readiness-receipt": "immutable",
        "unique-and-join": "immutable",
        "retained-request-join-core": "immutable",
        "request-receipt": "immutable",
        "strict-human-records": "immutable",
        "fresh-human-trust": "immutable",
        "execution-environment-check": "named",
        "executor-construction": "immutable",
        "pre-reservation-proof-boundary": "immutable",
    }
)
_SAFE_SEMANTIC_CONSUMERS = frozenset(
    token for token, source in _SEMANTIC_CONSUMER_SOURCES.items() if source == "immutable"
)


def _tail(
    action: str,
    checkpoint: str,
) -> tuple[tuple[str, frozenset[str]], ...]:
    parent = frozenset({"parent_identity", "target_identity"})
    named_parent = parent | frozenset({"ancestor_route"})
    child_open = frozenset({"child_id", "child_reparse", "reopen_availability"})
    child_meta = frozenset({"child_id", "child_reparse", "child_link_count", "child_size"})
    stream = frozenset({"child_streams"})
    child_bytes = frozenset({"child_bytes"})
    reopen_compare = frozenset({"reopen_identity", "reopen_bytes"})
    sequences = {
        "read_regular": (
            ("initial_parent_identity", parent),
            ("first_no_follow_child_open", child_open),
            ("first_child_metadata", child_meta),
            ("first_child_ads", stream),
            ("first_raw_read", child_bytes),
            ("post_read_metadata", child_meta),
            ("expected_identity_size_hash", child_meta | child_bytes),
            ("intermediate_parent_identity", parent),
            ("second_no_follow_child_reopen", frozenset({"reopen_availability"})),
            ("reopened_child_metadata", child_meta | frozenset({"reopen_identity"})),
            ("reopened_raw_read", frozenset({"reopen_bytes"})),
            ("reopened_identity_bytes_hash", reopen_compare),
            ("reopened_child_ads", stream),
            ("final_parent_identity", parent),
        ),
        "create_regular": (
            ("initial_parent_identity", parent),
            ("exclusive_no_follow_create", frozenset({"child_existence", "child_reparse"})),
            ("exact_complete_write", frozenset({"write_count", "child_size"})),
            ("file_flush", frozenset({"file_durability"})),
            ("created_child_metadata", child_meta),
            ("created_size_comparison", frozenset({"child_size"})),
            ("created_child_ads", stream),
            ("post_write_parent_identity", parent),
            ("created_descriptor_close", frozenset()),
            ("parent_durability", frozenset({"parent_durability", "parent_identity"})),
            ("no_follow_child_reopen", frozenset({"reopen_availability"})),
            ("reopened_child_metadata", child_meta | frozenset({"reopen_identity"})),
            ("reopened_raw_read", frozenset({"reopen_bytes"})),
            ("reopened_identity_bytes_hash", reopen_compare),
            ("reopened_child_ads", stream),
            ("final_parent_identity", parent),
        ),
        "open": (
            (
                "acquisition_namespace_classification",
                frozenset(
                    {
                        "ancestor_route",
                        "namespace_route",
                        "namespace_class",
                        "volume_class",
                        "stable_namespace",
                    }
                ),
            ),
            ("open_target_ancestor_identity", named_parent),
        ),
        "verify_identity": (
            ("complete_target_ancestor_identity", parent),
            ("final_identity_comparison", parent),
        ),
        "direct_child_names": (
            ("initial_identity", parent),
            ("retained_enumeration", frozenset()),
            ("final_identity", parent),
        ),
    }[action]
    starts = {
        "read_regular": (0, 1, 2, 7, 12, 14),
        "create_regular": (0, 1, 2, 3, 4, 10, 14, 16),
        "open": (0, 1, 2),
        "verify_identity": (0, 1, 2),
        "direct_child_names": (0, 1, 2, 3),
    }[action]
    return sequences[starts[_CHECKPOINTS[action].index(checkpoint)] :]


def _graph_tokens(relative_paths: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    counts: dict[str, int] = {}

    def occurrence(plan_id: str) -> str:
        counts[plan_id] = counts.get(plan_id, 0) + 1
        return f"{plan_id}@{counts[plan_id]}"

    def acq(base: str) -> tuple[str, ...]:
        return (occurrence(f"{base}-P-DO"), occurrence(f"{base}-AR"))

    def reverify(base: str) -> tuple[str, ...]:
        return (occurrence(f"{base}-P-DV"), occurrence(f"{base}-AR"))

    counts.clear()
    readiness = (
        *acq("R-SP"),
        "parse-spec",
        *reverify("R-SP"),
        *acq("R-AP"),
        *acq("R-SG"),
        "strict-human-trust",
        occurrence("R-OUT-P-DO"),
        occurrence("R-OUT-XC"),
        "readiness-bytes-loader",
        *reverify("R-AP"),
        *reverify("R-SG"),
        occurrence("R-OUT-P-DV"),
        "readiness-receipt",
    )
    counts.clear()
    request = (
        *acq("Q-SP"),
        "parse-spec",
        *reverify("Q-SP"),
        *acq("Q-BM"),
        *acq("Q-RA"),
        *acq("Q-AP"),
        *acq("Q-SG"),
        *acq("Q-EC"),
        occurrence("Q-TR-DO"),
        occurrence("Q-TR-DV"),
        occurrence("Q-LR-DO"),
        occurrence("Q-LR-DV"),
        occurrence("Q-QR-DO"),
        occurrence("Q-QR-DV"),
        occurrence("Q-LA"),
        occurrence("Q-QA"),
        "unique-and-join",
        "readiness-bytes-loader",
        "strict-human-trust",
        occurrence("Q-OUT-P-DO"),
        occurrence("Q-OUT-XC"),
        occurrence("Q-TR-DV"),
        occurrence("Q-LR-DV"),
        occurrence("Q-QR-DV"),
        "retained-request-join-core",
        *reverify("Q-BM"),
        *reverify("Q-RA"),
        *reverify("Q-AP"),
        *reverify("Q-SG"),
        *reverify("Q-EC"),
        occurrence("Q-LR-DV"),
        occurrence("Q-LA"),
        occurrence("Q-QR-DV"),
        occurrence("Q-QA"),
        occurrence("Q-TR-DV"),
        occurrence("Q-OUT-P-DV"),
        "request-receipt",
    )
    counts.clear()
    calibration_acq = tuple(
        token for relative_path in relative_paths for token in acq(f"O-CA:{relative_path}")
    )
    calibration_reverify = tuple(
        token for relative_path in relative_paths for token in reverify(f"O-CA:{relative_path}")
    )
    one_shot = (
        *acq("O-SP"),
        "parse-spec",
        *reverify("O-SP"),
        *acq("O-RQ"),
        *acq("O-BM"),
        *acq("O-RA"),
        *acq("O-AP"),
        *acq("O-SG"),
        *acq("O-EC"),
        *acq("O-CRM"),
        *calibration_acq,
        occurrence("O-TR-DO"),
        occurrence("O-TR-DV"),
        occurrence("O-LR-DO"),
        occurrence("O-LR-DV"),
        occurrence("O-QR-DO"),
        occurrence("O-QR-DV"),
        occurrence("O-LA"),
        occurrence("O-QA"),
        occurrence("O-CP-DO"),
        occurrence("O-CP-DV"),
        "strict-human-records",
        occurrence("O-TR-DV"),
        occurrence("O-LR-DV"),
        occurrence("O-QR-DV"),
        "retained-request-join-core",
        "readiness-bytes-loader",
        "fresh-human-trust",
        *reverify("O-RQ"),
        *reverify("O-BM"),
        *reverify("O-RA"),
        *reverify("O-AP"),
        *reverify("O-SG"),
        *reverify("O-EC"),
        occurrence("O-LR-DV"),
        occurrence("O-LA"),
        occurrence("O-QR-DV"),
        occurrence("O-QA"),
        *reverify("O-CRM"),
        *calibration_reverify,
        occurrence("O-CP-DE"),
        occurrence("O-LR-DE"),
        occurrence("O-QR-DE"),
        occurrence("O-TR-DV"),
        occurrence("O-LR-DV"),
        occurrence("O-QR-DV"),
        occurrence("O-CP-DV"),
        "execution-environment-check",
        "executor-construction",
        "pre-reservation-proof-boundary",
    )
    return {
        "readiness": readiness,
        "request": request,
        "one_shot": one_shot,
    }


def _component_specs(
    relative_paths: tuple[str, ...],
) -> list[tuple[str, str, str, str]]:
    if relative_paths != tuple(sorted(set(relative_paths))) or not relative_paths:
        raise ValueError("calibration path set must be strict sorted closed")
    rows: list[tuple[str, str, str, str]] = []

    def standalone(materializer: str, base: str, role: str) -> None:
        rows.extend(
            (
                (materializer, f"{base}-P-DO", f"{role}.parent", "open"),
                (materializer, f"{base}-P-DV", f"{role}.parent", "verify_identity"),
                (materializer, f"{base}-AR", role, "read_regular"),
            )
        )

    for base, role in (
        ("R-SP", "readiness.spec"),
        ("R-AP", "readiness.approval_record"),
        ("R-SG", "readiness.signature_record"),
    ):
        standalone("readiness", base, role)
    for base, role in (
        ("Q-SP", "request.spec"),
        ("Q-BM", "request.batch_manifest"),
        ("Q-RA", "request.readiness_authorization"),
        ("Q-AP", "request.human_approval_record"),
        ("Q-SG", "request.human_signature_record"),
        ("Q-EC", "request.execution_context"),
    ):
        standalone("request", base, role)
    for base, role in (
        ("O-SP", "one_shot.spec"),
        ("O-RQ", "one_shot.loader_request"),
        ("O-BM", "one_shot.batch_manifest"),
        ("O-RA", "one_shot.readiness_authorization"),
        ("O-AP", "one_shot.human_approval_record"),
        ("O-SG", "one_shot.human_signature_record"),
        ("O-EC", "one_shot.execution_context"),
        ("O-CRM", "one_shot.calibration_root_manifest"),
    ):
        standalone("one_shot", base, role)
    for relative_path in relative_paths:
        standalone(
            "one_shot",
            f"O-CA:{relative_path}",
            f"one_shot.calibration_artifact:{relative_path}",
        )
    rows.extend(
        (
            ("request", "Q-LA", "request.ledger_root_anchor", "read_regular"),
            ("request", "Q-QA", "request.quarantine_root_anchor", "read_regular"),
            ("one_shot", "O-LA", "one_shot.ledger_root_anchor", "read_regular"),
            ("one_shot", "O-QA", "one_shot.quarantine_root_anchor", "read_regular"),
            ("readiness", "R-OUT-P-DO", "readiness.output.parent", "open"),
            ("readiness", "R-OUT-P-DV", "readiness.output.parent", "verify_identity"),
            ("readiness", "R-OUT-XC", "readiness.output", "create_regular"),
            ("request", "Q-OUT-P-DO", "request.output.parent", "open"),
            ("request", "Q-OUT-P-DV", "request.output.parent", "verify_identity"),
            ("request", "Q-OUT-XC", "request.output", "create_regular"),
        )
    )
    for materializer, base, role, actions in (
        ("request", "Q-TR", "request.test_root", ("open", "verify_identity")),
        ("request", "Q-LR", "request.ledger_base", ("open", "verify_identity")),
        ("request", "Q-QR", "request.quarantine_base", ("open", "verify_identity")),
        ("one_shot", "O-TR", "one_shot.test_root", ("open", "verify_identity")),
        (
            "one_shot",
            "O-LR",
            "one_shot.ledger_base",
            ("open", "verify_identity", "direct_child_names"),
        ),
        (
            "one_shot",
            "O-QR",
            "one_shot.quarantine_base",
            ("open", "verify_identity", "direct_child_names"),
        ),
        (
            "one_shot",
            "O-CP",
            "one_shot.common_parent",
            ("open", "verify_identity", "direct_child_names"),
        ),
    ):
        suffixes = {
            "open": "DO",
            "verify_identity": "DV",
            "direct_child_names": "DE",
        }
        rows.extend(
            (materializer, f"{base}-{suffixes[action]}", role, action) for action in actions
        )
    return rows


_EXPECTED_COMPONENT_SPECS_PREFIX = (
    ("readiness", "R-SP-P-DO", "readiness.spec.parent", "open"),
    ("readiness", "R-SP-P-DV", "readiness.spec.parent", "verify_identity"),
    ("readiness", "R-SP-AR", "readiness.spec", "read_regular"),
    ("readiness", "R-AP-P-DO", "readiness.approval_record.parent", "open"),
    ("readiness", "R-AP-P-DV", "readiness.approval_record.parent", "verify_identity"),
    ("readiness", "R-AP-AR", "readiness.approval_record", "read_regular"),
    ("readiness", "R-SG-P-DO", "readiness.signature_record.parent", "open"),
    ("readiness", "R-SG-P-DV", "readiness.signature_record.parent", "verify_identity"),
    ("readiness", "R-SG-AR", "readiness.signature_record", "read_regular"),
    ("request", "Q-SP-P-DO", "request.spec.parent", "open"),
    ("request", "Q-SP-P-DV", "request.spec.parent", "verify_identity"),
    ("request", "Q-SP-AR", "request.spec", "read_regular"),
    ("request", "Q-BM-P-DO", "request.batch_manifest.parent", "open"),
    ("request", "Q-BM-P-DV", "request.batch_manifest.parent", "verify_identity"),
    ("request", "Q-BM-AR", "request.batch_manifest", "read_regular"),
    ("request", "Q-RA-P-DO", "request.readiness_authorization.parent", "open"),
    ("request", "Q-RA-P-DV", "request.readiness_authorization.parent", "verify_identity"),
    ("request", "Q-RA-AR", "request.readiness_authorization", "read_regular"),
    ("request", "Q-AP-P-DO", "request.human_approval_record.parent", "open"),
    ("request", "Q-AP-P-DV", "request.human_approval_record.parent", "verify_identity"),
    ("request", "Q-AP-AR", "request.human_approval_record", "read_regular"),
    ("request", "Q-SG-P-DO", "request.human_signature_record.parent", "open"),
    ("request", "Q-SG-P-DV", "request.human_signature_record.parent", "verify_identity"),
    ("request", "Q-SG-AR", "request.human_signature_record", "read_regular"),
    ("request", "Q-EC-P-DO", "request.execution_context.parent", "open"),
    ("request", "Q-EC-P-DV", "request.execution_context.parent", "verify_identity"),
    ("request", "Q-EC-AR", "request.execution_context", "read_regular"),
    ("one_shot", "O-SP-P-DO", "one_shot.spec.parent", "open"),
    ("one_shot", "O-SP-P-DV", "one_shot.spec.parent", "verify_identity"),
    ("one_shot", "O-SP-AR", "one_shot.spec", "read_regular"),
    ("one_shot", "O-RQ-P-DO", "one_shot.loader_request.parent", "open"),
    ("one_shot", "O-RQ-P-DV", "one_shot.loader_request.parent", "verify_identity"),
    ("one_shot", "O-RQ-AR", "one_shot.loader_request", "read_regular"),
    ("one_shot", "O-BM-P-DO", "one_shot.batch_manifest.parent", "open"),
    ("one_shot", "O-BM-P-DV", "one_shot.batch_manifest.parent", "verify_identity"),
    ("one_shot", "O-BM-AR", "one_shot.batch_manifest", "read_regular"),
    ("one_shot", "O-RA-P-DO", "one_shot.readiness_authorization.parent", "open"),
    ("one_shot", "O-RA-P-DV", "one_shot.readiness_authorization.parent", "verify_identity"),
    ("one_shot", "O-RA-AR", "one_shot.readiness_authorization", "read_regular"),
    ("one_shot", "O-AP-P-DO", "one_shot.human_approval_record.parent", "open"),
    ("one_shot", "O-AP-P-DV", "one_shot.human_approval_record.parent", "verify_identity"),
    ("one_shot", "O-AP-AR", "one_shot.human_approval_record", "read_regular"),
    ("one_shot", "O-SG-P-DO", "one_shot.human_signature_record.parent", "open"),
    ("one_shot", "O-SG-P-DV", "one_shot.human_signature_record.parent", "verify_identity"),
    ("one_shot", "O-SG-AR", "one_shot.human_signature_record", "read_regular"),
    ("one_shot", "O-EC-P-DO", "one_shot.execution_context.parent", "open"),
    ("one_shot", "O-EC-P-DV", "one_shot.execution_context.parent", "verify_identity"),
    ("one_shot", "O-EC-AR", "one_shot.execution_context", "read_regular"),
    ("one_shot", "O-CRM-P-DO", "one_shot.calibration_root_manifest.parent", "open"),
    (
        "one_shot",
        "O-CRM-P-DV",
        "one_shot.calibration_root_manifest.parent",
        "verify_identity",
    ),
    ("one_shot", "O-CRM-AR", "one_shot.calibration_root_manifest", "read_regular"),
)
_EXPECTED_COMPONENT_SPECS_SUFFIX = (
    ("request", "Q-LA", "request.ledger_root_anchor", "read_regular"),
    ("request", "Q-QA", "request.quarantine_root_anchor", "read_regular"),
    ("one_shot", "O-LA", "one_shot.ledger_root_anchor", "read_regular"),
    ("one_shot", "O-QA", "one_shot.quarantine_root_anchor", "read_regular"),
    ("readiness", "R-OUT-P-DO", "readiness.output.parent", "open"),
    ("readiness", "R-OUT-P-DV", "readiness.output.parent", "verify_identity"),
    ("readiness", "R-OUT-XC", "readiness.output", "create_regular"),
    ("request", "Q-OUT-P-DO", "request.output.parent", "open"),
    ("request", "Q-OUT-P-DV", "request.output.parent", "verify_identity"),
    ("request", "Q-OUT-XC", "request.output", "create_regular"),
    ("request", "Q-TR-DO", "request.test_root", "open"),
    ("request", "Q-TR-DV", "request.test_root", "verify_identity"),
    ("request", "Q-LR-DO", "request.ledger_base", "open"),
    ("request", "Q-LR-DV", "request.ledger_base", "verify_identity"),
    ("request", "Q-QR-DO", "request.quarantine_base", "open"),
    ("request", "Q-QR-DV", "request.quarantine_base", "verify_identity"),
    ("one_shot", "O-TR-DO", "one_shot.test_root", "open"),
    ("one_shot", "O-TR-DV", "one_shot.test_root", "verify_identity"),
    ("one_shot", "O-LR-DO", "one_shot.ledger_base", "open"),
    ("one_shot", "O-LR-DV", "one_shot.ledger_base", "verify_identity"),
    ("one_shot", "O-LR-DE", "one_shot.ledger_base", "direct_child_names"),
    ("one_shot", "O-QR-DO", "one_shot.quarantine_base", "open"),
    ("one_shot", "O-QR-DV", "one_shot.quarantine_base", "verify_identity"),
    ("one_shot", "O-QR-DE", "one_shot.quarantine_base", "direct_child_names"),
    ("one_shot", "O-CP-DO", "one_shot.common_parent", "open"),
    ("one_shot", "O-CP-DV", "one_shot.common_parent", "verify_identity"),
    ("one_shot", "O-CP-DE", "one_shot.common_parent", "direct_child_names"),
)


def _expected_component_specs(
    relative_paths: tuple[str, ...],
) -> tuple[tuple[str, str, str, str], ...]:
    dynamic = tuple(
        row
        for relative_path in relative_paths
        for row in (
            (
                "one_shot",
                f"O-CA:{relative_path}-P-DO",
                f"one_shot.calibration_artifact:{relative_path}.parent",
                "open",
            ),
            (
                "one_shot",
                f"O-CA:{relative_path}-P-DV",
                f"one_shot.calibration_artifact:{relative_path}.parent",
                "verify_identity",
            ),
            (
                "one_shot",
                f"O-CA:{relative_path}-AR",
                f"one_shot.calibration_artifact:{relative_path}",
                "read_regular",
            ),
        )
    )
    return (*_EXPECTED_COMPONENT_SPECS_PREFIX, *dynamic, *_EXPECTED_COMPONENT_SPECS_SUFFIX)


def _target_parent(role: str) -> Path:
    model = _MATRIX_ROOT / "typed-model"
    if "ledger_root_anchor" in role:
        return model / role.split(".", 1)[0] / "ledger_base"
    if "quarantine_root_anchor" in role:
        return model / role.split(".", 1)[0] / "quarantine_base"
    if role.endswith((".test_root", ".ledger_base", ".quarantine_base", ".common_parent")):
        return model / Path(*role.split("."))
    artifact_role = role.removesuffix(".parent")
    return model / Path(*artifact_role.split(".")) / "parent"


def _ancestor_chain(target: Path) -> tuple[Path, ...]:
    relative = target.relative_to(_MATRIX_ROOT)
    chain = [_MATRIX_ROOT]
    for part in relative.parts:
        chain.append(chain[-1] / part)
    return tuple(chain)


def _make_plan(
    *,
    materializer: str,
    plan_id: str,
    role: str,
    action: str,
    operation: str | None = None,
    source_mode: str | None = None,
    graph: tuple[str, ...],
    valid_typed_keys: frozenset[tuple[str, str, str, str]],
) -> ComponentPlan:
    typed_key = (materializer, plan_id, role, action)
    if typed_key not in valid_typed_keys:
        raise ValueError("invalid-component-combination")
    derived_operation, derived_source = _DERIVED[action]
    if operation not in {None, derived_operation} or source_mode not in {
        None,
        derived_source,
    }:
        raise ValueError("invalid-component-combination")
    occurrences = tuple(
        index for index, token in enumerate(graph) if token.split("@", 1)[0] == plan_id
    )
    if not occurrences:
        raise ValueError("component plan absent from graph")
    suffix = graph[occurrences[0] + 1 :]
    checkpoints = _CHECKPOINTS[action]
    return ComponentPlan(
        plan_id,
        materializer,
        derived_operation,
        role,
        _ancestor_chain(_target_parent(role)),
        action,
        derived_source,
        suffix,
        checkpoints,
        _FAULTS,
        checkpoints,
        graph[-1],
        typed_key,
    )


def _build_component_registry(
    relative_paths: tuple[str, ...],
    *,
    candidate_specifications: tuple[tuple[str, str, str, str], ...] | None = None,
) -> ComponentRegistry:
    graphs = _graph_tokens(relative_paths)
    expected_specifications = _expected_component_specs(relative_paths)
    generated_specifications = tuple(_component_specs(relative_paths))
    if generated_specifications != expected_specifications:
        raise ValueError("generated component plans differ from independent literal registry")
    specifications = (
        generated_specifications
        if candidate_specifications is None
        else tuple(candidate_specifications)
    )
    if specifications != expected_specifications:
        raise ValueError("missing, extra, or unstable component plan")
    valid_typed_keys = frozenset(specifications)
    if len(valid_typed_keys) != len(specifications):
        raise ValueError("duplicate component typed key")
    plans = tuple(
        sorted(
            (
                _make_plan(
                    materializer=materializer,
                    plan_id=plan_id,
                    role=role,
                    action=action,
                    graph=graphs[materializer],
                    valid_typed_keys=valid_typed_keys,
                )
                for materializer, plan_id, role, action in specifications
            ),
            key=lambda plan: plan.component_plan_id,
        )
    )
    keys = {(plan.role, plan.action) for plan in plans}
    if len({plan.component_plan_id for plan in plans}) != len(plans) or len(keys) != len(plans):
        raise ValueError("duplicate component plan ID/key")
    roles = frozenset(plan.role for plan in plans)
    invalid_role_action_keys = tuple(
        sorted(
            (role, action) for role in roles for action in _DERIVED if (role, action) not in keys
        )
    )
    if not invalid_role_action_keys:
        raise ValueError("component complement is empty")
    return ComponentRegistry(
        plans,
        valid_typed_keys,
        invalid_role_action_keys,
    )


def _fault_stage_available(plan: ComponentPlan, checkpoint: str, fault: str) -> bool:
    if fault in _CHILD_FAULTS:
        return plan.operation in {"read", "create"}
    if fault in _CREATE_FAULTS:
        if plan.operation != "create":
            return False
        return {
            "create-collision": checkpoint
            in {
                "before_parent_identity_check",
                "after_parent_identity_check_before_exclusive_open",
            },
            "partial-write": checkpoint
            in {
                "after_exclusive_open_before_write",
                "after_write_before_file_flush",
            },
            "file-flush-failure": checkpoint == "after_write_before_file_flush",
            "parent-flush-failure": checkpoint == "after_file_flush_before_parent_durability",
        }[fault]
    if fault in _REOPEN_FAULTS:
        return (plan.operation == "read" and checkpoint == "after_content_check_before_reopen") or (
            plan.operation == "create" and checkpoint == "after_parent_durability_before_reopen"
        )
    return True


def _suffix_detector(
    plan: ComponentPlan,
    checkpoint: str,
    changed_fields: tuple[str, ...],
    registry: Mapping[str, ComponentPlan],
) -> DetectorBinding | None:
    fields = set(changed_fields)
    for check, read_fields in _tail(plan.action, checkpoint):
        if fields & read_fields:
            return DetectorBinding(
                plan.component_plan_id,
                1,
                checkpoint,
                check,
                plan.action,
                ("named" if plan.source_mode == "named_acquisition" else "retained"),
            )
    for token in plan.consumer_sequence:
        plan_id = token.split("@", 1)[0]
        consumer = registry.get(plan_id)
        if consumer is None or not fields & _ACTION_FIELDS[consumer.action]:
            continue
        first_checkpoint = consumer.checkpoint_sequence[0]
        for check, read_fields in _tail(consumer.action, first_checkpoint):
            if fields & read_fields:
                return DetectorBinding(
                    plan_id,
                    int(token.rsplit("@", 1)[1]),
                    first_checkpoint,
                    check,
                    consumer.action,
                    ("named" if consumer.source_mode == "named_acquisition" else "retained"),
                )
        raise AssertionError("consumer action field map has no exact production check")
    return None


def _retained_safe_suffix(
    plan: ComponentPlan,
    checkpoint: str,
    registry: Mapping[str, ComponentPlan],
) -> tuple[str, ...]:
    current_tail = tuple(
        f"{plan.component_plan_id}@1#{check}" for check, _fields in _tail(plan.action, checkpoint)
    )
    if current_tail and plan.source_mode == "named_acquisition":
        return ()
    for token in plan.consumer_sequence:
        consumer = registry.get(token.split("@", 1)[0])
        if consumer is not None and consumer.source_mode == "named_acquisition":
            return ()
        if consumer is None and token not in _SAFE_SEMANTIC_CONSUMERS:
            return ()
    return (*current_tail, *plan.consumer_sequence)


def _classify_edge(
    platform: Literal["posix", "windows"],
    plan: ComponentPlan,
    selected_ancestor_index: int,
    checkpoint: str,
    fault: str,
    registry: Mapping[str, ComponentPlan],
) -> MutationEdge:
    if checkpoint not in plan.checkpoint_sequence or fault not in _FAULTS:
        raise ValueError("invalid-component-combination")
    changed_fields = _FAULT_FIELDS[fault]
    occurrence = 1
    adapter_id = f"{platform}:{fault}"
    detector: DetectorBinding | None = None
    neutralized: tuple[str, ...] = ()
    if fault in _WINDOWS_ONLY and platform != "windows":
        disposition = "closed-not-applicable:windows-only"
        adapter_id = None
    elif fault == "parent-flush-failure" and platform != "posix":
        disposition = "closed-not-applicable:posix-only"
        adapter_id = None
    elif (
        (fault in _CHILD_FAULTS and plan.operation not in {"read", "create"})
        or (fault in _CREATE_FAULTS and plan.operation != "create")
        or (fault in _REOPEN_FAULTS and plan.operation not in {"read", "create"})
    ):
        disposition = "closed-not-applicable:plan-family"
        adapter_id = None
    elif fault not in _NAMESPACE_FAULTS and selected_ancestor_index != len(plan.ancestor_chain) - 1:
        disposition = "closed-not-applicable:fault-does-not-target-selected-ancestor"
        adapter_id = None
    elif not _fault_stage_available(plan, checkpoint, fault):
        disposition = "closed-not-applicable:fault-stage-unavailable"
        adapter_id = None
    else:
        detector = _suffix_detector(plan, checkpoint, changed_fields, registry)
        if detector is not None:
            disposition = "applicable:detector-required"
        else:
            neutralized = (
                _retained_safe_suffix(plan, checkpoint, registry)
                if fault in _NAMESPACE_FAULTS
                else ()
            )
            if neutralized:
                disposition = "applicable:retained-route-neutralized"
            else:
                disposition = (
                    "closed-not-applicable:no-reachable-detector-after-final-check"
                    if checkpoint.endswith("final_parent_check")
                    or checkpoint
                    in {
                        "after_open_identity_check",
                        "after_final_identity_check",
                    }
                    else "closed-not-applicable:no-reachable-detector"
                )
                adapter_id = None
    return MutationEdge(
        platform,
        plan.component_plan_id,
        occurrence,
        selected_ancestor_index,
        checkpoint,
        fault,
        changed_fields,
        adapter_id,
        (
            *(
                f"{plan.component_plan_id}@1#{check}"
                for check, _fields in _tail(plan.action, checkpoint)
            ),
            *plan.consumer_sequence,
        ),
        detector,
        neutralized,
        disposition,
    )


_REAL_SEMANTIC_CALLABLES = MappingProxyType(
    {
        "parse-spec": (orchestrator._load_top_spec,),
        "strict-human-trust": (
            orchestrator._strict_load_human_records,
            orchestrator._validate_human_trust,
        ),
        "readiness-bytes-loader": (orchestrator._load_readiness_from_retained,),
        "readiness-receipt": (orchestrator.materialize_gate_b_readiness,),
        "unique-and-join": (
            orchestrator._unique_physical_artifacts,
            orchestrator._join_request_payload,
        ),
        "retained-request-join-core": (
            orchestrator._build_retained_request_bundle,
            orchestrator._load_request_from_retained,
        ),
        "request-receipt": (orchestrator.materialize_gate_b_loader_request,),
        "strict-human-records": (orchestrator._strict_load_human_records,),
        "fresh-human-trust": (
            orchestrator._strict_load_human_records,
            orchestrator._load_readiness_from_retained,
            orchestrator._validate_human_trust,
        ),
        "execution-environment-check": (orchestrator._preflight_gate_b_one_shot,),
        "executor-construction": (orchestrator.GateBProductionExecutor.from_request,),
        "pre-reservation-proof-boundary": (orchestrator.reserve_gate_b_attempt,),
    }
)


def _record_semantic_occurrence(
    token: str,
    *,
    materializer: str,
    recorder: ConsumerEvidenceRecorder,
) -> None:
    callables = _REAL_SEMANTIC_CALLABLES.get(token)
    if callables is None:
        raise AssertionError(f"unregistered semantic consumer: {token}")
    if not all(callable(function) for function in callables):
        raise AssertionError("semantic consumer is not bound to a production callable")
    occurrence = 1 + sum(item.token == token for item in recorder.records)
    source_kind = "named" if _SEMANTIC_CONSUMER_SOURCES[token] == "named" else "immutable-derived"
    recorder.append(
        ConsumerOccurrenceEvidence(
            token=token,
            materializer=materializer,
            component_plan_id=None,
            occurrence=occurrence,
            action="+".join(function.__qualname__ for function in callables),
            checkpoint_reached=token,
            logical_role=None,
            bundle_slot_role=None,
            source_kind=source_kind,
            reference_path=None,
            parent_reference_path=None,
            physical_identity=None,
            parent_physical_identity=None,
            selected_ancestor_index=None,
            selected_ancestor_path=None,
            selected_ancestor_pre_identity=None,
            selected_ancestor_post_identity=None,
            named_read_delta=int(source_kind == "named"),
            retained_read_delta=0,
            named_write_delta=0,
            retained_write_delta=0,
            mutation_observed=False,
            detector_check=None,
            terminal_observation=None,
            handles_opened=0,
            handles_closed=0,
        )
    )


def _prefixed_checks(
    plan_id: str,
    occurrence: int,
    checks: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(f"{plan_id}@{occurrence}#{check}" for check in checks)


def _execute_edge(
    edge: MutationEdge,
    registry: Mapping[str, ComponentPlan],
) -> MatrixEvidence:
    state_type = (
        _InjectedWindowsPlatformState if edge.platform == "windows" else _InjectedPosixPlatformState
    )
    state = state_type(_FAULT_FIELDS[edge.fault])
    recorder = ConsumerEvidenceRecorder()
    pre = sha256_bytes(canonical_json_bytes(state.current))
    if edge.adapter_id is None:
        return MatrixEvidence(
            edge,
            0,
            False,
            pre,
            pre,
            edge.disposition,
            (),
            (),
        )
    producer = registry[edge.component_plan_id]
    producer_route = RealRouteContext(
        edge.platform,
        state,
        producer,
        edge.occurrence,
        edge.selected_ancestor_index,
    )
    producer_trace, producer_consumed, producer_failure = _run_production_primitive(
        producer_route,
        producer,
        occurrence=edge.occurrence,
        edge=edge,
        recorder=recorder,
    )
    trace = list(_prefixed_checks(producer.component_plan_id, 1, producer_trace))
    post = sha256_bytes(canonical_json_bytes(state.current))
    assert state.adapter_invocations == 1
    assert post != pre
    if edge.disposition == "applicable:detector-required":
        binding = edge.candidate_detector
        if binding is None:
            raise AssertionError("detector-required edge has no bound detector")
        failure = producer_failure
        consumed = producer_consumed
        if failure is not None:
            if (binding.component_plan_id, binding.occurrence) != (
                producer.component_plan_id,
                1,
            ):
                raise AssertionError(
                    "producer failed before the bound graph consumer: "
                    f"edge={edge!r}, failure={failure!r}, "
                    f"consumed={consumed!r}, trace={producer_trace!r}"
                )
        else:
            if producer_consumed is not None:
                raise AssertionError("producer consumed changed state without failing closed")
            for token in producer.consumer_sequence:
                consumer = registry.get(token.split("@", 1)[0])
                if consumer is None:
                    _record_semantic_occurrence(
                        token,
                        materializer=producer.materializer,
                        recorder=recorder,
                    )
                    trace.append(token)
                    continue
                occurrence = int(token.rsplit("@", 1)[1])
                consumer_route = RealRouteContext(
                    edge.platform,
                    state,
                    consumer,
                    occurrence,
                    len(consumer.ancestor_chain) - 1,
                )
                consumer_trace, consumed, failure = _run_production_primitive(
                    consumer_route,
                    consumer,
                    occurrence=occurrence,
                    recorder=recorder,
                )
                trace.append(token)
                trace.extend(
                    _prefixed_checks(
                        consumer.component_plan_id,
                        occurrence,
                        consumer_trace,
                    )
                )
                if failure is None:
                    if consumed is not None:
                        raise AssertionError(
                            "consumer read changed state without the production detector rejecting"
                        )
                    continue
                if (binding.component_plan_id, binding.occurrence) != (
                    consumer.component_plan_id,
                    occurrence,
                ):
                    raise AssertionError("earlier graph consumer failed before bound detector")
                break
        if failure is None:
            raise AssertionError("detector-required suffix reached no production failure")
        if consumed != binding.check:
            raise AssertionError(
                "bound detector mismatch: "
                f"expected={binding.check!r}, consumed={consumed!r}, "
                f"edge={edge!r}, failure={failure!r}, trace={trace!r}"
            )
        terminal = "Gate B orchestration failed closed"
        state.production_trace = tuple(trace)
        return MatrixEvidence(
            edge,
            state.adapter_invocations,
            True,
            pre,
            post,
            terminal,
            tuple(trace),
            recorder.records,
        )
    if producer_failure is not None:
        raise AssertionError("neutralized producer failed after retained-safe mutation")
    start = _EXPECTED_CHECKPOINT_STARTS[producer.action][
        _CHECKPOINTS[producer.action].index(edge.checkpoint)
    ]
    current_tail = _prefixed_checks(
        producer.component_plan_id,
        1,
        producer_trace[start:],
    )
    expected_current_tail = tuple(
        token
        for token in edge.candidate_retained_neutralization_suffix
        if token.startswith(f"{producer.component_plan_id}@1#")
    )
    if current_tail != expected_current_tail:
        raise AssertionError("neutralized current-operation tail was not executed completely")
    safe_trace = list(current_tail)
    for token in producer.consumer_sequence:
        consumer = registry.get(token.split("@", 1)[0])
        if consumer is None:
            _record_semantic_occurrence(
                token,
                materializer=producer.materializer,
                recorder=recorder,
            )
            safe_trace.append(token)
            continue
        if consumer.source_mode == "named_acquisition":
            raise AssertionError("named-path consumer entered retained-neutralized suffix")
        occurrence = int(token.rsplit("@", 1)[1])
        consumer_route = RealRouteContext(
            edge.platform,
            state,
            consumer,
            occurrence,
            len(consumer.ancestor_chain) - 1,
        )
        consumer_trace, consumed, failure = _run_production_primitive(
            consumer_route,
            consumer,
            occurrence=occurrence,
            recorder=recorder,
        )
        if failure is not None or consumed is not None:
            raise AssertionError("retained-safe graph consumer observed substituted namespace")
        safe_trace.append(token)
        safe_trace.extend(_prefixed_checks(consumer.component_plan_id, occurrence, consumer_trace))
    if not edge.candidate_retained_neutralization_suffix:
        raise AssertionError("neutralized edge has no complete nonempty suffix")
    for token in edge.candidate_retained_neutralization_suffix:
        if token not in safe_trace:
            raise AssertionError(f"neutralized suffix consumer was not executed: {token}")
    terminal = edge.candidate_retained_neutralization_suffix[-1]
    state.production_trace = tuple(safe_trace)
    return MatrixEvidence(
        edge,
        state.adapter_invocations,
        True,
        pre,
        post,
        terminal,
        tuple(safe_trace),
        recorder.records,
    )


def test_typed_component_registry_is_closed_complete_and_stably_ordered() -> None:
    relative_paths = ("calibration/a.json", "calibration/nested/b.json")
    registry = _build_component_registry(relative_paths)
    expected_specifications = _expected_component_specs(relative_paths)
    assert tuple(_component_specs(relative_paths)) == expected_specifications
    graph_semantics = {
        token
        for graph in _graph_tokens(relative_paths).values()
        for token in graph
        if "@" not in token
    }
    assert graph_semantics == set(_SEMANTIC_CONSUMER_SOURCES)
    assert tuple(plan.component_plan_id for plan in registry) == tuple(
        sorted(plan.component_plan_id for plan in registry)
    )
    assert len(registry) == len(expected_specifications)
    assert registry.valid_typed_keys == frozenset(expected_specifications)
    assert {plan.typed_key for plan in registry} == registry.valid_typed_keys
    assert all(plan.ancestor_chain[0] == _MATRIX_ROOT for plan in registry)
    assert all(plan.ancestor_chain[-1] == _target_parent(plan.role) for plan in registry)
    assert all(
        "." not in path.parts and ".." not in path.parts
        for plan in registry
        for path in plan.ancestor_chain
    )
    valid = {(plan.role, plan.action) for plan in registry}
    roles = {plan.role for plan in registry}
    actions = set(_DERIVED)
    complement = tuple(
        sorted(
            (role, action) for role in roles for action in actions if (role, action) not in valid
        )
    )
    assert registry.invalid_role_action_keys == complement
    assert complement == tuple(sorted(complement))
    for role, action in complement:
        plan = next(item for item in registry if item.role == role)
        with pytest.raises(ValueError, match="invalid-component-combination"):
            _make_plan(
                materializer=plan.materializer,
                plan_id=plan.component_plan_id,
                role=role,
                action=action,
                graph=_graph_tokens(relative_paths)[plan.materializer],
                valid_typed_keys=registry.valid_typed_keys,
            )
    plan = registry[0]
    wrong_operation = "create" if plan.operation != "create" else "read"
    with pytest.raises(ValueError, match="invalid-component-combination"):
        _make_plan(
            materializer=plan.materializer,
            plan_id=plan.component_plan_id,
            role=plan.role,
            action=plan.action,
            operation=wrong_operation,
            graph=_graph_tokens(relative_paths)[plan.materializer],
            valid_typed_keys=registry.valid_typed_keys,
        )
    for changed in (
        {"materializer": ("request" if plan.materializer != "request" else "one_shot")},
        {"plan_id": f"{plan.component_plan_id}-unknown"},
        {"role": next(item.role for item in registry if item.role != plan.role)},
    ):
        arguments = {
            "materializer": plan.materializer,
            "plan_id": plan.component_plan_id,
            "role": plan.role,
            "action": plan.action,
            "graph": _graph_tokens(relative_paths)[plan.materializer],
            "valid_typed_keys": registry.valid_typed_keys,
        }
        arguments.update(changed)
        if "materializer" in changed:
            arguments["graph"] = _graph_tokens(relative_paths)[changed["materializer"]]
        with pytest.raises(ValueError, match="invalid-component-combination"):
            _make_plan(**arguments)
    with pytest.raises(ValueError):
        _build_component_registry(tuple(reversed(relative_paths)))
    with pytest.raises(ValueError, match="missing, extra, or unstable"):
        _build_component_registry(
            relative_paths,
            candidate_specifications=expected_specifications[:-1],
        )
    with pytest.raises(ValueError, match="missing, extra, or unstable"):
        _build_component_registry(
            relative_paths,
            candidate_specifications=(
                *expected_specifications,
                ("readiness", "R-EXTRA", "readiness.extra", "open"),
            ),
        )
    with pytest.raises(ValueError, match="missing, extra, or unstable"):
        _build_component_registry(
            relative_paths,
            candidate_specifications=tuple(reversed(expected_specifications)),
        )


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize(
    "action",
    ["read_regular", "create_regular", "open", "verify_identity", "direct_child_names"],
)
def test_injected_platform_models_execute_literal_production_primitive_traces(
    platform: Literal["posix", "windows"],
    action: str,
) -> None:
    state_type = (
        _InjectedWindowsPlatformState if platform == "windows" else _InjectedPosixPlatformState
    )
    plans = _build_component_registry(("calibration/a.json",))
    plan = next(item for item in plans if item.action == action)
    route = RealRouteContext(
        platform,
        state_type(()),
        plan,
        1,
        len(plan.ancestor_chain) - 1,
    )
    recorder = ConsumerEvidenceRecorder()
    trace, consumed, failure = _run_production_primitive(
        route,
        plan,
        occurrence=1,
        recorder=recorder,
    )
    assert consumed is None
    assert failure is None
    assert trace == _EXPECTED_PRIMITIVE_TRACES[action]
    assert len(recorder.records) == 1
    assert recorder.records[0].component_plan_id == plan.component_plan_id
    assert recorder.records[0].reference_path == route.reference_path
    assert recorder.records[0].parent_reference_path == route.target_parent
    assert recorder.records[0].handles_opened == recorder.records[0].handles_closed == 1
    for checkpoint, start in zip(
        _CHECKPOINTS[action],
        _EXPECTED_CHECKPOINT_STARTS[action],
        strict=True,
    ):
        assert (
            tuple(check for check, _fields in _tail(action, checkpoint))
            == (_EXPECTED_PRIMITIVE_TRACES[action][start:])
        )


def test_adapter_injects_at_exact_checkpoint_and_real_production_comparison_rejects() -> None:
    plans = _build_component_registry(("calibration/a.json",))
    registry = MappingProxyType({plan.component_plan_id: plan for plan in plans})
    plan = registry["R-AP-AR"]
    edge = _classify_edge(
        "windows",
        plan,
        len(plan.ancestor_chain) - 1,
        "after_content_check_before_reopen",
        "child-replacement",
        registry,
    )
    assert edge.candidate_detector is not None
    assert edge.candidate_detector.check == "reopened_child_metadata"
    state = _InjectedWindowsPlatformState(edge.changed_fields)
    route = RealRouteContext(
        "windows",
        state,
        plan,
        1,
        edge.selected_ancestor_index,
    )
    recorder = ConsumerEvidenceRecorder()
    trace, consumed, failure = _run_production_primitive(
        route,
        plan,
        occurrence=1,
        edge=edge,
        recorder=recorder,
    )
    injection_index = _EXPECTED_CHECKPOINT_STARTS[plan.action][
        _CHECKPOINTS[plan.action].index(edge.checkpoint)
    ]
    assert state.adapter_invocations == 1
    assert state.adapter_trace_prefix == _EXPECTED_PRIMITIVE_TRACES[plan.action][:injection_index]
    assert trace[:injection_index] == state.adapter_trace_prefix
    assert consumed == edge.candidate_detector.check
    assert type(failure) is GateBLedgerError
    assert failure.__cause__ is None
    assert failure.__context__ is None
    assert recorder.records[0].selected_ancestor_path == route.selected_ancestor_path
    assert (
        recorder.records[0].selected_ancestor_pre_identity
        != recorder.records[0].selected_ancestor_post_identity
    )


def test_retained_neutralization_executes_complete_safe_tail_and_named_semantic_forbids() -> None:
    plans = _build_component_registry(("calibration/a.json",))
    registry = MappingProxyType({plan.component_plan_id: plan for plan in plans})
    plan = registry["R-OUT-P-DV"]
    edge = _classify_edge(
        "windows",
        plan,
        len(plan.ancestor_chain) - 1,
        "before_identity_check",
        "windows-drive-alias",
        registry,
    )
    assert edge.disposition == "applicable:retained-route-neutralized"
    assert edge.candidate_retained_neutralization_suffix[:2] == (
        "R-OUT-P-DV@1#complete_target_ancestor_identity",
        "R-OUT-P-DV@1#final_identity_comparison",
    )
    assert edge.candidate_retained_neutralization_suffix[-1] == "readiness-receipt"
    assert all(
        (
            token in _SAFE_SEMANTIC_CONSUMERS
            or registry[token.split("@", 1)[0]].source_mode
            in {"retained_directory", "exclusive_create"}
        )
        for token in edge.candidate_retained_neutralization_suffix
        if "#" not in token
    )
    evidence = _execute_edge(edge, registry)
    assert evidence.adapter_invocation_count == 1
    assert evidence.mutation_applied
    assert evidence.named_reads == 0
    assert evidence.named_writes == 0
    assert evidence.terminal == "readiness-receipt"
    assert all(
        token in evidence.production_trace
        for token in edge.candidate_retained_neutralization_suffix
    )
    named_semantic_plan = registry["O-CP-DV"]
    named_semantic_edge = _classify_edge(
        "windows",
        named_semantic_plan,
        len(named_semantic_plan.ancestor_chain) - 1,
        "after_final_identity_check",
        "windows-drive-alias",
        registry,
    )
    assert "execution-environment-check" in named_semantic_plan.consumer_sequence
    assert _SEMANTIC_CONSUMER_SOURCES["execution-environment-check"] == "named"
    assert "execution-environment-check" not in _SAFE_SEMANTIC_CONSUMERS
    assert named_semantic_edge.disposition == (
        "closed-not-applicable:no-reachable-detector-after-final-check"
    )
    named_semantic_evidence = _execute_edge(named_semantic_edge, registry)
    assert named_semantic_evidence.adapter_invocation_count == 0
    assert not named_semantic_evidence.mutation_applied
    assert named_semantic_evidence.named_reads == 0
    assert named_semantic_evidence.retained_reads == 0


def test_two_phase_classifier_is_total_and_na_is_zero_io_zero_mutation() -> None:
    plans = _build_component_registry(("calibration/a.json", "calibration/nested/b.json"))
    registry = MappingProxyType({plan.component_plan_id: plan for plan in plans})
    universe: set[tuple[object, ...]] = set()
    applicable: set[tuple[object, ...]] = set()
    not_applicable: set[tuple[object, ...]] = set()
    executed_applicable: set[tuple[object, ...]] = set()
    executed_na: set[tuple[object, ...]] = set()
    for platform in ("posix", "windows"):
        for plan in plans:
            for selected_index in range(len(plan.ancestor_chain)):
                for checkpoint in plan.checkpoint_sequence:
                    for fault in _FAULTS:
                        key = (
                            platform,
                            plan.component_plan_id,
                            selected_index,
                            checkpoint,
                            fault,
                        )
                        assert key not in universe
                        universe.add(key)
                        edge = _classify_edge(
                            platform,
                            plan,
                            selected_index,
                            checkpoint,
                            fault,
                            registry,
                        )
                        evidence = _execute_edge(edge, registry)
                        if edge.disposition.startswith("applicable:"):
                            applicable.add(key)
                            executed_applicable.add(key)
                            assert evidence.adapter_invocation_count == 1
                            assert evidence.mutation_applied
                            assert evidence.pre_state_digest != evidence.post_state_digest
                            if edge.disposition == "applicable:detector-required":
                                assert evidence.terminal == "Gate B orchestration failed closed"
                                assert evidence.named_reads + evidence.retained_reads >= 1
                                assert edge.candidate_detector is not None
                                assert any(
                                    token
                                    == (
                                        f"{edge.candidate_detector.component_plan_id}"
                                        f"@{edge.candidate_detector.occurrence}"
                                        f"#{edge.candidate_detector.check}"
                                    )
                                    for token in evidence.production_trace
                                )
                            else:
                                assert (
                                    evidence.terminal
                                    == edge.candidate_retained_neutralization_suffix[-1]
                                )
                                assert evidence.named_reads == 0
                                assert evidence.named_writes == 0
                                assert edge.candidate_retained_neutralization_suffix
                                assert all(
                                    token in evidence.production_trace
                                    for token in edge.candidate_retained_neutralization_suffix
                                )
                        else:
                            not_applicable.add(key)
                            executed_na.add(key)
                            assert evidence.adapter_invocation_count == 0
                            assert not evidence.mutation_applied
                            assert evidence.pre_state_digest == evidence.post_state_digest
                            assert (
                                evidence.named_reads,
                                evidence.retained_reads,
                                evidence.named_writes,
                                evidence.retained_writes,
                            ) == (0, 0, 0, 0)
    assert applicable == executed_applicable
    assert not_applicable == executed_na
    assert applicable.isdisjoint(not_applicable)
    assert applicable | not_applicable == universe


def test_checkpoint_tails_bind_same_occurrence_before_graph_suffix() -> None:
    plans = _build_component_registry(("calibration/a.json",))
    registry = MappingProxyType({plan.component_plan_id: plan for plan in plans})
    read_plan = registry["R-AP-AR"]
    edge = _classify_edge(
        "windows",
        read_plan,
        len(read_plan.ancestor_chain) - 1,
        "after_child_open_before_content_check",
        "child-replacement",
        registry,
    )
    assert edge.disposition == "applicable:detector-required"
    assert edge.candidate_detector is not None
    assert edge.candidate_detector.component_plan_id == "R-AP-AR"
    assert edge.candidate_detector.occurrence == 1
    reverified_plan = registry["R-SP-AR"]
    after_final = _classify_edge(
        "windows",
        reverified_plan,
        len(reverified_plan.ancestor_chain) - 1,
        "after_final_parent_check",
        "child-replacement",
        registry,
    )
    assert after_final.disposition == "applicable:detector-required"
    assert after_final.candidate_detector is not None
    assert after_final.candidate_detector.component_plan_id == "R-SP-AR"
    assert after_final.candidate_detector.occurrence == 2
    named_open_plan = registry["R-SP-P-DO"]
    namespace_after_acquire = _classify_edge(
        "windows",
        named_open_plan,
        len(named_open_plan.ancestor_chain) - 1,
        "after_open_identity_check",
        "windows-drive-alias",
        registry,
    )
    assert namespace_after_acquire.disposition == "applicable:detector-required"
    assert namespace_after_acquire.candidate_detector is not None
    assert namespace_after_acquire.candidate_detector.component_plan_id != "R-SP-P-DV"
    assert namespace_after_acquire.candidate_detector.action == "open"
    assert namespace_after_acquire.candidate_detector.read_source == "named"
    retained_verify_plan = registry["R-SP-P-DV"]
    namespace_during_retained_verify = _classify_edge(
        "windows",
        retained_verify_plan,
        len(retained_verify_plan.ancestor_chain) - 1,
        "before_identity_check",
        "windows-drive-alias",
        registry,
    )
    assert namespace_during_retained_verify.disposition == "applicable:detector-required"
    assert namespace_during_retained_verify.candidate_detector is not None
    assert namespace_during_retained_verify.candidate_detector.action == "open"
    assert namespace_during_retained_verify.candidate_detector.read_source == "named"
    final_plan = registry["R-OUT-P-DV"]
    final_edge = _classify_edge(
        "windows",
        final_plan,
        len(final_plan.ancestor_chain) - 1,
        "after_final_identity_check",
        "parent-identity-change",
        registry,
    )
    assert final_edge.disposition.startswith("closed-not-applicable:")


def test_unrelated_valid_human_pair_and_readiness_are_rejected(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "synthetic-authority"
    specs = tmp_path / "synthetic-specs"
    output = tmp_path / "synthetic-output"
    for path in (authority, specs, output):
        path.mkdir(parents=True)
    approval_a, signature_a, _readiness_a = _human_files(authority / "pair-a")
    approval_b_payload = _approval_payload()
    approval_b_payload["approval_record_id"] = "synthetic-approval-002"
    approval_b = authority / "pair-b" / "approval.json"
    approval_b_hash, _size = _store(approval_b, approval_b_payload)
    signature_b_payload = _signature_payload(approval_b_hash)
    signature_b_payload["signature_record_id"] = "synthetic-signature-002"
    signature_b_payload["approval_record_id"] = "synthetic-approval-002"
    signature_b = authority / "pair-b" / "signature.json"
    signature_b_hash, _size = _store(signature_b, signature_b_payload)
    readiness_b = _readiness_payload(approval_b_hash, signature_b_hash)
    readiness_b["approval_record_id"] = "synthetic-approval-002"
    output_path = output / "readiness.json"
    spec_path = specs / "readiness-spec.json"
    _store(
        spec_path,
        {
            "schema_version": orchestrator.READINESS_SPEC_SCHEMA,
            "artifact_type": "gate_b_readiness_materialization_spec",
            "output": _output_reference(output_path),
            "approval_record": _artifact_reference(approval_a),
            "signature_record": _artifact_reference(signature_a),
            "authorization_payload": readiness_b,
        },
    )

    with pytest.raises(GateBMaterializationError):
        materialize_gate_b_readiness(_spec_reference(spec_path))
    assert not output_path.exists()


def _calibration_reference(base: Path) -> dict[str, object]:
    evidence = _build_genuine_evidence()
    base.mkdir(parents=True)
    root_path = base / "root.json"
    _store(root_path, evidence.root_manifest_raw)
    artifacts = []
    for index, artifact in enumerate(evidence.artifacts):
        path = base / f"artifact-{index:03d}.json"
        _store(path, artifact.raw)
        artifacts.append(
            {
                "relative_path": artifact.relative_path,
                **_artifact_reference(path),
            }
        )
    artifacts.sort(key=lambda item: item["relative_path"])
    return {
        "schema_version": orchestrator.CALIBRATION_REFERENCE_SCHEMA,
        "artifact_type": "gate_b_calibration_bundle_reference",
        "root_manifest": _artifact_reference(root_path),
        "artifacts": artifacts,
    }


def _one_shot_fixture(tmp_path: Path) -> tuple[GateBPinnedSpecReference, GateBLoaderRequest]:
    inputs = tmp_path / "synthetic-inputs"
    specs = tmp_path / "synthetic-specs"
    common = tmp_path / "synthetic-common"
    calibration = tmp_path / "synthetic-calibration"
    for path in (inputs, specs, common):
        path.mkdir(parents=True)
    test_root = common / "test-root"
    ledger_root = common / "ledger-root"
    quarantine_root = common / "quarantine-root"
    for path in (test_root, ledger_root, quarantine_root):
        path.mkdir()
    approval_path, signature_path, readiness_payload = _human_files(inputs)
    readiness_path = inputs / "readiness.json"
    _store(readiness_path, readiness_payload)
    batch_path = inputs / "batch.json"
    _store(batch_path, {"synthetic": "batch"})
    context_path = inputs / "context.json"
    _store(context_path, {"synthetic": "context"})
    ledger_anchor = ledger_root / ".gate-b-root-anchor.json"
    quarantine_anchor = quarantine_root / ".gate-b-root-anchor.json"
    _store(ledger_anchor, {"synthetic": "ledger-anchor"})
    _store(quarantine_anchor, {"synthetic": "quarantine-anchor"})
    roots = {
        "test_root": _directory_reference(test_root),
        "ledger_base": _directory_reference(ledger_root),
        "quarantine_base": _directory_reference(quarantine_root),
    }
    request_roots = {
        "test_root": {
            **roots["test_root"],
            "anchor_relative_path": None,
            "anchor_sha256": None,
            "identity_scheme": (
                "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
            ),
            "root_role": "test_root",
        },
        "ledger_base": {
            **roots["ledger_base"],
            "anchor_relative_path": ledger_anchor.name,
            "anchor_sha256": sha256_bytes(ledger_anchor.read_bytes()),
            "identity_scheme": (
                "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
            ),
            "root_role": "ledger_base",
        },
        "quarantine_base": {
            **roots["quarantine_base"],
            "anchor_relative_path": quarantine_anchor.name,
            "anchor_sha256": sha256_bytes(quarantine_anchor.read_bytes()),
            "identity_scheme": (
                "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
            ),
            "root_role": "quarantine_base",
        },
    }
    for value in request_roots.values():
        value["absolute_path"] = value.pop("absolute_path")
    request_payload = {
        "batch_manifest": {
            "absolute_path": str(batch_path.resolve()),
            "sha256": sha256_bytes(batch_path.read_bytes()),
        },
        "readiness_authorization": {
            "absolute_path": str(readiness_path.resolve()),
            "sha256": sha256_bytes(readiness_path.read_bytes()),
        },
        "execution_context": {
            "absolute_path": str(context_path.resolve()),
            "sha256": sha256_bytes(context_path.read_bytes()),
        },
        "roots": request_roots,
    }
    request_path = inputs / "request.json"
    _store(request_path, request_payload)
    pinned_inputs = {
        "loader_request": _artifact_reference(request_path),
        "batch_manifest": _artifact_reference(batch_path),
        "readiness_authorization": _artifact_reference(readiness_path),
        "human_approval_record": _artifact_reference(approval_path),
        "human_signature_record": _artifact_reference(signature_path),
        "execution_context": _artifact_reference(context_path),
        "calibration_bundle": _calibration_reference(calibration),
        "ledger_root_anchor": _artifact_reference(ledger_anchor),
        "quarantine_root_anchor": _artifact_reference(quarantine_anchor),
    }
    common_volume, common_file = _identity(common)
    spec_path = specs / "one-shot.json"
    _store(
        spec_path,
        {
            "schema_version": orchestrator.ONE_SHOT_SPEC_SCHEMA,
            "artifact_type": "gate_b_one_shot_execution_spec",
            "pinned_inputs": pinned_inputs,
            "roots": roots,
            "common_parent": {
                "absolute_path": str(common.resolve()),
                "file_id_hex": common_file,
                "identity_scheme": (
                    "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
                ),
                "volume_id_hex": common_volume,
                "expected_direct_children": [
                    "ledger-root",
                    "quarantine-root",
                    "test-root",
                ],
            },
            "expected_latest_record_sha256": None,
            "operation_timeout_seconds": 7200,
            "process_timeout_seconds": 7500,
            "output_limits": orchestrator._expected_output_limits(),
        },
    )
    readiness = SimpleNamespace(
        sha256=sha256_bytes(readiness_path.read_bytes()),
        payload=MappingProxyType(readiness_payload),
    )
    batch = SimpleNamespace(
        test_batch_hash=HASH_A,
        payload=MappingProxyType(
            {
                "components": {
                    "execution_sampler": {
                        "schema_version": "synthetic-sampler-v1",
                        "sha256": "e" * 64,
                    }
                }
            }
        ),
    )
    context = SimpleNamespace(sha256=HASH_B)
    request = GateBLoaderRequest(
        sha256_bytes(request_path.read_bytes()),
        batch,
        readiness,
        context,
        MappingProxyType(request_roots),
        "synthetic-runner",
        "test_runner",
        1,
        MappingProxyType(request_payload),
        request_path,
    )
    return _spec_reference(spec_path), request


@dataclass(frozen=True, slots=True)
class _RealRouteFixture:
    request: GateBLoaderRequest
    request_path: Path
    request_raw: bytes
    one_shot_reference: GateBPinnedSpecReference
    pinned_inputs: Mapping[str, object]
    roots: Mapping[str, object]
    common_parent: Path
    projection_sha256: str
    approval_path: Path
    approval_raw: bytes
    signature_path: Path
    signature_raw: bytes
    readiness_path: Path
    readiness_raw: bytes
    anchor_raws: Mapping[str, bytes]
    git_directory: Path
    git_index: Path
    repository_root: Path
    source_blobs: Mapping[str, bytes]


def _relative_to_repository(repository_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repository_root).as_posix()


def _real_dependency_lock(repository_root: Path) -> dict[str, object]:
    executable = Path(sys.executable).resolve()
    base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if sys.flags.no_site:
        venv_root, purelib = loader_module.require_gate_b_v2_bootstrap_topology()
        pyvenv = (venv_root / "pyvenv.cfg").resolve()
    else:
        purelib = Path(sysconfig.get_path("purelib")).resolve()
        pyvenv = (Path(sys.prefix) / "pyvenv.cfg").resolve()
    project_name = "poker-xai"
    return {
        "schema_version": DEPENDENCY_LOCK_SCHEMA_VERSION,
        "lock_scope": "complete-installed-environment-snapshot",
        "distributions": loader_module._installed_distributions(project_name, purelib),
        "project": {
            "git_commit": COMMIT,
            "name": project_name,
            "repository_path": ".",
            "source": "repository",
            "version": importlib.metadata.version(project_name),
        },
        "python": {
            "base_executable_path": str(base_executable),
            "base_executable_sha256": sha256_bytes(base_executable.read_bytes()),
            "compiler": platform_module.python_compiler(),
            "implementation": platform_module.python_implementation(),
            "platform": platform_module.platform(),
            "pyvenv_cfg_path": str(pyvenv),
            "pyvenv_cfg_sha256": sha256_bytes(pyvenv.read_bytes()),
            "site_packages_path": str(purelib),
            "venv_executable_path": str(executable),
            "venv_executable_sha256": sha256_bytes(executable.read_bytes()),
            "version": platform_module.python_version(),
        },
    }


def _real_route_fixture(tmp_path: Path) -> _RealRouteFixture:
    base = tmp_path / "genuine-route"
    inputs = base / "inputs"
    specs = base / "specs"
    output = base / "output"
    common_parent = base / "common"
    for path in (inputs, specs, output, common_parent):
        path.mkdir(parents=True)
    root_paths = {
        "ledger_base": common_parent / "ledger-root",
        "quarantine_base": common_parent / "quarantine-root",
        "test_root": common_parent / "test-root",
    }
    for path in root_paths.values():
        path.mkdir()
    identity_scheme = "windows-volume-file-id-v1" if os.name == "nt" else "posix-device-inode-v1"
    roots = {role: _directory_reference(path) for role, path in root_paths.items()}
    stable_root_references = {
        role: {
            **roots[role],
            "anchor_relative_path": (None if role == "test_root" else ".gate-b-root-anchor.json"),
            "anchor_sha256": None,
            "identity_scheme": identity_scheme,
            "root_role": role,
        }
        for role in ("ledger_base", "quarantine_base", "test_root")
    }
    projection = build_gate_b_preapproval_root_identity_projection(stable_root_references)

    repository_root = Path(__file__).resolve().parents[2]
    dependency_path = inputs / "dependency-lock.json"
    dependency_hash, dependency_size = _store(
        dependency_path,
        _real_dependency_lock(repository_root),
    )
    batch_payload = _contract_batch_payload()
    batch_payload["git"]["commit_oid"] = COMMIT
    batch_payload["runtime"] = {
        "dependency_lock": {
            "name": "dependency_lock",
            "schema_version": DEPENDENCY_LOCK_SCHEMA_VERSION,
            "sha256": dependency_hash,
            "size_bytes": dependency_size,
        },
        "machine": platform_module.machine(),
        "os_name": platform_module.system(),
        "os_release": platform_module.release(),
        "python_implementation": platform_module.python_implementation(),
        "python_version": platform_module.python_version(),
    }
    batch_path = inputs / "batch.json"
    batch_hash, _size = _store(batch_path, batch_payload)
    source_blobs = {
        relative_path: (repository_root / relative_path).read_bytes()
        for _module_name, relative_path in ACTIVE_MODULE_PATHS
    }
    source_blobs["pyproject.toml"] = (repository_root / "pyproject.toml").read_bytes()
    context_payload = {
        "schema_version": EXECUTION_CONTEXT_SCHEMA_VERSION,
        "artifact_type": "gate_b_execution_context",
        "active_modules": [
            {
                "module_name": module_name,
                "repository_relative_path": relative_path,
                "sha256": sha256_bytes(source_blobs[relative_path]),
            }
            for module_name, relative_path in ACTIVE_MODULE_PATHS
        ],
        "created_at_utc": "2026-07-29T00:00:00Z",
        "repository_root": _root_identity_payload(repository_root),
        "expected_implementation_commit": COMMIT,
        "runtime_fingerprint": loader_module._runtime_fingerprint(),
        "dependency_lock": {
            "absolute_path": str(dependency_path.resolve()),
            "sha256": dependency_hash,
            "size_bytes": dependency_size,
        },
    }
    context_path = inputs / "context.json"
    context_hash, _size = _store(context_path, context_payload)

    approval_payload = _approval_payload()
    approval_payload.update(
        {
            "test_batch_hash": batch_hash,
            "approved_implementation_commit": COMMIT,
            "approved_execution_context_sha256": context_hash,
            "approved_roots_sha256": projection.sha256,
        }
    )
    approval_raw = canonical_json_bytes(approval_payload)
    approval_path = inputs / "approval.json"
    approval_hash, _size = _store(approval_path, approval_payload)
    signature_payload = _signature_payload(approval_hash)
    signature_payload.update(
        {
            "test_batch_hash": batch_hash,
            "approved_implementation_commit": COMMIT,
            "approved_execution_context_sha256": context_hash,
            "approved_roots_sha256": projection.sha256,
        }
    )
    signature_raw = canonical_json_bytes(signature_payload)
    signature_path = inputs / "signature.json"
    signature_hash, _size = _store(signature_path, signature_payload)
    readiness_payload = _readiness_payload(approval_hash, signature_hash)
    readiness_payload.update(
        {
            "test_batch_hash": batch_hash,
            "approved_implementation_commit": COMMIT,
            "approved_execution_context_sha256": context_hash,
            "approved_roots_sha256": projection.sha256,
        }
    )
    readiness_raw = canonical_json_bytes(readiness_payload)
    readiness_path = inputs / "readiness.json"
    readiness_hash, _size = _store(readiness_path, readiness_payload)

    anchor_paths: dict[str, Path] = {}
    anchor_raws: dict[str, bytes] = {}
    for role in ("ledger_base", "quarantine_base"):
        anchor_path = root_paths[role] / ".gate-b-root-anchor.json"
        anchor_payload = {
            "schema_version": ROOT_ANCHOR_SCHEMA_VERSION,
            "artifact_type": "gate_b_root_anchor",
            "root_role": role,
            "anchor_id": f"genuine-{role}-anchor",
            "created_at_utc": "2026-07-29T00:00:01Z",
            "approval_record_sha256": approval_hash,
        }
        _store(
            anchor_path,
            anchor_payload,
        )
        anchor_paths[role] = anchor_path
        anchor_raws[role] = canonical_json_bytes(anchor_payload)
    request_roots = {
        role: {
            **stable_root_references[role],
            "anchor_sha256": (
                None if role == "test_root" else sha256_bytes(anchor_paths[role].read_bytes())
            ),
        }
        for role in ("ledger_base", "quarantine_base", "test_root")
    }
    assert (
        build_gate_b_preapproval_root_identity_projection(request_roots).sha256 == projection.sha256
    )
    request_payload = {
        "schema_version": LOADER_REQUEST_SCHEMA_VERSION,
        "artifact_type": "gate_b_test_loader_request",
        "requested_at_utc": "2026-07-29T00:00:02Z",
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
        "roots": request_roots,
        "actor": {
            "actor_id": "synthetic-runner",
            "actor_role": "test_runner",
        },
        "attempt_ordinal": 1,
    }
    request_raw = canonical_json_bytes(request_payload)
    request_path = output / "loader-request.json"
    request_materialization_inputs = {
        "batch_manifest": _artifact_reference(batch_path),
        "readiness_authorization": _artifact_reference(readiness_path),
        "human_approval_record": _artifact_reference(approval_path),
        "human_signature_record": _artifact_reference(signature_path),
        "execution_context": _artifact_reference(context_path),
        "ledger_root_anchor": _artifact_reference(anchor_paths["ledger_base"]),
        "quarantine_root_anchor": _artifact_reference(anchor_paths["quarantine_base"]),
    }
    request_spec_path = specs / "request.json"
    _store(
        request_spec_path,
        {
            "schema_version": orchestrator.REQUEST_SPEC_SCHEMA,
            "artifact_type": "gate_b_request_materialization_spec",
            "output": _output_reference(request_path),
            "request_payload": request_payload,
            "pinned_inputs": request_materialization_inputs,
            "roots": roots,
        },
    )
    receipt = orchestrator.materialize_gate_b_loader_request(_spec_reference(request_spec_path))
    assert dict(receipt) == {
        "schema_version": "phase6-gate-b-cli-materialization-receipt-v1",
        "operation": "materialize-request",
        "status": "created",
    }
    request_reference = _artifact_reference(request_path)
    request = loader_module.load_gate_b_loader_request(
        request_path,
        expected_sha256=request_reference["expected_sha256"],
        expected_readiness_authorization_sha256=readiness_hash,
        expected_readiness_approval_record_sha256=approval_hash,
        expected_readiness_signature_record_sha256=signature_hash,
    )

    process_zero = base / "process-zero"
    git_directory = process_zero / "git-directory"
    git_directory.mkdir(parents=True)
    git_index = process_zero / "index"
    git_index.write_bytes(b"synthetic-process-zero-index\n")
    pinned_inputs: dict[str, object] = {
        "loader_request": request_reference,
        **request_materialization_inputs,
        "calibration_bundle": _calibration_reference(base / "calibration"),
    }
    common_volume, common_file = _identity(common_parent)
    one_shot_path = specs / "one-shot.json"
    _store(
        one_shot_path,
        {
            "schema_version": orchestrator.ONE_SHOT_SPEC_SCHEMA,
            "artifact_type": "gate_b_one_shot_execution_spec",
            "pinned_inputs": pinned_inputs,
            "roots": roots,
            "common_parent": {
                "absolute_path": str(common_parent.resolve()),
                "file_id_hex": common_file,
                "identity_scheme": identity_scheme,
                "volume_id_hex": common_volume,
                "expected_direct_children": sorted(path.name for path in root_paths.values()),
            },
            "expected_latest_record_sha256": None,
            "operation_timeout_seconds": 7200,
            "process_timeout_seconds": 7500,
            "output_limits": orchestrator._expected_output_limits(),
        },
    )
    return _RealRouteFixture(
        request=request,
        request_path=request_path,
        request_raw=request_raw,
        one_shot_reference=_spec_reference(one_shot_path),
        pinned_inputs=MappingProxyType(pinned_inputs),
        roots=MappingProxyType(roots),
        common_parent=common_parent,
        projection_sha256=projection.sha256,
        approval_path=approval_path,
        approval_raw=approval_raw,
        signature_path=signature_path,
        signature_raw=signature_raw,
        readiness_path=readiness_path,
        readiness_raw=readiness_raw,
        anchor_raws=MappingProxyType(anchor_raws),
        git_directory=git_directory,
        git_index=git_index,
        repository_root=repository_root,
        source_blobs=MappingProxyType(source_blobs),
    )


def _private_artifact_reference(path: Path):
    reference = _artifact_reference(path)
    return orchestrator._PinnedArtifactReference(
        Path(reference["parent_absolute_path"]),
        reference["parent_volume_id_hex"],
        reference["parent_file_id_hex"],
        reference["direct_child_name"],
        reference["expected_sha256"],
        reference["expected_size_bytes"],
    )


def test_real_accepted_retained_loader_composes_with_orchestrator_snapshots_without_named_reread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_loader_fixture(tmp_path)
    request_payload = json.loads(fixture.request_path.read_bytes())
    batch_path = Path(request_payload["batch_manifest"]["absolute_path"])
    readiness_path = Path(request_payload["readiness_authorization"]["absolute_path"])
    context_path = Path(request_payload["execution_context"]["absolute_path"])
    ledger_anchor = (
        Path(request_payload["roots"]["ledger_base"]["absolute_path"]) / ".gate-b-root-anchor.json"
    )
    quarantine_anchor = (
        Path(request_payload["roots"]["quarantine_base"]["absolute_path"])
        / ".gate-b-root-anchor.json"
    )
    references = {
        "loader_request": _private_artifact_reference(fixture.request_path),
        "batch_manifest": _private_artifact_reference(batch_path),
        "readiness_authorization": _private_artifact_reference(readiness_path),
        "execution_context": _private_artifact_reference(context_path),
        "ledger_root_anchor": _private_artifact_reference(ledger_anchor),
        "quarantine_root_anchor": _private_artifact_reference(quarantine_anchor),
    }
    root_references = {
        name: orchestrator._PinnedDirectoryReference(
            Path(payload["absolute_path"]),
            payload["volume_id_hex"],
            payload["file_id_hex"],
        )
        for name, payload in request_payload["roots"].items()
    }

    with ExitStack() as stack:
        opened = {
            name: orchestrator._open_artifact(
                references[name],
                stack,
                logical_role=f"one_shot.{name}",
            )
            for name in (
                "loader_request",
                "batch_manifest",
                "readiness_authorization",
                "execution_context",
            )
        }
        retained_roots = orchestrator._open_retained_roots(
            root_references,
            stack,
            materializer="one_shot",
        )
        opened.update(
            orchestrator._open_retained_root_anchors(
                references,
                retained_roots,
                materializer="one_shot",
            )
        )
        bundle = orchestrator._build_retained_request_bundle(
            request=opened["loader_request"].artifact,
            opened=opened,
            roots=retained_roots,
        )
        assert bundle.request is opened["loader_request"].artifact
        assert bundle.batch_manifest is opened["batch_manifest"].artifact
        assert bundle.readiness_authorization is opened["readiness_authorization"].artifact
        assert bundle.execution_context is opened["execution_context"].artifact
        monkeypatch.setattr(
            Path,
            "read_bytes",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("named reread after retained acquisition")
            ),
        )
        monkeypatch.setattr(
            Path,
            "resolve",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("named resolve after retained acquisition")
            ),
        )
        loaded = orchestrator._load_request_from_retained(
            bundle,
            approval_sha256=fixture.request.readiness.payload["approval_record_sha256"],
            signature_sha256=fixture.request.readiness.payload["signature_record_sha256"],
        )
        for item in opened.values():
            orchestrator._reverify(item)

    assert loaded.request_sha256 == fixture.request_hash
    assert loaded.batch.test_batch_hash == fixture.request.batch.test_batch_hash
    assert loaded.readiness.sha256 == fixture.request.readiness.sha256
    assert loaded.execution_context.sha256 == fixture.request.execution_context.sha256


def test_request_materialization_uses_pinned_composition_and_never_reserves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = _real_route_fixture(tmp_path)
    request_payload = json.loads(route.request_path.read_bytes())
    output_parent = tmp_path / "synthetic-request-output"
    output_parent.mkdir()
    output_path = output_parent / "request.json"
    spec_path = tmp_path / "request-spec.json"
    request_inputs = {
        name: route.pinned_inputs[name]
        for name in (
            "batch_manifest",
            "readiness_authorization",
            "human_approval_record",
            "human_signature_record",
            "execution_context",
            "ledger_root_anchor",
            "quarantine_root_anchor",
        )
    }
    _store(
        spec_path,
        {
            "schema_version": orchestrator.REQUEST_SPEC_SCHEMA,
            "artifact_type": "gate_b_request_materialization_spec",
            "output": _output_reference(output_path),
            "request_payload": request_payload,
            "pinned_inputs": request_inputs,
            "roots": {name: dict(reference) for name, reference in route.roots.items()},
        },
    )
    lifecycle_calls = []

    def forbidden(*_args, **_kwargs):
        lifecycle_calls.append("called")
        raise AssertionError("request materialization reached lifecycle")

    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", forbidden)
    monkeypatch.setattr(orchestrator, "prepare_gate_b_test_open", forbidden)
    monkeypatch.setattr(orchestrator, "open_gate_b_test_input", forbidden)

    result = orchestrator.materialize_gate_b_loader_request(_spec_reference(spec_path))

    assert dict(result) == {
        "schema_version": "phase6-gate-b-cli-materialization-receipt-v1",
        "operation": "materialize-request",
        "status": "created",
    }
    assert output_path.read_bytes() == canonical_json_bytes(request_payload)
    assert route.request.request_sha256 == sha256_bytes(output_path.read_bytes())
    assert lifecycle_calls == []


class _PreReservationProofComplete(BaseException):
    pass


class _ProcessZeroGitProbe:
    def __init__(self, route: _RealRouteFixture) -> None:
        expected_commit = route.request.execution_context.payload["expected_implementation_commit"]
        self._root = route.repository_root
        self.calls: list[tuple[Path, tuple[str, ...], bool]] = []
        self._queue: list[tuple[tuple[str, ...], bool, str | bytes]] = [
            (
                ("rev-parse", "--git-dir"),
                True,
                f"{route.git_directory.resolve()}\n",
            ),
            (
                ("rev-parse", "--git-path", "index"),
                True,
                f"{route.git_index.resolve()}\n",
            ),
            (("branch", "--show-current"), True, "main\n"),
            (("rev-parse", "HEAD"), True, f"{expected_commit}\n"),
            (("rev-parse", "refs/heads/main"), True, f"{expected_commit}\n"),
            (
                ("rev-parse", "refs/remotes/origin/main"),
                True,
                f"{expected_commit}\n",
            ),
            (
                (
                    "rev-list",
                    "--left-right",
                    "--count",
                    "main...refs/remotes/origin/main",
                ),
                True,
                "0\t0\n",
            ),
            (
                ("status", "--porcelain=v1", "--untracked-files=all"),
                True,
                "",
            ),
            (("diff", "--cached", "--name-only"), True, ""),
            *[
                (
                    (
                        "cat-file",
                        "blob",
                        f"{expected_commit}:{relative_path}",
                    ),
                    False,
                    route.source_blobs[relative_path],
                )
                for _module_name, relative_path in ACTIVE_MODULE_PATHS
            ],
            (
                ("cat-file", "blob", f"{expected_commit}:pyproject.toml"),
                False,
                route.source_blobs["pyproject.toml"],
            ),
        ]

    def __call__(
        self,
        root: Path,
        *arguments: str,
        text: bool = True,
    ) -> str | bytes:
        call = (root, tuple(arguments), text)
        self.calls.append(call)
        if root != self._root or not self._queue:
            raise AssertionError("unexpected process-zero repository query")
        expected_arguments, expected_text, result = self._queue.pop(0)
        if tuple(arguments) != expected_arguments or text is not expected_text:
            raise AssertionError("misordered process-zero repository query")
        if (text and type(result) is not str) or (not text and type(result) is not bytes):
            raise AssertionError("process-zero repository result type mismatch")
        return result

    def assert_complete(self) -> None:
        assert self._queue == []
        assert len(self.calls) == 10 + len(ACTIVE_MODULE_PATHS)


def test_root_anchor_preapproval_projection_genuine_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_requests: list[tuple[object, ...]] = []
    one_shot_request_reads: list[tuple[object, ...]] = []
    retained_directories = []
    public_loader_request_reads = []
    public_loader_directories = []
    original_create = orchestrator.create_gate_b_retained_artifact
    original_read = orchestrator.read_gate_b_retained_artifact
    original_open_directory = orchestrator.open_gate_b_retained_directory
    original_public_read = loader_module.read_gate_b_retained_artifact
    original_public_open_directory = loader_module.open_gate_b_retained_directory

    def observe_create(*args, **kwargs):
        created = original_create(*args, **kwargs)
        if kwargs["logical_role"] == "request.output":
            created_requests.append(
                (
                    created.reference_path,
                    created.raw,
                    created.size_bytes,
                    created.sha256,
                    created.physical_identity,
                )
            )
        return created

    def observe_read(*args, **kwargs):
        retained = original_read(*args, **kwargs)
        if kwargs["logical_role"] == "one_shot.loader_request":
            one_shot_request_reads.append(
                (
                    retained.reference_path,
                    retained.raw,
                    retained.size_bytes,
                    retained.sha256,
                    retained.physical_identity,
                )
            )
        return retained

    def observe_open_directory(*args, **kwargs):
        retained = original_open_directory(*args, **kwargs)
        retained_directories.append(retained)
        return retained

    def observe_public_read(*args, **kwargs):
        retained = original_public_read(*args, **kwargs)
        if kwargs["logical_role"] == "compatibility.loader_request":
            public_loader_request_reads.append(retained)
        return retained

    def observe_public_open_directory(*args, **kwargs):
        retained = original_public_open_directory(*args, **kwargs)
        public_loader_directories.append(retained)
        return retained

    monkeypatch.setattr(orchestrator, "create_gate_b_retained_artifact", observe_create)
    monkeypatch.setattr(orchestrator, "read_gate_b_retained_artifact", observe_read)
    monkeypatch.setattr(
        orchestrator,
        "open_gate_b_retained_directory",
        observe_open_directory,
    )
    monkeypatch.setattr(loader_module, "read_gate_b_retained_artifact", observe_public_read)
    monkeypatch.setattr(
        loader_module,
        "open_gate_b_retained_directory",
        observe_public_open_directory,
    )
    route = _real_route_fixture(tmp_path)
    assert len(created_requests) == 1
    created = created_requests[0]
    assert created == (
        route.request_path,
        route.request_raw,
        len(route.request_raw),
        sha256_bytes(route.request_raw),
        created[4],
    )
    assert route.request.request_sha256 == created[3]
    assert route.pinned_inputs["loader_request"]["direct_child_name"] == route.request_path.name
    assert route.pinned_inputs["loader_request"]["expected_sha256"] == created[3]
    assert route.pinned_inputs["loader_request"]["expected_size_bytes"] == created[2]
    assert len(public_loader_request_reads) == 1
    public_request = public_loader_request_reads[0]
    assert (
        public_request.reference_path,
        public_request.raw,
        public_request.size_bytes,
        public_request.sha256,
        public_request.physical_identity,
    ) == created
    assert public_request._parent._closed
    assert public_loader_directories
    assert all(retained._closed for retained in public_loader_directories)
    approval = json.loads(route.approval_raw)
    signature = json.loads(route.signature_raw)
    readiness = json.loads(route.readiness_raw)
    assert {
        approval["approved_roots_sha256"],
        signature["approved_roots_sha256"],
        readiness["approved_roots_sha256"],
        route.projection_sha256,
    } == {route.projection_sha256}
    approval_hash = sha256_bytes(route.approval_raw)
    request_payload = json.loads(route.request_raw)
    for role in ("ledger_base", "quarantine_base"):
        anchor_raw = route.anchor_raws[role]
        assert json.loads(anchor_raw)["approval_record_sha256"] == approval_hash
        assert request_payload["roots"][role]["anchor_sha256"] == sha256_bytes(anchor_raw)
    assert (
        build_gate_b_preapproval_root_identity_projection(request_payload["roots"]).sha256
        == route.projection_sha256
    )

    probe = _ProcessZeroGitProbe(route)
    external_process_calls: list[tuple[object, ...]] = []
    reservation_calls: list[tuple[GateBLoaderRequest, object]] = []

    def forbid_external_process(*args, **kwargs):
        external_process_calls.append((args, kwargs))
        raise AssertionError("external process invocation is forbidden")

    def stop_before_reservation(
        request: GateBLoaderRequest,
        *,
        expected_latest_record_sha256,
    ):
        reservation_calls.append((request, expected_latest_record_sha256))
        raise _PreReservationProofComplete

    monkeypatch.setattr(loader_module, "_run_git", probe)
    monkeypatch.setattr(loader_module.subprocess, "run", forbid_external_process)
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", stop_before_reservation)
    tracked_codes = {
        "preflight": orchestrator._preflight_gate_b_one_shot.__code__,
        "environment": loader_module.verify_gate_b_execution_environment.__wrapped__.__code__,
        "factory": orchestrator.GateBProductionExecutor.from_request.__func__.__code__,
    }
    observed_calls = {name: 0 for name in tracked_codes}

    def profile(frame, event, _arg):
        if event == "call":
            for name, code in tracked_codes.items():
                if frame.f_code is code:
                    observed_calls[name] += 1

    previous_profile = sys.getprofile()
    sys.setprofile(profile)
    try:
        with pytest.raises(_PreReservationProofComplete):
            execute_gate_b_once(route.one_shot_reference)
    finally:
        sys.setprofile(previous_profile)

    probe.assert_complete()
    assert external_process_calls == []
    assert observed_calls == {"preflight": 1, "environment": 1, "factory": 1}
    assert reservation_calls == [(route.request, None)]
    assert one_shot_request_reads
    assert all(observed == created for observed in one_shot_request_reads)
    assert retained_directories
    assert all(retained._closed for retained in retained_directories)
    for role in ("ledger_base", "quarantine_base"):
        root = Path(route.request.roots[role]["absolute_path"])
        assert tuple(path.name for path in root.iterdir()) == (".gate-b-root-anchor.json",)
    assert tuple(Path(route.request.roots["test_root"]["absolute_path"]).iterdir()) == ()


def test_synthetic_one_shot_loads_genuine_evidence_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    calls: list[str] = []
    captured: dict[str, object] = {}
    original_calibration = orchestrator._load_calibration_evidence
    original_human_records = orchestrator._strict_load_human_records
    original_readiness = orchestrator._load_readiness_from_retained
    original_trust = orchestrator._validate_human_trust
    original_factory = orchestrator.GateBProductionExecutor.from_request

    def load_calibration(*args, **kwargs):
        calls.append("calibration-evidence")
        result = original_calibration(*args, **kwargs)
        captured["loader_evidence"] = result[0]
        return result

    def load_human_records(*args, **kwargs):
        calls.append("human-records")
        return original_human_records(*args, **kwargs)

    def load_request(*_args, **_kwargs):
        calls.append("load-request")
        return request

    def load_readiness(*args, **kwargs):
        calls.append("load-readiness")
        return original_readiness(*args, **kwargs)

    def validate_trust(*args, **kwargs):
        calls.append("trust")
        return original_trust(*args, **kwargs)

    def verify_environment(*_args, **_kwargs):
        calls.append("preflight")
        return None

    def factory(
        _cls,
        factory_request,
        *,
        phase6_contract_bundle_evidence,
        execution_context_sha256,
        operation_timeout_seconds=7200,
    ):
        calls.append("factory")
        assert phase6_contract_bundle_evidence is captured["loader_evidence"]
        captured["evidence"] = phase6_contract_bundle_evidence
        executor = original_factory(
            factory_request,
            phase6_contract_bundle_evidence=phase6_contract_bundle_evidence,
            execution_context_sha256=execution_context_sha256,
            operation_timeout_seconds=operation_timeout_seconds,
        )
        assert executor._phase6_contract_bundle_evidence is phase6_contract_bundle_evidence
        captured["executor"] = executor
        return executor

    def reserve(*_args, **_kwargs):
        calls.append("reserve")
        return SimpleNamespace()

    def prepare(*_args, **_kwargs):
        calls.append("prepare")
        return SimpleNamespace()

    def open_once(_prepared, *, executor):
        calls.append("open")
        assert isinstance(executor, orchestrator._GateBCallbackClassifier)
        assert object.__getattribute__(executor, "_delegate") is captured["executor"]
        assert (
            object.__getattribute__(executor, "_delegate")._phase6_contract_bundle_evidence
            is captured["evidence"]
        )
        return SimpleNamespace(state="SEALED", attempt_ordinal=1)

    monkeypatch.setattr(orchestrator, "_load_calibration_evidence", load_calibration)
    monkeypatch.setattr(orchestrator, "_strict_load_human_records", load_human_records)
    monkeypatch.setattr(orchestrator, "_load_request_from_retained", load_request)
    monkeypatch.setattr(orchestrator, "_load_readiness_from_retained", load_readiness)
    monkeypatch.setattr(orchestrator, "_validate_human_trust", validate_trust)
    monkeypatch.setattr(orchestrator, "verify_gate_b_execution_environment", verify_environment)
    monkeypatch.setattr(
        orchestrator.GateBProductionExecutor,
        "from_request",
        classmethod(factory),
    )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)
    monkeypatch.setattr(orchestrator, "prepare_gate_b_test_open", prepare)
    monkeypatch.setattr(orchestrator, "open_gate_b_test_input", open_once)

    result = execute_gate_b_once(reference)

    assert dict(result) == {
        "schema_version": "phase6-gate-b-cli-execution-receipt-v1",
        "operation": "execute-once",
        "status": "sealed",
        "attempt_ordinal": 1,
        "state": "SEALED",
    }
    assert calls == [
        "calibration-evidence",
        "human-records",
        "load-request",
        "load-readiness",
        "trust",
        "preflight",
        "factory",
        "reserve",
        "prepare",
        "open",
    ]


@pytest.mark.parametrize("unsafe_location", ["common-parent", "ledger-base"])
def test_one_shot_rejects_nonclosed_topology_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_location: str,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    if unsafe_location == "common-parent":
        unsafe = tmp_path / "synthetic-common" / "synthetic-unapproved-child"
    else:
        unsafe = tmp_path / "synthetic-common" / "ledger-root" / "synthetic-derived-namespace"
    unsafe.mkdir()
    reservation_count = 0

    def reserve(*_args, **_kwargs):
        nonlocal reservation_count
        reservation_count += 1
        raise AssertionError("unsafe topology reached reservation")

    monkeypatch.setattr(
        orchestrator,
        "_load_request_from_retained",
        lambda *_args, **_kwargs: request,
    )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)
    monkeypatch.setattr(
        orchestrator,
        "verify_gate_b_execution_environment",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(GateBPreflightError):
        execute_gate_b_once(reference)
    assert reservation_count == 0


def test_invalid_genuine_calibration_load_fails_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    spec_path = reference.parent_absolute_path / reference.direct_child_name
    spec = json.loads(spec_path.read_bytes())
    artifact_ref = spec["pinned_inputs"]["calibration_bundle"]["artifacts"][0]
    artifact_path = Path(artifact_ref["parent_absolute_path"]) / artifact_ref["direct_child_name"]
    invalid_raw = canonical_json_bytes(
        {
            "schema_version": "synthetic-invalid-calibration-v1",
            "artifact_type": "synthetic_invalid_calibration",
        }
    )
    artifact_path.write_bytes(invalid_raw)
    artifact_ref["expected_sha256"] = sha256_bytes(invalid_raw)
    artifact_ref["expected_size_bytes"] = len(invalid_raw)
    _store(spec_path, spec)
    reference = _spec_reference(spec_path)
    reservation_count = 0

    def reserve(*_args, **_kwargs):
        nonlocal reservation_count
        reservation_count += 1
        raise AssertionError("invalid evidence reached reservation")

    monkeypatch.setattr(
        orchestrator,
        "_load_request_from_retained",
        lambda *_args, **_kwargs: request,
    )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)

    with pytest.raises(GateBPreflightError):
        execute_gate_b_once(reference)
    assert reservation_count == 0


def test_fresh_factory_evidence_validation_failure_never_reserves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    original_factory = orchestrator.GateBProductionExecutor.from_request
    reservation_count = 0

    def invalidating_factory(
        _cls,
        factory_request,
        *,
        phase6_contract_bundle_evidence,
        execution_context_sha256,
        operation_timeout_seconds=7200,
    ):
        object.__setattr__(
            phase6_contract_bundle_evidence,
            "_provenance_sha256",
            "f" * 64,
        )
        return original_factory(
            factory_request,
            phase6_contract_bundle_evidence=phase6_contract_bundle_evidence,
            execution_context_sha256=execution_context_sha256,
            operation_timeout_seconds=operation_timeout_seconds,
        )

    def reserve(*_args, **_kwargs):
        nonlocal reservation_count
        reservation_count += 1
        raise AssertionError("invalid factory evidence reached reservation")

    monkeypatch.setattr(
        orchestrator,
        "_load_request_from_retained",
        lambda *_args, **_kwargs: request,
    )
    monkeypatch.setattr(
        orchestrator,
        "verify_gate_b_execution_environment",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        orchestrator.GateBProductionExecutor,
        "from_request",
        classmethod(invalidating_factory),
    )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)

    with pytest.raises(GateBPreflightError):
        execute_gate_b_once(reference)
    assert reservation_count == 0


@pytest.mark.parametrize(
    ("failure_boundary", "expected_error_code"),
    [
        ("accepted-loader", "gate_b_loader_failure"),
        ("executor-factory", "gate_b_executor_failure"),
    ],
)
def test_integrated_known_failure_mapping_is_preserved_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_boundary: str,
    expected_error_code: str,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    reservation_count = 0
    factory_count = 0

    def reserve(*_args, **_kwargs):
        nonlocal reservation_count
        reservation_count += 1
        raise AssertionError("known pre-reservation failure reached reservation")

    if failure_boundary == "accepted-loader":
        monkeypatch.setattr(
            orchestrator,
            "_load_request_from_retained",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                GateBLoaderError("synthetic accepted-loader failure")
            ),
        )
    else:

        def fail_factory(*_args, **_kwargs):
            nonlocal factory_count
            factory_count += 1
            raise GateBExecutorError()

        monkeypatch.setattr(
            orchestrator,
            "_load_request_from_retained",
            lambda *_args, **_kwargs: request,
        )
        monkeypatch.setattr(
            orchestrator,
            "_preflight_gate_b_one_shot",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(
            orchestrator.GateBProductionExecutor,
            "from_request",
            classmethod(fail_factory),
        )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)
    stdout = SimpleNamespace(buffer=io.BytesIO())
    stderr = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(orchestrator.sys, "stdout", stdout)
    monkeypatch.setattr(orchestrator.sys, "stderr", stderr)
    argv = [
        "execute-once",
        "--spec-parent",
        str(reference.parent_absolute_path),
        "--spec-parent-volume-id-hex",
        reference.parent_volume_id_hex,
        "--spec-parent-file-id-hex",
        reference.parent_file_id_hex,
        "--spec-name",
        reference.direct_child_name,
        "--expected-spec-sha256",
        reference.expected_sha256,
        "--expected-spec-size-bytes",
        str(reference.expected_size_bytes),
    ]

    assert orchestrator.main(argv) == 1
    if failure_boundary == "executor-factory":
        assert factory_count == 1
    assert stdout.buffer.getvalue() == b""
    assert json.loads(stderr.buffer.getvalue()) == {
        "schema_version": "phase6-gate-b-cli-error-v1",
        "operation": "execute-once",
        "status": "failed",
        "error_code": expected_error_code,
    }
    assert reservation_count == 0


def test_post_reservation_internal_receipt_failure_is_not_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference, request = _one_shot_fixture(tmp_path)
    reservation_count = 0

    def reserve(*_args, **_kwargs):
        nonlocal reservation_count
        reservation_count += 1
        return SimpleNamespace()

    monkeypatch.setattr(
        orchestrator,
        "_load_request_from_retained",
        lambda *_args, **_kwargs: request,
    )
    monkeypatch.setattr(
        orchestrator,
        "verify_gate_b_execution_environment",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", reserve)
    monkeypatch.setattr(
        orchestrator,
        "prepare_gate_b_test_open",
        lambda *_args, **_kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        orchestrator,
        "open_gate_b_test_input",
        lambda *_args, **_kwargs: SimpleNamespace(
            state="SYNTHETIC_INVALID",
            attempt_ordinal=1,
        ),
    )

    with pytest.raises(ValueError, match="receipt"):
        execute_gate_b_once(reference)
    assert reservation_count == 1


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (GateBDeadlineExceeded, "gate_b_operation_timeout"),
        (KeyboardInterrupt, "gate_b_interrupted"),
    ],
)
def test_callback_classifier_captures_only_timeout_or_interrupt(
    failure: type[BaseException],
    expected: str,
) -> None:
    class Delegate:
        executor_id = "synthetic-sampler-v1"
        executor_sha256 = "e" * 64

        def execute(self, _input, _output):
            raise failure

    classifier = orchestrator._GateBCallbackClassifier(Delegate())
    with pytest.raises(failure):
        classifier.execute(None, None)
    assert classifier.consume_failure_kind() == expected
    assert classifier.consume_failure_kind() is None


@pytest.mark.parametrize(
    ("failure", "error_code", "exit_status"),
    [
        (GateBDeadlineExceeded, "gate_b_operation_timeout", 124),
        (KeyboardInterrupt, "gate_b_interrupted", 130),
    ],
)
def test_real_accepted_loader_callback_route_reaches_exact_cli_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
    error_code: str,
    exit_status: int,
) -> None:
    case_root = tmp_path.parent / (
        "cb-timeout" if failure is GateBDeadlineExceeded else "cb-interrupt"
    )
    case_root.mkdir()
    fixture = _build_loader_fixture(case_root)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _loader_evidence(request),
    )
    reservation = loader_module.reserve_gate_b_attempt(
        fixture.request,
        expected_latest_record_sha256=None,
    )
    prepared = loader_module.prepare_gate_b_test_open(fixture.request, reservation)

    class Delegate:
        executor_id = fixture.executor_id
        executor_sha256 = fixture.executor_sha256

        def execute(self, _input, _output):
            raise failure

    stdout = SimpleNamespace(buffer=io.BytesIO())
    stderr = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(orchestrator.sys, "stdout", stdout)
    monkeypatch.setattr(orchestrator.sys, "stderr", stderr)
    monkeypatch.setattr(
        orchestrator,
        "_dispatch",
        lambda _argv: orchestrator._open_with_callback_classification(
            prepared,
            Delegate(),
        ),
    )

    assert orchestrator.main(["execute-once"]) == exit_status
    assert stdout.buffer.getvalue() == b""
    assert json.loads(stderr.buffer.getvalue()) == {
        "schema_version": "phase6-gate-b-cli-error-v1",
        "operation": "execute-once",
        "status": "failed",
        "error_code": error_code,
    }
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == [
        "RESERVED",
        "STARTED",
        "FAILED_CLOSED",
    ]


@pytest.mark.parametrize(
    "failure",
    [GateBPartialEvidenceError, GateBLedgerError],
)
def test_callback_classification_never_overwrites_partial_or_ledger_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
) -> None:
    case_root = tmp_path.parent / (
        "cb-partial" if failure is GateBPartialEvidenceError else "cb-ledger"
    )
    case_root.mkdir()
    fixture = _build_loader_fixture(case_root)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _loader_evidence(request),
    )
    reservation = loader_module.reserve_gate_b_attempt(
        fixture.request,
        expected_latest_record_sha256=None,
    )
    prepared = loader_module.prepare_gate_b_test_open(fixture.request, reservation)

    class Delegate:
        executor_id = fixture.executor_id
        executor_sha256 = fixture.executor_sha256

        def execute(self, _input, _output):
            raise GateBDeadlineExceeded

    monkeypatch.setattr(
        loader_module,
        "_complete_failure",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure("synthetic failure-seal evidence")),
    )

    with pytest.raises(failure):
        orchestrator._open_with_callback_classification(prepared, Delegate())
    chain = GateBLedgerStore(fixture.request).load_chain()
    assert [record.to_state for record in chain] == ["RESERVED", "STARTED"]


def test_one_shot_source_has_exact_evidence_factory_reservation_and_bridge_order() -> None:
    source = textwrap.dedent(inspect.getsource(orchestrator.execute_gate_b_once))
    assert source.index("_load_calibration_evidence(") < source.index("_strict_load_human_records(")
    assert source.index("_strict_load_human_records(") < source.index(
        "_load_request_from_retained("
    )
    assert source.index("_load_request_from_retained(") < source.index(
        "_load_readiness_from_retained("
    )
    assert source.index("_load_readiness_from_retained(") < source.index("_validate_human_trust(")
    assert source.index("_validate_human_trust(") < source.index("_preflight_gate_b_one_shot(")
    assert source.index("_preflight_gate_b_one_shot(") < source.index(
        "GateBProductionExecutor.from_request("
    )
    assert source.index("GateBProductionExecutor.from_request(") < source.index(
        "reserve_gate_b_attempt("
    )
    assert source.index("reserve_gate_b_attempt(") < source.index("prepare_gate_b_test_open(")
    assert source.index("prepare_gate_b_test_open(") < source.index(
        "_open_with_callback_classification("
    )
    bridge = textwrap.dedent(inspect.getsource(orchestrator._open_with_callback_classification))
    assert bridge.index("_GateBCallbackClassifier(") < bridge.index("open_gate_b_test_input(")
    tree = ast.parse(source)
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {
            "getattr",
            "hasattr",
            "globals",
            "locals",
            "__import__",
            "load_phase6_contract_bundle_evidence",
        }
        for node in ast.walk(tree)
    )


def test_strict_spec_parsers_reject_unknown_fields_and_caller_forgery() -> None:
    with pytest.raises(ValueError):
        orchestrator._parse_one_shot_spec(
            {
                "schema_version": orchestrator.ONE_SHOT_SPEC_SCHEMA,
                "artifact_type": "gate_b_one_shot_execution_spec",
                "unknown": True,
            }
        )
    forged = object.__new__(orchestrator._OneShotExecutionSpec)
    with pytest.raises(TypeError):
        orchestrator._require_loaded_spec(
            forged,
            orchestrator._OneShotExecutionSpec,
        )


def test_v2_materialization_specs_join_exact_hashes_without_materializing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden = []

    def create_forbidden(*_args, **_kwargs):
        forbidden.append("create")
        raise AssertionError("v2 compatibility spec validation created output")

    monkeypatch.setattr(GateBPinnedDirectory, "create_regular", create_forbidden)
    fixture = _v2_specs_fixture()
    assert type(fixture.specs) is GateBV2CompatibilityMaterializationSpecs
    assert fixture.specs.readiness_spec_sha256 == sha256_bytes(fixture.readiness_raw)
    assert fixture.specs.request_spec_sha256 == sha256_bytes(fixture.request_raw)
    assert forbidden == []


@pytest.mark.parametrize(
    ("artifact", "mutation"),
    [
        ("readiness", lambda value: value.pop("schema_version")),
        (
            "readiness",
            lambda value: value.__setitem__(
                "schema_version", "phase6-gate-b-readiness-materialization-spec-v1"
            ),
        ),
        ("readiness", lambda value: value.update({"unknown": None})),
        ("request", lambda value: value.pop("schema_version")),
        (
            "request",
            lambda value: value.__setitem__(
                "schema_version", "phase6-gate-b-request-materialization-spec-v1"
            ),
        ),
        (
            "request",
            lambda value: value["projection_descriptor"].__setitem__(
                "serialization_profile", "windows-minimal-lowerhex-v1"
            ),
        ),
        (
            "readiness",
            lambda value: value["projection_descriptor"].__setitem__(
                "source_materialization_projection_size_bytes", 868.0
            ),
        ),
        (
            "request",
            lambda value: value["projection_descriptor"].__setitem__(
                "source_materialization_projection_size_bytes", 868.0
            ),
        ),
        (
            "request",
            lambda value: value.__setitem__("loader_request_sha256", "f" * 64),
        ),
        (
            "request",
            lambda value: value["root_anchor_sha256s"].__setitem__("ledger_base", "f" * 64),
        ),
    ],
)
def test_v2_materialization_specs_reject_schema_profile_field_and_hash_drift(
    artifact: str,
    mutation,
) -> None:
    fixture = _v2_specs_fixture()
    payload = copy.deepcopy(getattr(fixture, artifact))
    mutation(payload)
    raw = canonical_json_bytes(payload)
    kwargs = {
        "readiness_spec_raw": fixture.readiness_raw,
        "expected_readiness_spec_sha256": sha256_bytes(fixture.readiness_raw),
        "request_spec_raw": fixture.request_raw,
        "expected_request_spec_sha256": sha256_bytes(fixture.request_raw),
    }
    kwargs[f"{artifact}_spec_raw"] = raw
    kwargs[f"expected_{artifact}_spec_sha256"] = sha256_bytes(raw)
    with pytest.raises(GateBSpecError):
        validate_gate_b_v2_compatibility_materialization_specs(
            fixture.chain_fixture.chain,
            **kwargs,
        )


def test_v2_materialization_specs_reject_noncanonical_bytes_and_private_tamper() -> None:
    fixture = _v2_specs_fixture()
    malformed = fixture.request_raw.rstrip(b"\n") + b" \n"
    with pytest.raises(GateBSpecError):
        validate_gate_b_v2_compatibility_materialization_specs(
            fixture.chain_fixture.chain,
            readiness_spec_raw=fixture.readiness_raw,
            expected_readiness_spec_sha256=sha256_bytes(fixture.readiness_raw),
            request_spec_raw=malformed,
            expected_request_spec_sha256=sha256_bytes(malformed),
        )
    object.__setattr__(fixture.specs, "request_spec_sha256", "f" * 64)
    with pytest.raises(GateBPreflightError):
        prepare_gate_b_v2_compatibility(fixture.specs, fixture.chain_fixture.chain)


def test_v2_materialization_spec_provenance_rejects_int_float_equivalence() -> None:
    fixture = _v2_specs_fixture()
    descriptor = copy.deepcopy(fixture.chain_fixture.descriptor)
    descriptor["source_materialization_projection_size_bytes"] = 868.0
    object.__setattr__(
        fixture.specs,
        "projection_descriptor",
        MappingProxyType(descriptor),
    )
    with pytest.raises(GateBPreflightError):
        prepare_gate_b_v2_compatibility(fixture.specs, fixture.chain_fixture.chain)


@pytest.mark.parametrize(
    "artifact_hash_slot",
    [
        "approval_record",
        "signature_record",
        "readiness_authorization",
        "ledger_root_anchor",
        "quarantine_root_anchor",
        "loader_request",
    ],
)
def test_v2_compatibility_prepare_rejects_every_cross_chain_artifact_hash_substitution(
    artifact_hash_slot: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _v2_specs_fixture()
    substituted = _v2_chain_fixture(artifact_variant=artifact_hash_slot)
    assert substituted.descriptor == fixture.chain_fixture.descriptor
    assert (
        fixture.chain_fixture.chain.artifact_hashes[artifact_hash_slot]
        != substituted.chain.artifact_hashes[artifact_hash_slot]
    )
    reached = []

    def forbidden_prepare(_chain):
        reached.append("retained-preflight")
        raise AssertionError("cross-chain substitution reached retained preflight")

    monkeypatch.setattr(
        orchestrator,
        "prepare_gate_b_v2_compatibility_preflight",
        forbidden_prepare,
    )
    with pytest.raises(GateBPreflightError):
        prepare_gate_b_v2_compatibility(fixture.specs, substituted.chain)
    assert reached == []


def test_v2_materialization_spec_private_artifact_hash_snapshot_rejects_tamper() -> None:
    fixture = _v2_specs_fixture()
    hashes = dict(fixture.specs._artifact_hashes)
    hashes["loader_request"] = "f" * 64
    object.__setattr__(fixture.specs, "_artifact_hashes", MappingProxyType(hashes))
    with pytest.raises(GateBPreflightError):
        prepare_gate_b_v2_compatibility(fixture.specs, fixture.chain_fixture.chain)


def test_v2_compatibility_prepare_dispatches_only_to_distinct_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _v2_specs_fixture()
    sentinel = object()
    calls = []

    def prepare(chain):
        calls.append(chain)
        return sentinel

    monkeypatch.setattr(orchestrator, "prepare_gate_b_v2_compatibility_preflight", prepare)
    assert prepare_gate_b_v2_compatibility(fixture.specs, fixture.chain_fixture.chain) is sentinel
    assert calls == [fixture.chain_fixture.chain]


def test_v1_one_shot_surfaces_nominally_reject_v2_before_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _v2_specs_fixture()
    lifecycle = []

    def forbidden(*_args, **_kwargs):
        lifecycle.append("called")
        raise AssertionError("v2 reached a legacy lifecycle API")

    monkeypatch.setattr(orchestrator, "reserve_gate_b_attempt", forbidden)
    monkeypatch.setattr(orchestrator, "prepare_gate_b_test_open", forbidden)
    with pytest.raises(GateBPreflightError):
        execute_gate_b_once(fixture.specs)
    with pytest.raises(GateBPreflightError):
        orchestrator._preflight_gate_b_one_shot(
            fixture.specs,
            fixture.chain_fixture.chain,
            {},
            fixture.specs,
        )
    assert lifecycle == []
