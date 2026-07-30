"""Closed CLI failure and nondisclosure tests for Gate B."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest

import phase6.gate_b_orchestrator as orchestrator
from phase6.contracts import canonical_json_bytes
from phase6.gate_b_contracts import GateBContractError
from phase6.gate_b_executor import (
    GateBDeadlineExceeded,
    GateBFrameError,
    GateBOutputError,
    GateBScientificError,
)
from phase6.gate_b_ledger import GateBLedgerError
from phase6.gate_b_loader import (
    GateBCapabilityClosed,
    GateBExecutionEnvironmentFailure,
    GateBExecutorContractViolation,
    GateBExecutorFailure,
    GateBLoaderError,
    GateBPartialEvidenceError,
    GateBTestInputFailure,
)
from phase6.gate_b_orchestrator import (
    GateBMaterializationError,
    GateBOrchestratorError,
    GateBPreflightError,
    GateBSpecError,
)


class _Stream:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, value: str) -> int:
        return self.buffer.write(value.encode("utf-8"))

    def flush(self) -> None:
        return None

    def raw(self) -> bytes:
        return self.buffer.getvalue()


class _FailingFailureStream:
    def __init__(self, stage: str) -> None:
        self.buffer = self
        self.stage = stage
        self.writes: list[bytes] = []
        self.flush_count = 0

    def write(self, raw: bytes) -> int:
        if self.stage == "write":
            raise OSError("synthetic failure emission write")
        self.writes.append(bytes(raw))
        return len(raw)

    def flush(self) -> None:
        self.flush_count += 1
        if self.stage == "flush":
            raise KeyboardInterrupt


def _run(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    dispatch: Callable[[object], object] | None = None,
) -> tuple[int, bytes, bytes]:
    stdout = _Stream()
    stderr = _Stream()
    monkeypatch.setattr(orchestrator.sys, "stdout", stdout)
    monkeypatch.setattr(orchestrator.sys, "stderr", stderr)
    if dispatch is not None:
        monkeypatch.setattr(orchestrator, "_dispatch", dispatch)
    status = orchestrator.main(argv)
    return status, stdout.raw(), stderr.raw()


def _raise(error: BaseException) -> Callable[[object], object]:
    def dispatch(_argv):
        raise error

    return dispatch


@pytest.mark.parametrize(
    ("error", "code", "exit_status"),
    [
        (GateBSpecError(), "gate_b_spec_failure", 1),
        (GateBMaterializationError(), "gate_b_materialization_failure", 1),
        (GateBPreflightError(), "gate_b_preflight_failure", 1),
        (GateBContractError("synthetic-secret"), "gate_b_contract_failure", 1),
        (GateBLedgerError("synthetic-secret"), "gate_b_ledger_failure", 1),
        (GateBLoaderError("synthetic-secret"), "gate_b_loader_failure", 1),
        (
            GateBExecutionEnvironmentFailure("synthetic-secret"),
            "gate_b_loader_failure",
            1,
        ),
        (GateBTestInputFailure("synthetic-secret"), "gate_b_loader_failure", 1),
        (GateBExecutorFailure("synthetic-secret"), "gate_b_loader_failure", 1),
        (
            GateBExecutorContractViolation("synthetic-secret"),
            "gate_b_loader_failure",
            1,
        ),
        (GateBCapabilityClosed("synthetic-secret"), "gate_b_loader_failure", 1),
        (GateBPartialEvidenceError("synthetic-secret"), "gate_b_loader_failure", 1),
        (GateBDeadlineExceeded(), "gate_b_operation_timeout", 124),
        (GateBFrameError(), "gate_b_executor_failure", 1),
        (GateBScientificError(), "gate_b_executor_failure", 1),
        (GateBOutputError(), "gate_b_executor_failure", 1),
        (GateBOrchestratorError(), "gate_b_orchestrator_failure", 1),
        (KeyboardInterrupt(), "gate_b_interrupted", 130),
        (ValueError("synthetic-secret"), "gate_b_internal_failure", 1),
    ],
)
def test_complete_exception_mapping_is_closed_and_path_free(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    code: str,
    exit_status: int,
) -> None:
    status, stdout, stderr = _run(
        monkeypatch,
        ["execute-once"],
        _raise(error),
    )

    assert status == exit_status
    assert stdout == b""
    assert stderr == canonical_json_bytes(
        {
            "schema_version": "phase6-gate-b-cli-error-v1",
            "operation": "execute-once",
            "status": "failed",
            "error_code": code,
        }
    )
    assert b"synthetic-secret" not in stderr


@pytest.mark.parametrize("failure_stage", ["write", "flush"])
def test_failure_emission_failure_is_contained_without_second_object_or_traceback(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    stdout = _Stream()
    stderr = _FailingFailureStream(failure_stage)
    monkeypatch.setattr(orchestrator.sys, "stdout", stdout)
    monkeypatch.setattr(orchestrator.sys, "stderr", stderr)
    monkeypatch.setattr(
        orchestrator,
        "_dispatch",
        _raise(ValueError("synthetic dispatch failure")),
    )

    assert orchestrator.main(["execute-once"]) == 1
    assert stdout.raw() == b""
    assert stderr.flush_count <= 1
    assert len(stderr.writes) <= 1
    if stderr.writes:
        assert json.loads(stderr.writes[0]) == {
            "schema_version": "phase6-gate-b-cli-error-v1",
            "operation": "execute-once",
            "status": "failed",
            "error_code": "gate_b_internal_failure",
        }


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        ([], "pre-dispatch"),
        (["unknown"], "pre-dispatch"),
        (["--help-extra"], "pre-dispatch"),
        (["materialize-readiness"], "materialize-readiness"),
        (["materialize-request"], "materialize-request"),
        (["execute-once"], "execute-once"),
    ],
)
def test_parse_failure_operation_uses_only_raw_first_token(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    operation: str,
) -> None:
    status, stdout, stderr = _run(monkeypatch, argv)

    assert status == 2
    assert stdout == b""
    assert json.loads(stderr) == {
        "schema_version": "phase6-gate-b-cli-error-v1",
        "operation": operation,
        "status": "failed",
        "error_code": "gate_b_invalid_arguments",
    }


@pytest.mark.parametrize(
    "argv",
    [
        ["--help"],
        ["materialize-readiness", "--help"],
        ["materialize-request", "--help"],
        ["execute-once", "--help"],
    ],
)
def test_help_is_stdout_only_and_performs_no_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    forbidden = []

    def lifecycle(*_args, **_kwargs):
        forbidden.append("called")
        raise AssertionError("help reached lifecycle")

    monkeypatch.setattr(orchestrator, "materialize_gate_b_readiness", lifecycle)
    monkeypatch.setattr(orchestrator, "materialize_gate_b_loader_request", lifecycle)
    monkeypatch.setattr(orchestrator, "execute_gate_b_once", lifecycle)

    status, stdout, stderr = _run(monkeypatch, argv)

    assert status == 0
    assert b"usage:" in stdout
    assert stderr == b""
    assert forbidden == []


def _complete_argv(tmp_path: Path, operation: str) -> list[str]:
    parent = tmp_path / "synthetic-spec-parent"
    parent.mkdir()
    return [
        operation,
        "--spec-parent",
        str(parent.resolve()),
        "--spec-parent-volume-id-hex",
        "1",
        "--spec-parent-file-id-hex",
        "2",
        "--spec-name",
        "synthetic-spec.json",
        "--expected-spec-sha256",
        "a" * 64,
        "--expected-spec-size-bytes",
        "1",
    ]


@pytest.mark.parametrize(
    ("operation", "schema", "status_value"),
    [
        (
            "materialize-readiness",
            "phase6-gate-b-cli-materialization-receipt-v1",
            "created",
        ),
        (
            "materialize-request",
            "phase6-gate-b-cli-materialization-receipt-v1",
            "created",
        ),
        (
            "execute-once",
            "phase6-gate-b-cli-execution-receipt-v1",
            "sealed",
        ),
    ],
)
def test_success_receipts_are_exact_closed_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    schema: str,
    status_value: str,
) -> None:
    if operation == "execute-once":
        payload = {
            "schema_version": schema,
            "operation": operation,
            "status": status_value,
            "attempt_ordinal": 1,
            "state": "SEALED",
        }
    else:
        payload = {
            "schema_version": schema,
            "operation": operation,
            "status": status_value,
        }

    status, stdout, stderr = _run(
        monkeypatch,
        _complete_argv(tmp_path, operation),
        lambda _argv: payload,
    )

    assert status == 0
    assert stdout == canonical_json_bytes(payload)
    assert stderr == b""


def test_closed_operation_and_error_enums_are_exact() -> None:
    assert {
        "pre-dispatch",
        "materialize-readiness",
        "materialize-request",
        "execute-once",
    } == orchestrator._OPERATION_VALUES
    assert {
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
    } == orchestrator._ERROR_CODE_VALUES
    with pytest.raises(ValueError):
        orchestrator._error_payload("execute-once", "gate_b_frame_failure")
    with pytest.raises(ValueError):
        orchestrator._error_payload("unknown", "gate_b_internal_failure")


def test_invalid_arguments_do_not_reach_dispatch_or_emit_usage_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("called")
        raise AssertionError("invalid arguments reached lifecycle")

    monkeypatch.setattr(orchestrator, "materialize_gate_b_readiness", forbidden)
    monkeypatch.setattr(orchestrator, "materialize_gate_b_loader_request", forbidden)
    monkeypatch.setattr(orchestrator, "execute_gate_b_once", forbidden)
    status, stdout, stderr = _run(monkeypatch, ["execute-once"])

    assert status == 2
    assert calls == []
    assert stdout == b""
    assert b"usage:" not in stderr
