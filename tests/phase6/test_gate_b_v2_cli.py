from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

import phase6.gate_b_v2_cli as cli
import phase6.gate_b_v2_route as route
from phase6.gate_b_orchestrator import (
    GateBPinnedSpecReference,
    execute_gate_b_once,
    execute_gate_b_v2_once,
)


def _receipt() -> dict[str, object]:
    return {
        "schema_version": "phase6-gate-b-cli-execution-receipt-v2",
        "operation": "execute-once-v2",
        "status": "sealed",
        "attempt_ordinal": 1,
        "state": "SEALED",
        "projection_sha256": "1" * 64,
        "execution_binding_sha256": "2" * 64,
        "loader_request_sha256": "3" * 64,
        "execution_context_sha256": "4" * 64,
        "execution_route_attestation_sha256": "7" * 64,
        "sealed_record_sha256": "5" * 64,
        "quarantine_manifest_sha256": "6" * 64,
    }


def _argv(parent: Path) -> list[str]:
    return [
        "execute-once-v2",
        "--spec-parent",
        str(parent),
        "--spec-parent-identity-scheme",
        "windows-volume-file-id-v1",
        "--spec-parent-serialization-profile",
        "windows-volume8-file16-lowerhex-v1",
        "--spec-parent-volume-id-hex",
        "00000001",
        "--spec-parent-file-id-hex",
        "0000000000000001",
        "--spec-name",
        "gate-b-v2-bootstrap.json",
        "--expected-spec-sha256",
        "a" * 64,
        "--expected-spec-size-bytes",
        "101",
    ]


def _error(capfd: pytest.CaptureFixture[str]) -> dict[str, str]:
    captured = capfd.readouterr()
    assert captured.out == ""
    return json.loads(captured.err)


def test_v1_signature_remains_closed_and_v2_is_a_separate_entry() -> None:
    assert inspect.signature(execute_gate_b_once).parameters["spec_reference"].annotation == (
        "GateBPinnedSpecReference"
    )
    assert execute_gate_b_once is not execute_gate_b_v2_once
    assert GateBPinnedSpecReference.__name__ == "GateBPinnedSpecReference"


def test_v2_cli_success_emits_only_the_canonical_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "validate_gate_b_v2_fixed_local_path", lambda value, _label: value)
    reference = object()
    monkeypatch.setattr(cli, "build_gate_b_v2_pinned_spec_reference", lambda **_kwargs: reference)
    monkeypatch.setattr(cli, "execute_gate_b_v2_once", lambda value: _receipt())
    assert cli.main(_argv(tmp_path.resolve())) == 0
    captured = capfd.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == _receipt()


@pytest.mark.parametrize("operation", [[], ["execute-once"], ["unknown-operation"]])
def test_unknown_operation_is_closed_before_path_parsing(
    operation: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "build_gate_b_v2_pinned_spec_reference",
        lambda **_kwargs: pytest.fail("unknown operation reached path/reference construction"),
    )
    assert cli.main(operation) == 2
    assert _error(capfd) == {
        "schema_version": cli.V2_CLI_ERROR_SCHEMA_VERSION,
        "operation": "pre-dispatch",
        "status": "failed",
        "error_code": "gate_b_invalid_arguments",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda argv: argv + ["--spec-name", "again.json"],
        lambda argv: argv[:-2],
        lambda argv: ["execute-once-v2", *argv[2:]],
        lambda argv: [item.replace("--spec-name", "--spec-nam") for item in argv],
    ],
)
def test_each_option_is_required_once_with_exact_spelling_before_path_parsing(
    tmp_path: Path,
    mutation,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "validate_gate_b_v2_fixed_local_path",
        lambda *_args: pytest.fail("invalid option set reached path parsing"),
    )
    assert cli.main(mutation(_argv(tmp_path.resolve()))) == 2
    assert _error(capfd)["error_code"] == "gate_b_invalid_arguments"


@pytest.mark.parametrize(
    "invalid",
    [
        r"\\server\share\gate-b",
        r"\\?\C:\gate-b",
        r"\\.\C:\gate-b",
        r"C:\gate-b\manifest.json:stream",
    ],
)
def test_unc_device_and_ads_paths_reject_before_reference_construction(
    invalid: str,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "build_gate_b_v2_pinned_spec_reference",
        lambda **_kwargs: pytest.fail("invalid path reached reference construction"),
    )
    assert cli.main(_argv(Path(invalid))) == 2
    assert _error(capfd)["error_code"] == "gate_b_invalid_arguments"


def test_nonfixed_volume_rejects_before_reference_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(route, "_windows_drive_type", lambda _root: 4)
    monkeypatch.setattr(
        cli,
        "build_gate_b_v2_pinned_spec_reference",
        lambda **_kwargs: pytest.fail("nonfixed path reached reference construction"),
    )
    assert cli.main(_argv(tmp_path.resolve())) == 2
    assert _error(capfd)["error_code"] == "gate_b_invalid_arguments"


def test_non_windows_cli_imports_and_fails_closed_before_reference_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(route.os, "name", "posix")
    monkeypatch.setattr(
        cli,
        "build_gate_b_v2_pinned_spec_reference",
        lambda **_kwargs: pytest.fail("non-Windows path reached reference construction"),
    )
    assert cli.main(_argv(tmp_path.resolve())) == 2
    assert _error(capfd)["error_code"] == "gate_b_invalid_arguments"


@pytest.mark.parametrize(
    ("exception", "error_code", "status"),
    [
        ("spec", "gate_b_invalid_spec", 1),
        ("preflight", "gate_b_invalid_preflight", 1),
        ("post_seal", "gate_b_invalid_preflight", 1),
        ("contract", "gate_b_contract_error", 1),
        ("ledger", "gate_b_ledger_error", 1),
        ("loader", "gate_b_loader_error", 1),
        ("executor", "gate_b_executor_error", 1),
        ("timeout", "gate_b_operation_timeout", 124),
        ("orchestrator", "gate_b_orchestrator_error", 1),
        ("interrupt", "gate_b_interrupted", 130),
        ("internal", "gate_b_internal_error", 1),
    ],
)
def test_v2_cli_exception_mapping_is_canonical_and_closed(
    tmp_path: Path,
    exception: str,
    error_code: str,
    status: int,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "validate_gate_b_v2_fixed_local_path", lambda value, _label: value)
    monkeypatch.setattr(cli, "build_gate_b_v2_pinned_spec_reference", lambda **_kwargs: object())

    def fail(_reference):
        if exception == "spec":
            from phase6.gate_b_orchestrator import GateBSpecError

            raise GateBSpecError
        if exception == "preflight":
            from phase6.gate_b_orchestrator import GateBPreflightError

            raise GateBPreflightError
        if exception == "post_seal":
            from phase6.gate_b_orchestrator import GateBPostSealValidationError

            raise GateBPostSealValidationError
        if exception == "contract":
            from phase6.gate_b_contracts import GateBContractError

            raise GateBContractError("closed contract fixture")
        if exception == "ledger":
            from phase6.gate_b_ledger import GateBLedgerError

            raise GateBLedgerError("closed ledger fixture")
        if exception == "loader":
            from phase6.gate_b_loader import GateBLoaderError

            raise GateBLoaderError("closed loader fixture")
        if exception == "executor":
            from phase6.gate_b_executor import GateBExecutorError

            raise GateBExecutorError
        if exception == "timeout":
            from phase6.gate_b_executor import GateBDeadlineExceeded

            raise GateBDeadlineExceeded
        if exception == "interrupt":
            raise KeyboardInterrupt
        if exception == "orchestrator":
            from phase6.gate_b_orchestrator import GateBOrchestratorError

            raise GateBOrchestratorError
        raise RuntimeError("closed internal fixture")

    monkeypatch.setattr(cli, "execute_gate_b_v2_once", fail)
    assert cli.main(_argv(tmp_path.resolve())) == status
    assert _error(capfd) == {
        "schema_version": cli.V2_CLI_ERROR_SCHEMA_VERSION,
        "operation": "execute-once-v2",
        "status": "failed",
        "error_code": error_code,
    }


def test_huge_decimal_size_is_invalid_arguments_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    argv = _argv(tmp_path.resolve())
    argv[-1] = "9" * 5000
    monkeypatch.setattr(
        cli,
        "build_gate_b_v2_pinned_spec_reference",
        lambda **_kwargs: pytest.fail("huge decimal reached reference construction"),
    )
    assert cli.main(argv) == 2
    assert _error(capfd)["error_code"] == "gate_b_invalid_arguments"
