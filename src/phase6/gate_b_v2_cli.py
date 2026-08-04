"""Closed command dispatcher for the exact Gate B v2 one-shot route."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from phase6.contracts import canonical_json_bytes
from phase6.gate_b_contracts import GateBContractError
from phase6.gate_b_executor import GateBDeadlineExceeded, GateBExecutorError
from phase6.gate_b_ledger import GateBLedgerError
from phase6.gate_b_loader import GateBLoaderError
from phase6.gate_b_orchestrator import (
    GateBOrchestratorError,
    GateBPreflightError,
    GateBSpecError,
    _validate_gate_b_v2_execution_receipt,
    execute_gate_b_v2_once,
)
from phase6.gate_b_v2_route import (
    GateBV2RouteError,
    build_gate_b_v2_pinned_spec_reference,
    validate_gate_b_v2_fixed_local_path,
)

V2_CLI_ERROR_SCHEMA_VERSION = "phase6-gate-b-v2-cli-error-v1"

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_VOLUME_RE = re.compile(r"[0-9a-f]{8}\Z")
_FILE_RE = re.compile(r"[0-9a-f]{16}\Z")
_CHILD_RE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"|\.[A-Za-z0-9][A-Za-z0-9._-]{0,126})\Z"
)
_OPTION_NAMES = (
    "--spec-parent",
    "--spec-parent-identity-scheme",
    "--spec-parent-serialization-profile",
    "--spec-parent-volume-id-hex",
    "--spec-parent-file-id-hex",
    "--spec-name",
    "--expected-spec-sha256",
    "--expected-spec-size-bytes",
)
_ERROR_CODES = {
    "gate_b_invalid_arguments",
    "gate_b_invalid_spec",
    "gate_b_invalid_preflight",
    "gate_b_contract_error",
    "gate_b_ledger_error",
    "gate_b_loader_error",
    "gate_b_executor_error",
    "gate_b_operation_timeout",
    "gate_b_orchestrator_error",
    "gate_b_internal_error",
    "gate_b_interrupted",
}


class _InvalidArguments(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _InvalidArguments

    def exit(self, _status: int = 0, _message: str | None = None) -> None:
        raise _InvalidArguments


def _parser() -> _Parser:
    parser = _Parser(prog="phase6_gate_b_v2", add_help=False, allow_abbrev=False)
    parser.add_argument("operation")
    parser.add_argument("--spec-parent", required=True)
    parser.add_argument("--spec-parent-identity-scheme", required=True)
    parser.add_argument("--spec-parent-serialization-profile", required=True)
    parser.add_argument("--spec-parent-volume-id-hex", required=True)
    parser.add_argument("--spec-parent-file-id-hex", required=True)
    parser.add_argument("--spec-name", required=True)
    parser.add_argument("--expected-spec-sha256", required=True)
    parser.add_argument("--expected-spec-size-bytes", required=True)
    return parser


def _operation(argv: Sequence[str]) -> str:
    return "execute-once-v2" if argv and argv[0] == "execute-once-v2" else "pre-dispatch"


def _validate_error_payload(value: object) -> dict[str, str]:
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "operation", "status", "error_code"}
        or value.get("schema_version") != V2_CLI_ERROR_SCHEMA_VERSION
        or value.get("operation") not in {"pre-dispatch", "execute-once-v2"}
        or value.get("status") != "failed"
        or value.get("error_code") not in _ERROR_CODES
        or any(type(item) is not str for item in value.values())
    ):
        raise ValueError("v2 CLI error payload mismatch")
    return dict(value)


def _error_payload(operation: str, error_code: str) -> dict[str, str]:
    return _validate_error_payload(
        {
            "schema_version": V2_CLI_ERROR_SCHEMA_VERSION,
            "operation": operation,
            "status": "failed",
            "error_code": error_code,
        }
    )


def _emit_error(operation: str, error_code: str, status: int) -> int:
    try:
        sys.stderr.buffer.write(canonical_json_bytes(_error_payload(operation, error_code)))
        sys.stderr.buffer.flush()
    except BaseException:
        return status
    return status


def _dispatch(argv: Sequence[str]) -> Mapping[str, object]:
    if not argv or argv[0] != "execute-once-v2":
        raise _InvalidArguments
    if len(argv) != 1 + 2 * len(_OPTION_NAMES) or any(
        argv.count(option) != 1 for option in _OPTION_NAMES
    ):
        raise _InvalidArguments
    namespace = _parser().parse_args(list(argv))
    if namespace.operation != "execute-once-v2":
        raise _InvalidArguments
    try:
        parent = validate_gate_b_v2_fixed_local_path(
            Path(namespace.spec_parent), "v2 CLI spec parent"
        )
    except GateBV2RouteError:
        raise _InvalidArguments from None
    if (
        namespace.spec_parent_identity_scheme != "windows-volume-file-id-v1"
        or namespace.spec_parent_serialization_profile != "windows-volume8-file16-lowerhex-v1"
        or _VOLUME_RE.fullmatch(namespace.spec_parent_volume_id_hex) is None
        or int(namespace.spec_parent_volume_id_hex, 16) == 0
        or _FILE_RE.fullmatch(namespace.spec_parent_file_id_hex) is None
        or int(namespace.spec_parent_file_id_hex, 16) == 0
        or _CHILD_RE.fullmatch(namespace.spec_name) is None
        or namespace.spec_name in {".", ".."}
        or ":" in namespace.spec_name
        or _SHA_RE.fullmatch(namespace.expected_spec_sha256) is None
        or not namespace.expected_spec_size_bytes.isascii()
        or not namespace.expected_spec_size_bytes.isdecimal()
    ):
        raise _InvalidArguments
    size = int(namespace.expected_spec_size_bytes, 10)
    if size <= 0 or str(size) != namespace.expected_spec_size_bytes:
        raise _InvalidArguments
    try:
        reference = build_gate_b_v2_pinned_spec_reference(
            parent_absolute_path=parent,
            parent_identity_scheme=namespace.spec_parent_identity_scheme,
            parent_serialization_profile=namespace.spec_parent_serialization_profile,
            parent_volume_id_hex=namespace.spec_parent_volume_id_hex,
            parent_file_id_hex=namespace.spec_parent_file_id_hex,
            direct_child_name=namespace.spec_name,
            expected_sha256=namespace.expected_spec_sha256,
            expected_size_bytes=size,
        )
    except GateBV2RouteError:
        raise _InvalidArguments from None
    return execute_gate_b_v2_once(reference)


def main(argv: Sequence[str] | None = None) -> int:
    raw = tuple(sys.argv[1:] if argv is None else argv)
    operation = _operation(raw)
    try:
        receipt = _validate_gate_b_v2_execution_receipt(dict(_dispatch(raw)))
        sys.stdout.buffer.write(canonical_json_bytes(dict(receipt)))
        sys.stdout.buffer.flush()
        return 0
    except _InvalidArguments:
        return _emit_error(operation, "gate_b_invalid_arguments", 2)
    except GateBSpecError:
        return _emit_error(operation, "gate_b_invalid_spec", 1)
    except GateBPreflightError:
        return _emit_error(operation, "gate_b_invalid_preflight", 1)
    except GateBContractError:
        return _emit_error(operation, "gate_b_contract_error", 1)
    except GateBLedgerError:
        return _emit_error(operation, "gate_b_ledger_error", 1)
    except GateBLoaderError:
        return _emit_error(operation, "gate_b_loader_error", 1)
    except GateBDeadlineExceeded:
        return _emit_error(operation, "gate_b_operation_timeout", 124)
    except GateBExecutorError:
        return _emit_error(operation, "gate_b_executor_error", 1)
    except GateBOrchestratorError:
        return _emit_error(operation, "gate_b_orchestrator_error", 1)
    except KeyboardInterrupt:
        return _emit_error(operation, "gate_b_interrupted", 130)
    except Exception:
        return _emit_error(operation, "gate_b_internal_error", 1)


if __name__ == "__main__":
    raise SystemExit(main())
