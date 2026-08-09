from __future__ import annotations

import ast
import copy
import gc
import os
import subprocess
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext, suppress
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from test_gate_b_contracts import (
    _v2_chain_fixture,
    human_approval_payload,
    human_signature_payload,
    readiness_payload,
)
from test_gate_b_executor import _build_genuine_evidence
from test_gate_b_loader import (
    _build_fixture,
    _DrainExecutor,
    _evidence,
    _native_v2_directory_identity,
)

import phase6.gate_b_ledger as ledger_module
import phase6.gate_b_loader as loader_module
import phase6.gate_b_orchestrator as orchestrator_module
import phase6.gate_b_v2_route as route_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import _plain
from phase6.gate_b_executor import GateBProductionExecutor
from phase6.gate_b_ledger import GateBLedgerError, GateBLedgerStore, GateBPinnedDirectory
from phase6.gate_b_orchestrator import (
    GateBPostSealValidationError,
    GateBPreflightError,
    execute_gate_b_v2_once,
)
from phase6.gate_b_v2_route import (
    EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
    HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
    HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
    LOADER_REQUEST_V3_SCHEMA_VERSION,
    ONE_SHOT_SPEC_V2_SCHEMA_VERSION,
    READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
    GateBV2RouteError,
    build_gate_b_v2_execution_plan,
    build_gate_b_v2_pinned_spec_reference,
    close_gate_b_v2_execution_plan,
    close_gate_b_v2_execution_route,
    prepare_gate_b_v2_execution_route,
    prepare_gate_b_v2_execution_route_from_reference,
    validate_gate_b_v2_execution_plan,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXACT_ROUTE_COMMIT = (
    subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={_REPOSITORY_ROOT.as_posix()}",
            "-C",
            str(_REPOSITORY_ROOT),
            "rev-parse",
            "HEAD",
        ],
        check=True,
        capture_output=True,
    )
    .stdout.decode("ascii")
    .strip()
)
WINDOWS_PRODUCTION = pytest.mark.skipif(
    os.name != "nt",
    reason="Gate B v2 production routes require Windows fixed-local identity",
)


@pytest.fixture(autouse=True)
def _close_unprepared_v2_plans_after_each_test():
    existing = set(route_module._PLAN_REGISTRY)
    yield
    for plan_id, snapshot in tuple(route_module._PLAN_REGISTRY.items()):
        if plan_id not in existing:
            with suppress(GateBV2RouteError):
                close_gate_b_v2_execution_plan(snapshot[0])


def _write_raw(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path.resolve()


def _production_plan_fixture(tmp_path: Path):
    """Materialize only disposable tmp artifacts for the read-only production builder."""
    source = _build_fixture(tmp_path / "source-case")
    compatibility = _v2_chain_fixture()
    chain = compatibility.chain
    projection = chain.projection
    descriptor = dict(route_module.gate_b_root_identity_projection_descriptor_v2(projection))
    compatibility_hash = chain.artifact_hashes["loader_request"]
    bundle_evidence = _build_genuine_evidence()

    batch_raw = source.request.batch.raw_bytes
    batch_hash = source.request.batch.sha256
    batch_path = source.request.batch.path

    context = _plain(source.request.execution_context.payload)
    science_commit = source.request.batch.payload["git"]["commit_oid"]
    active_module_sources_sha256 = sha256_bytes(canonical_json_bytes(context["active_modules"]))
    execution_route_attestation_sha256 = loader_module.gate_b_v2_route_attestation_sha256(
        science_commit,
        EXACT_ROUTE_COMMIT,
    )
    context.update(
        {
            "schema_version": EXECUTION_CONTEXT_V2_SCHEMA_VERSION,
            "projection_descriptor": copy.deepcopy(descriptor),
            "compatibility_preflight_request_sha256": compatibility_hash,
            "phase6_contract_bundle_root_manifest_sha256": (bundle_evidence.root_manifest_sha256),
            "phase6_contract_bundle_provenance_sha256": (bundle_evidence.provenance_sha256),
            "science_commit": science_commit,
            "execution_route_commit": EXACT_ROUTE_COMMIT,
            "active_module_sources_sha256": active_module_sources_sha256,
            "execution_route_attestation_sha256": execution_route_attestation_sha256,
        }
    )
    context_raw = canonical_json_bytes(context)
    context_hash = sha256_bytes(context_raw)
    context_path = _write_raw(tmp_path / "v2-execution-context.json", context_raw)

    approval = human_approval_payload()
    approval.update(
        {
            "schema_version": HUMAN_APPROVAL_RECORD_V4_SCHEMA_VERSION,
            "test_batch_hash": batch_hash,
            "approved_implementation_commit": source.request.batch.payload["git"]["commit_oid"],
            "approved_execution_context_sha256": context_hash,
            "approved_roots_sha256": projection.sha256,
            "projection_descriptor": copy.deepcopy(descriptor),
            "compatibility_preflight_request_sha256": compatibility_hash,
        }
    )
    approval_raw = canonical_json_bytes(approval)
    approval_hash = sha256_bytes(approval_raw)
    approval_path = _write_raw(tmp_path / "v2-approval.json", approval_raw)

    signature = human_signature_payload(approval_hash)
    signature.update(
        {
            "schema_version": HUMAN_SIGNATURE_RECORD_V4_SCHEMA_VERSION,
            "test_batch_hash": batch_hash,
            "approved_implementation_commit": source.request.batch.payload["git"]["commit_oid"],
            "approved_execution_context_sha256": context_hash,
            "approved_roots_sha256": projection.sha256,
            "projection_descriptor": copy.deepcopy(descriptor),
            "compatibility_preflight_request_sha256": compatibility_hash,
        }
    )
    signature_raw = canonical_json_bytes(signature)
    signature_hash = sha256_bytes(signature_raw)
    signature_path = _write_raw(tmp_path / "v2-signature.json", signature_raw)

    readiness = readiness_payload(batch_hash, context_hash, projection.sha256)
    readiness.update(
        {
            "schema_version": READINESS_AUTHORIZATION_V4_SCHEMA_VERSION,
            "approval_record_sha256": approval_hash,
            "signature_record_sha256": signature_hash,
            "projection_descriptor": copy.deepcopy(descriptor),
            "compatibility_preflight_request_sha256": compatibility_hash,
        }
    )
    readiness_raw = canonical_json_bytes(readiness)
    readiness_hash = sha256_bytes(readiness_raw)
    readiness_path = _write_raw(tmp_path / "v2-readiness.json", readiness_raw)

    request_roots = copy.deepcopy(_plain(chain.roots))
    request = {
        "schema_version": LOADER_REQUEST_V3_SCHEMA_VERSION,
        "artifact_type": "gate_b_test_loader_request",
        "requested_at_utc": "2026-08-01T01:04:00Z",
        "operation": "execute_once",
        "projection_descriptor": copy.deepcopy(descriptor),
        "compatibility_preflight_request_sha256": compatibility_hash,
        "batch_manifest": {"absolute_path": str(batch_path), "sha256": batch_hash},
        "readiness_authorization": {
            "absolute_path": str(readiness_path),
            "sha256": readiness_hash,
        },
        "execution_context": {
            "absolute_path": str(context_path),
            "sha256": context_hash,
        },
        "roots": request_roots,
        "actor": {"actor_id": "fixture-runner", "actor_role": "test_runner"},
        "attempt_ordinal": 1,
    }
    request_raw = canonical_json_bytes(request)
    request_hash = sha256_bytes(request_raw)
    request_path = _write_raw(tmp_path / "v2-request.json", request_raw)

    spec = {
        "schema_version": ONE_SHOT_SPEC_V2_SCHEMA_VERSION,
        "artifact_type": "gate_b_one_shot_execution_spec",
        "projection_descriptor": copy.deepcopy(descriptor),
        "compatibility_preflight_request_sha256": compatibility_hash,
        "phase6_contract_bundle_root_manifest_sha256": (bundle_evidence.root_manifest_sha256),
        "phase6_contract_bundle_provenance_sha256": bundle_evidence.provenance_sha256,
        "approval_record_sha256": approval_hash,
        "signature_record_sha256": signature_hash,
        "readiness_authorization_sha256": readiness_hash,
        "ledger_root_anchor_sha256": chain.artifact_hashes["ledger_root_anchor"],
        "quarantine_root_anchor_sha256": chain.artifact_hashes["quarantine_root_anchor"],
        "loader_request_sha256": request_hash,
        "execution_context_sha256": context_hash,
        "batch_manifest_sha256": batch_hash,
        "science_commit": science_commit,
        "execution_route_commit": EXACT_ROUTE_COMMIT,
        "active_module_sources_sha256": active_module_sources_sha256,
        "execution_route_attestation_sha256": execution_route_attestation_sha256,
        "expected_latest_record_sha256": None,
        "operation_timeout_seconds": 7200,
        "process_timeout_seconds": 7500,
        "output_limits": route_module._expected_output_limits(),
    }
    spec_raw = canonical_json_bytes(spec)
    spec_path = _write_raw(tmp_path / "v2-one-shot.json", spec_raw)

    kwargs = {
        "phase6_contract_bundle_evidence": bundle_evidence,
        "approval_record_raw": approval_raw,
        "approval_record_path": approval_path,
        "signature_record_raw": signature_raw,
        "signature_record_path": signature_path,
        "readiness_authorization_raw": readiness_raw,
        "readiness_authorization_path": readiness_path,
        "loader_request_raw": request_raw,
        "loader_request_path": request_path,
        "execution_context_raw": context_raw,
        "execution_context_path": context_path,
        "batch_manifest_raw": batch_raw,
        "batch_manifest_path": batch_path,
        "one_shot_spec_raw": spec_raw,
        "one_shot_spec_path": spec_path,
    }
    return source, chain, request, spec, kwargs


def _production_bootstrap_reference(tmp_path: Path):
    source, chain, request, spec, kwargs = _production_plan_fixture(tmp_path / "plan")
    compatibility = _v2_chain_fixture()
    bundle = kwargs["phase6_contract_bundle_evidence"]
    bootstrap_parent = (tmp_path / "bootstrap-inputs").resolve()
    bootstrap_parent.mkdir(parents=True)

    compatibility_raws = {
        "compatibility_approval_record": compatibility.approval_raw,
        "compatibility_signature_record": compatibility.signature_raw,
        "compatibility_readiness_authorization": compatibility.readiness_raw,
        "ledger_root_anchor": compatibility.anchor_raws["ledger_base"],
        "quarantine_root_anchor": compatibility.anchor_raws["quarantine_base"],
        "compatibility_loader_request": compatibility.request_raw,
    }
    compatibility_paths = {
        name: _write_raw(bootstrap_parent / f"compat-{index:02d}.json", raw)
        for index, (name, raw) in enumerate(compatibility_raws.items())
    }
    execution_raws = {
        name: kwargs[f"{name}_raw"]
        for name in (
            "approval_record",
            "signature_record",
            "readiness_authorization",
            "loader_request",
            "execution_context",
            "batch_manifest",
            "one_shot_spec",
        )
    }
    execution_paths = {name: kwargs[f"{name}_path"] for name in execution_raws}
    bundle_root_path = _write_raw(
        bootstrap_parent / "bundle-root.json",
        bundle.root_manifest_raw,
    )
    bundle_paths = {
        artifact.relative_path: _write_raw(
            bootstrap_parent / f"bundle-{index:03d}.json",
            artifact.raw,
        )
        for index, artifact in enumerate(bundle.artifacts)
    }
    identities: dict[Path, tuple[str, str]] = {}

    def pin(path: Path, raw: bytes) -> dict[str, object]:
        parent = path.parent.resolve()
        if parent not in identities:
            identities[parent] = _native_v2_directory_identity(parent)
        volume_id_hex, file_id_hex = identities[parent]
        return {
            "parent_absolute_path": str(parent),
            "parent_identity_scheme": "windows-volume-file-id-v1",
            "parent_serialization_profile": route_module.ROOT_IDENTITY_SERIALIZATION_PROFILE_V2,
            "parent_volume_id_hex": volume_id_hex,
            "parent_file_id_hex": file_id_hex,
            "direct_child_name": path.name,
            "expected_sha256": sha256_bytes(raw),
            "expected_size_bytes": len(raw),
        }

    payload = {
        "schema_version": route_module.ROUTE_BOOTSTRAP_V2_SCHEMA_VERSION,
        "artifact_type": "gate_b_v2_route_bootstrap",
        "compatibility_inputs": {
            name: pin(compatibility_paths[name], raw) for name, raw in compatibility_raws.items()
        },
        "phase6_contract_bundle": {
            "root_manifest": pin(bundle_root_path, bundle.root_manifest_raw),
            "artifacts": [
                {
                    "relative_path": artifact.relative_path,
                    "reference": pin(bundle_paths[artifact.relative_path], artifact.raw),
                }
                for artifact in bundle.artifacts
            ],
        },
        "execution_inputs": {
            name: pin(execution_paths[name], raw) for name, raw in execution_raws.items()
        },
    }
    bootstrap_raw = canonical_json_bytes(payload)
    bootstrap_path = _write_raw(bootstrap_parent / "route-bootstrap.json", bootstrap_raw)
    bootstrap_pin = pin(bootstrap_path, bootstrap_raw)
    reference = build_gate_b_v2_pinned_spec_reference(
        parent_absolute_path=bootstrap_parent,
        parent_identity_scheme=bootstrap_pin["parent_identity_scheme"],
        parent_serialization_profile=bootstrap_pin["parent_serialization_profile"],
        parent_volume_id_hex=bootstrap_pin["parent_volume_id_hex"],
        parent_file_id_hex=bootstrap_pin["parent_file_id_hex"],
        direct_child_name=bootstrap_pin["direct_child_name"],
        expected_sha256=bootstrap_pin["expected_sha256"],
        expected_size_bytes=bootstrap_pin["expected_size_bytes"],
    )
    return source, chain, request, spec, kwargs, reference


@WINDOWS_PRODUCTION
def test_v2_production_plan_reuses_published_chain_and_is_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    created = []

    def forbidden_create(*_args, **_kwargs):
        created.append("create")
        raise AssertionError("write-free v2 plan reached artifact creation")

    monkeypatch.setattr(GateBPinnedDirectory, "create_regular", forbidden_create)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    assert validate_gate_b_v2_execution_plan(plan) is plan
    assert plan.compatibility_chain is chain
    assert plan.request.attempt_ordinal == 1
    assert plan.execution_binding_sha256 == plan.artifact_hashes["one_shot_spec"]
    assert (
        plan.request.roots["ledger_base"]["anchor_sha256"]
        == chain.artifact_hashes["ledger_root_anchor"]
    )
    assert tuple(plan.artifact_hashes) == (
        "compatibility_preflight_request",
        "phase6_contract_bundle_root_manifest",
        "phase6_contract_bundle_provenance",
        "approval_record",
        "signature_record",
        "readiness_authorization",
        "ledger_root_anchor",
        "quarantine_root_anchor",
        "loader_request",
        "execution_context",
        "batch_manifest",
        "one_shot_spec",
    )
    assert created == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda spec: spec.__setitem__("loader_request_sha256", "f" * 64),
        lambda spec: spec.__setitem__("expected_latest_record_sha256", "f" * 64),
        lambda spec: spec.__setitem__("operation_timeout_seconds", 7200.0),
        lambda spec: spec["output_limits"].__setitem__("stdout", True),
        lambda spec: spec["projection_descriptor"].__setitem__(
            "serialization_profile", "windows-minimal-lowerhex-v1"
        ),
        lambda spec: spec.__setitem__("science_commit", "f" * 40),
        lambda spec: spec.__setitem__("execution_route_commit", spec["science_commit"]),
        lambda spec: spec.__setitem__("active_module_sources_sha256", "f" * 64),
        lambda spec: spec.__setitem__("execution_route_attestation_sha256", "f" * 64),
        lambda spec: spec.update({"unknown": None}),
    ],
)
def test_v2_plan_rejects_spec_drift_before_any_retained_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation,
) -> None:
    _source, chain, _request, spec, kwargs = _production_plan_fixture(tmp_path)
    mutation(spec)
    changed = canonical_json_bytes(spec)
    kwargs["one_shot_spec_raw"] = changed
    _write_raw(kwargs["one_shot_spec_path"], changed)
    opened = []

    def forbidden_open(*_args, **_kwargs):
        opened.append("open")
        raise AssertionError("invalid v2 plan reached retained-root open")

    monkeypatch.setattr(route_module, "open_gate_b_v2_pinned_directory", forbidden_open)
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)
    assert opened == []


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("requested_at_utc", "2026-08-01T01:04:00.0Z"),
        ("attempt_ordinal", True),
        ("attempt_ordinal", 1.0),
    ],
)
def test_v2_request_rejects_nonexact_timestamp_and_json_integer(
    tmp_path: Path,
    field: str,
    invalid: object,
) -> None:
    _source, chain, request, _spec, kwargs = _production_plan_fixture(tmp_path)
    request[field] = invalid
    changed = canonical_json_bytes(request)
    kwargs["loader_request_raw"] = changed
    _write_raw(kwargs["loader_request_path"], changed)
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)


def test_v2_plan_requires_bytes_to_exist_at_the_declared_pinned_path(tmp_path: Path) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    kwargs["approval_record_path"] = tmp_path / "missing-approval.json"
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)


@pytest.mark.parametrize(
    "path_field",
    [
        "approval_record_path",
        "signature_record_path",
        "readiness_authorization_path",
        "loader_request_path",
        "execution_context_path",
        "batch_manifest_path",
        "one_shot_spec_path",
    ],
)
@pytest.mark.parametrize("attack", ["unc", "device", "ads", "nonfixed"])
def test_direct_planner_rejects_every_nonlocal_artifact_path_before_any_open(
    tmp_path: Path,
    path_field: str,
    attack: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    invalid = {
        "unc": Path(r"\\server\share\artifact.json"),
        "device": Path(r"\\?\C:\gate-b\artifact.json"),
        "ads": Path(r"C:\gate-b\artifact.json:stream"),
        "nonfixed": Path(r"Z:\gate-b\artifact.json"),
    }[attack]
    kwargs[path_field] = invalid
    opened: list[str] = []
    monkeypatch.setattr(
        route_module.GateBPinnedDirectory,
        "open",
        lambda *_args, **_kwargs: opened.append("opened"),
    )
    if attack == "nonfixed":
        monkeypatch.setattr(
            route_module,
            "_windows_drive_type",
            lambda root: 4 if root.upper().startswith("Z:") else 3,
        )
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)
    assert opened == []


def test_non_windows_direct_planner_imports_and_fails_before_any_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    opened: list[str] = []
    monkeypatch.setattr(route_module.os, "name", "posix")
    monkeypatch.setattr(
        route_module.GateBPinnedDirectory,
        "open",
        lambda *_args, **_kwargs: opened.append("opened"),
    )
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)
    assert opened == []


@pytest.mark.parametrize(
    ("artifact", "field", "attack"),
    [
        ("loader_request", "batch_manifest", r"\\server\share\batch.json"),
        ("loader_request", "execution_context", r"\\?\C:\context.json"),
        ("execution_context", "repository_root", r"C:\repo:stream"),
        ("execution_context", "dependency_lock", r"Z:\dependency-lock.json"),
    ],
)
def test_embedded_request_and_context_paths_fail_before_any_parent_open(
    artifact: str,
    field: str,
    attack: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, request, _spec, kwargs = _production_plan_fixture(tmp_path)
    payload = (
        copy.deepcopy(request)
        if artifact == "loader_request"
        else copy.deepcopy(_plain(_source.request.execution_context.payload))
    )
    if artifact == "execution_context":
        payload = copy.deepcopy(
            route_module._strict_canonical_object(
                kwargs["execution_context_raw"],
                "fixture context",
            )
        )
    payload[field]["absolute_path"] = attack
    kwargs[f"{artifact}_raw"] = canonical_json_bytes(payload)
    opened: list[str] = []
    monkeypatch.setattr(
        route_module.GateBPinnedDirectory,
        "open",
        lambda *_args, **_kwargs: opened.append("open"),
    )
    monkeypatch.setattr(
        route_module,
        "_verify_directory",
        lambda *_args, **_kwargs: opened.append("verify-directory"),
    )
    if attack.startswith("Z:"):
        monkeypatch.setattr(
            route_module,
            "_windows_drive_type",
            lambda root: 4 if root.upper().startswith("Z:") else 3,
        )
    with pytest.raises(GateBV2RouteError):
        build_gate_b_v2_execution_plan(chain, **kwargs)
    assert opened == []


def test_route_attestation_is_commit_agnostic_and_has_closed_runtime_inventory() -> None:
    digest = loader_module.gate_b_v2_route_attestation_sha256("a" * 40, "b" * 40)
    other = loader_module.gate_b_v2_route_attestation_sha256("a" * 40, "c" * 40)
    assert len(digest) == 64
    assert digest != other
    inventory = {name for name, _path in loader_module.GATE_B_V2_ROUTE_MODULE_PATHS}
    assert {
        "phase6.gate_b_v2_route",
        "phase6.gate_b_orchestrator",
        "phase6.gate_b_v2_cli",
        "phase6.gate_b_executor",
        "phase6.calibration",
        "phase6.exact_ev",
        "phase6.p6_7",
        "phase6.production_inputs",
        "opponents.ground_truth",
        "opponents.model",
        "opponents.synthesis",
        "poker_ai.exploit",
        "poker_ai.leak",
        "poker_ai.mixer",
        "poker_ai.observation",
        "poker_solver.best_response",
        "poker_solver.game",
        "poker_solver.nodelock",
        "poker_solver.strategy",
    } <= inventory
    executor_tree = ast.parse(
        (Path(loader_module.__file__).with_name("gate_b_executor.py")).read_bytes()
    )
    direct_project_modules = {
        node.module
        for node in executor_tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.split(".", 1)[0] in {"opponents", "phase6", "poker_ai", "poker_solver"}
    }
    assert direct_project_modules <= inventory
    assert "src/phase6/exact_ev.py" not in loader_module.GATE_B_V2_ROUTE_ALLOWED_CHANGE_PATHS
    assert "src/phase6/gate_b_executor.py" not in loader_module.GATE_B_V2_ROUTE_ALLOWED_CHANGE_PATHS


def test_route_diff_rejects_forbidden_scientific_source_even_for_approved_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        loader_module,
        "_run_git",
        lambda *_args, **_kwargs: "src/phase6/exact_ev.py\n",
    )
    with pytest.raises(loader_module.GateBExecutionEnvironmentFailure):
        loader_module._verify_gate_b_v2_route_diff(Path.cwd(), "a" * 40, "b" * 40)


def test_route_diff_accepts_only_the_closed_route_change_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = "src/phase6/gate_b_v2_route.py\ntests/phase6/test_gate_b_v2_route.py\n"
    monkeypatch.setattr(loader_module, "_run_git", lambda *_args, **_kwargs: changed)
    assert loader_module._verify_gate_b_v2_route_diff(
        Path.cwd(),
        "a" * 40,
        "b" * 40,
    ) == (
        "src/phase6/gate_b_v2_route.py",
        "tests/phase6/test_gate_b_v2_route.py",
    )


@pytest.mark.parametrize("kind", ["missing", "blob", "resolved-as-other-object"])
def test_route_commit_must_resolve_to_the_exact_git_commit_object(
    kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "b" * 40

    def git_probe(_root: Path, *arguments, **_kwargs):
        if arguments[:2] == ("cat-file", "-e"):
            if kind in {"missing", "blob"}:
                raise loader_module.GateBExecutionEnvironmentFailure("not a commit")
            return ""
        if arguments[:1] == ("rev-parse",):
            return ("c" * 40 if kind == "resolved-as-other-object" else commit) + "\n"
        raise AssertionError(arguments)

    monkeypatch.setattr(loader_module, "_run_git", git_probe)
    with pytest.raises(loader_module.GateBExecutionEnvironmentFailure):
        loader_module._verify_commit_object(Path.cwd(), commit, "execution route")


@pytest.mark.parametrize(
    "drifted_path",
    [
        "src/phase6/gate_b_v2_route.py",
        "src/phase6/gate_b_orchestrator.py",
        "src/phase6/gate_b_v2_cli.py",
        "src/phase6/gate_b_executor.py",
    ],
)
def test_each_required_route_source_drift_fails_attestation(
    drifted_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path.cwd()

    def committed_blob(_root: Path, _commit: str, relative_path: str) -> bytes:
        raw = (root / relative_path).read_bytes()
        return b"# drifted route blob\n" if relative_path == drifted_path else raw

    monkeypatch.setattr(loader_module, "_commit_blob", committed_blob)
    with pytest.raises(loader_module.GateBExecutionEnvironmentFailure):
        loader_module._v2_route_module_sources(root, "b" * 40)


@pytest.mark.parametrize(
    ("raw", "blob"),
    [
        (b"value = 1\n", b"value = 1\n"),
        (b"value = 1\r\nnext_value = 2\r\n", b"value = 1\nnext_value = 2\n"),
        (b'value = b"\\r\\n"\r\n', b'value = b"\\r\\n"\n'),
    ],
)
def test_route_source_binding_accepts_only_exact_or_complete_crlf_checkout(
    raw: bytes,
    blob: bytes,
) -> None:
    assert loader_module._working_tree_source_matches_git_blob(raw, blob)


@pytest.mark.parametrize(
    ("raw", "blob"),
    [
        (b"changed = 2\r\n", b"value = 1\n"),
        (b"value = 1 \r\n", b"value = 1\n"),
        (b"value = 1\r\nnext_value = 2\n", b"value = 1\nnext_value = 2\n"),
        (b"value = 1", b"value = 1\n"),
        (b"value = 1\r", b"value = 1\n"),
        (b"value = 1\r\r\n", b"value = 1\n"),
        (b"value = 1\r\n\r\n", b"value = 1\n"),
        (b"\xef\xbb\xbfvalue = 1\r\n", b"value = 1\n"),
        (b"value = 1\r\n", b"value = 1\r\nnext_value = 2\r\n"),
        (b"value = 1\r\n", b"value = 1\r\n"),
    ],
)
def test_route_source_binding_rejects_partial_or_non_newline_drift(
    raw: bytes,
    blob: bytes,
) -> None:
    assert not loader_module._working_tree_source_matches_git_blob(raw, blob)


def test_route_source_attestation_hashes_the_canonical_git_blob(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path.cwd()
    blob = b"value = 1\n"
    monkeypatch.setattr(loader_module, "_read_pinned", lambda *_args: b"value = 1\r\n")
    monkeypatch.setattr(loader_module, "_commit_blob", lambda *_args: blob)
    monkeypatch.setattr(loader_module, "_verify_executed_source_code", lambda *_args: "a" * 64)
    sources = loader_module._v2_route_module_sources(root, "b" * 40)
    assert len(sources) == len(loader_module.GATE_B_V2_ROUTE_MODULE_PATHS)
    assert {entry["sha256"] for entry in sources} == {sha256_bytes(blob)}


@WINDOWS_PRODUCTION
def test_v2_plan_rejects_runtime_request_object_setattr_tamper(tmp_path: Path) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    plain_roots = MappingProxyType(
        {role: MappingProxyType(dict(root)) for role, root in _plain(plan.request.roots).items()}
    )
    object.__setattr__(plan.request, "roots", plain_roots)
    with pytest.raises(GateBV2RouteError):
        validate_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_v2_plan_rejects_replacing_even_equivalent_valid_bundle_evidence(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    other = _build_genuine_evidence()
    assert other is not plan.phase6_contract_bundle_evidence
    assert other.provenance_sha256 == plan.phase6_contract_bundle_evidence.provenance_sha256
    object.__setattr__(plan, "phase6_contract_bundle_evidence", other)
    with pytest.raises(GateBV2RouteError):
        validate_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_ledger_dispatch_accepts_only_nominal_v2_ref_and_exact_published_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    ref = plan.request.roots["ledger_base"]
    metadata = SimpleNamespace(
        st_ino=int(ref["file_id_hex"], 16),
        st_dev=int(ref["volume_id_hex"], 16),
    )
    monkeypatch.setattr(ledger_module, "_verify_directory", lambda *_args: metadata)
    monkeypatch.setattr(
        ledger_module,
        "_read_pinned",
        lambda *_args: chain._artifact_raws["ledger_root_anchor"],
    )
    assert ledger_module._verify_root_ref(ref, "ledger_base") == Path(ref["absolute_path"])
    with pytest.raises(GateBLedgerError):
        ledger_module._verify_root_ref(dict(ref), "ledger_base")

    monkeypatch.setattr(ledger_module, "_read_pinned", lambda *_args: b"{}\n")
    with pytest.raises((GateBLedgerError, GateBV2RouteError)):
        ledger_module._verify_root_ref(ref, "ledger_base")


class _FakePinnedRoot:
    def __init__(self, role: str, chain, close_log: list[str] | None = None) -> None:
        self.role = role
        self.chain = chain
        self.close_log = close_log
        self.closed = False
        self.drift = False

    def direct_child_names(self):
        if self.drift:
            return (".gate-b-root-anchor.json", "unexpected")
        return () if self.role == "test_root" else (".gate-b-root-anchor.json",)

    def read_regular(self, _name, *, expected_sha256, expected_size_bytes):
        artifact = f"{self.role.removesuffix('_base')}_root_anchor"
        raw = self.chain._artifact_raws[artifact]
        assert sha256_bytes(raw) == expected_sha256
        assert len(raw) == expected_size_bytes
        return SimpleNamespace(raw=raw)

    def close(self):
        self.closed = True
        if self.close_log is not None:
            self.close_log.append(self.role)


def _prepare_with_fake_roots(
    plan,
    chain,
    monkeypatch: pytest.MonkeyPatch,
    *,
    close_log: list[str] | None = None,
):
    roots: dict[str, _FakePinnedRoot] = {}
    by_path = {root["absolute_path"]: role for role, root in _plain(chain.roots).items()}

    def fake_open(path, **_kwargs):
        role = by_path[path]
        roots[role] = _FakePinnedRoot(role, chain, close_log)
        return roots[role]

    monkeypatch.setattr(route_module, "open_gate_b_v2_pinned_directory", fake_open)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_pinned_directory", lambda *_a, **_k: None)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_retained_root_topology", lambda *_a: None)
    monkeypatch.setattr(
        route_module,
        "verify_gate_b_v2_runtime_execution_environment",
        lambda request, _context: _evidence(request),
    )
    route = prepare_gate_b_v2_execution_route(
        plan,
    )
    return route, roots


@WINDOWS_PRODUCTION
def test_initial_prewrite_failure_repeatedly_releases_every_registered_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registries = {
        "plans": route_module._PLAN_REGISTRY,
        "plan_routes": route_module._PLAN_ROUTE_OWNERS,
        "prepared": route_module._PREPARED_REGISTRY,
        "artifacts": route_module._ARTIFACT_REGISTRY,
        "root_refs": route_module._ROOT_REF_REGISTRY,
        "input_owners": route_module._INPUT_OWNER_REGISTRY,
        "origins": route_module._V2_RUNTIME_REQUEST_ORIGINS,
        "runtime_plans": route_module._V2_RUNTIME_REQUEST_PLANS,
        "authorizations": route_module._V2_RESERVATION_AUTHORIZATIONS,
    }
    baselines = {name: set(registry) for name, registry in registries.items()}
    captured_routes = []
    captured_executors = []
    executor_references = []
    request_references = []

    monkeypatch.setattr(route_module, "verify_gate_b_v2_pinned_directory", lambda *_a, **_k: None)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_retained_root_topology", lambda *_a: None)

    def reject_runtime(request, _context):
        route = next(
            snapshot[0]
            for snapshot in route_module._PREPARED_REGISTRY.values()
            if snapshot[1].request is request
        )
        captured_routes.append(route)
        captured_executors.append(route.executor)
        executor_references.append(weakref.ref(route.executor))
        request_references.append(weakref.ref(request))
        raise ValueError("forced initial pre-write failure")

    monkeypatch.setattr(
        route_module,
        "verify_gate_b_v2_runtime_execution_environment",
        reject_runtime,
    )

    for attempt in range(3):
        _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path / str(attempt))
        plan = build_gate_b_v2_execution_plan(chain, **kwargs)
        artifacts = tuple(plan._artifacts.values())
        owners = plan._input_owners
        root_references = tuple(plan.request.roots.values())
        bundle = plan.phase6_contract_bundle_evidence
        bundle_artifacts = bundle.artifacts
        projection = chain.projection
        roots = []
        by_path = {root["absolute_path"]: role for role, root in _plain(chain.roots).items()}

        def fake_open(
            path,
            _by_path=by_path,
            _chain=chain,
            _roots=roots,
            **_kwargs,
        ):
            root = _FakePinnedRoot(_by_path[path], _chain)
            _roots.append(root)
            return root

        monkeypatch.setattr(route_module, "open_gate_b_v2_pinned_directory", fake_open)
        with pytest.raises(GateBV2RouteError, match="environment failed before reservation"):
            prepare_gate_b_v2_execution_route(plan)

        failed_route = captured_routes[-1]
        failed_executor = captured_executors[-1]
        assert failed_route._closed
        assert failed_route.plan is None and failed_route.executor is None
        assert not failed_route._directories and failed_route._executor_provenance == ()
        assert failed_executor._phase6_contract_bundle_evidence is None
        assert not failed_executor._manifest
        assert plan._closed and plan.request is None
        assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in artifacts)
        assert all(
            owner._closed and not owner.artifacts and not owner.directories for owner in owners
        )
        assert all(
            reference._anchor_raw is None and not reference._payload
            for reference in root_references
        )
        assert bundle.root_manifest_raw == b"" and not bundle.artifacts
        assert all(artifact.raw == b"" for artifact in bundle_artifacts)
        assert chain.projection is None and not chain._artifact_raws
        assert projection.canonical_bytes == b""
        assert all(root.closed for root in roots)
        for name, registry in registries.items():
            assert set(registry) == baselines[name]

    captured_routes.clear()
    captured_executors.clear()
    del failed_executor, failed_route, plan
    gc.collect()
    assert all(reference() is None for reference in executor_references)
    assert all(reference() is None for reference in request_references)


@WINDOWS_PRODUCTION
def test_plan_prepare_has_exclusive_route_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    registered_routes = set(route_module._PREPARED_REGISTRY)

    with pytest.raises(GateBV2RouteError, match="execution plan is already prepared"):
        prepare_gate_b_v2_execution_route(plan)

    assert set(route_module._PREPARED_REGISTRY) == registered_routes
    owner = route_module._PLAN_ROUTE_OWNERS[id(plan)]
    assert owner[0] is plan and owner[1] is route
    assert not route._closed and not any(root.closed for root in roots.values())
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
def test_prepared_plan_direct_close_owns_route_and_retained_root_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    executor = route.executor
    plan_id = id(plan)
    route_id = id(route)

    close_gate_b_v2_execution_plan(plan)

    assert all(root.closed for root in roots.values())
    assert plan_id not in route_module._PLAN_ROUTE_OWNERS
    assert plan_id not in route_module._PLAN_REGISTRY
    assert route_id not in route_module._PREPARED_REGISTRY
    assert route._closed and route.plan is None and route.executor is None
    assert executor._phase6_contract_bundle_evidence is None and not executor._manifest
    close_gate_b_v2_execution_route(route)
    close_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_unprepared_plan_has_explicit_idempotent_close_and_unregisters_request(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    owners = plan._input_owners
    request = plan.request
    assert route_module.is_gate_b_v2_runtime_request(request)
    close_gate_b_v2_execution_plan(plan)
    assert all(owner._closed for owner in owners)
    assert route_module.is_gate_b_v2_runtime_request(request)
    assert request._v2_reservation_state == "closed"
    with pytest.raises(GateBLedgerError):
        GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None)
    close_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_plan_owner_inventory_tamper_still_closes_registered_original_handles(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    original_owners = plan._input_owners
    request = plan.request
    object.__setattr__(plan, "_input_owners", ())
    with pytest.raises(GateBV2RouteError):
        close_gate_b_v2_execution_plan(plan)
    assert all(owner._closed for owner in original_owners)
    assert route_module.is_gate_b_v2_runtime_request(request)


@WINDOWS_PRODUCTION
def test_direct_plan_request_cannot_reserve_without_consumed_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    writes: list[str] = []
    monkeypatch.setattr(
        loader_module,
        "_reserve_attempt",
        lambda *_args, **_kwargs: writes.append("reserved"),
    )
    with pytest.raises(GateBLedgerError):
        loader_module.reserve_gate_b_attempt(
            plan.request,
            expected_latest_record_sha256=None,
        )
    assert writes == []


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("attack", ["state", "origin", "combined"])
def test_runtime_request_marker_tamper_cannot_forge_reserve_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    request = plan.request
    writes: list[str] = []
    monkeypatch.setattr(
        ledger_module,
        "_reserve_attempt",
        lambda *_args, **_kwargs: writes.append("reserved"),
    )
    if attack == "state":
        object.__setattr__(plan.request, "_v2_reservation_state", "authorized")
    else:
        object.__setattr__(plan.request, "_v2_reservation_origin", None)
        object.__setattr__(plan.request, "_v2_reservation_state", "legacy")
        if attack == "combined":
            object.__setattr__(plan.request, "_payload", MappingProxyType({}))
    with pytest.raises(GateBLedgerError):
        GateBLedgerStore.reserve_attempt(plan.request, expected_latest_record_sha256=None)
    assert writes == []
    with pytest.raises(GateBV2RouteError, match="v2 execution-plan close provenance mismatch"):
        close_gate_b_v2_execution_plan(plan)
    assert id(plan) not in route_module._PLAN_REGISTRY
    assert plan.request is None and request._v2_reservation_state == "closed"


@WINDOWS_PRODUCTION
def test_consumed_production_route_mints_exactly_one_reserve_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    writes: list[str] = []
    reservation = object()

    def reserve(*_args, **_kwargs):
        writes.append("reserved")
        return reservation

    monkeypatch.setattr(ledger_module, "_reserve_attempt", reserve)
    assert (
        loader_module.reserve_gate_b_attempt(
            request,
            expected_latest_record_sha256=None,
        )
        is reservation
    )
    with pytest.raises(GateBLedgerError):
        loader_module.reserve_gate_b_attempt(
            request,
            expected_latest_record_sha256=None,
        )
    assert writes == ["reserved"]
    close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_store_reserve_entrypoint_consumes_the_same_one_shot_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    reservation = object()
    writes: list[str] = []

    def reserve(*_args, **_kwargs):
        writes.append("reserved")
        return reservation

    monkeypatch.setattr(ledger_module, "_reserve_attempt", reserve)
    copied_request = copy.copy(request)
    object.__setattr__(copied_request, "_payload", MappingProxyType({}))
    with pytest.raises(GateBLedgerError):
        GateBLedgerStore.reserve_attempt(copied_request, expected_latest_record_sha256=None)
    assert (
        GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None) is reservation
    )
    with pytest.raises(GateBLedgerError):
        GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None)
    with pytest.raises(GateBLedgerError):
        loader_module.reserve_gate_b_attempt(request, expected_latest_record_sha256=None)
    assert writes == ["reserved"]
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("entrypoint", ["loader", "store"])
@pytest.mark.parametrize(
    "mutation",
    ["copy-only", "marker", "payload", "marker-and-payload"],
)
def test_v2_derived_request_copy_is_rejected_by_both_public_reserve_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    mutation: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    copied_request = copy.copy(request)
    if mutation in {"marker", "marker-and-payload"}:
        object.__setattr__(copied_request, "_v2_reservation_origin", None)
        object.__setattr__(copied_request, "_v2_reservation_state", "legacy")
        object.__setattr__(copied_request, "_v2_reservation_authorization", None)
    if mutation in {"payload", "marker-and-payload"}:
        object.__setattr__(copied_request, "_payload", MappingProxyType({}))
    assert route_module.is_gate_b_v2_runtime_request(copied_request)

    lower_reserve_calls: list[str] = []
    if entrypoint == "loader":
        monkeypatch.setattr(
            ledger_module.GateBLedgerStore,
            "reserve_attempt",
            staticmethod(lambda *_args, **_kwargs: lower_reserve_calls.append("store")),
        )
        call = loader_module.reserve_gate_b_attempt
    else:
        monkeypatch.setattr(
            ledger_module,
            "_reserve_attempt",
            lambda *_args, **_kwargs: lower_reserve_calls.append("ledger"),
        )
        call = GateBLedgerStore.reserve_attempt

    with pytest.raises(GateBLedgerError):
        call(copied_request, expected_latest_record_sha256=None)
    assert lower_reserve_calls == []
    assert request._v2_reservation_state == "authorized"
    assert id(request) in route_module._V2_RESERVATION_AUTHORIZATIONS
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
def test_consume_then_close_cleans_request_lifecycle_and_rejects_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    request_id = id(request)
    plan_id = id(plan)
    route_id = id(route)
    lower_reserve_calls: list[str] = []
    monkeypatch.setattr(
        ledger_module,
        "_reserve_attempt",
        lambda *_args, **_kwargs: lower_reserve_calls.append("ledger"),
    )

    close_gate_b_v2_execution_route(route)

    assert request._v2_reservation_state == "closed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RUNTIME_REQUEST_ORIGINS
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_PLANS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_COPY_PROVENANCE
    assert plan_id not in route_module._PLAN_ROUTE_OWNERS
    assert route_id not in route_module._PREPARED_REGISTRY
    for call in (loader_module.reserve_gate_b_attempt, GateBLedgerStore.reserve_attempt):
        with pytest.raises(GateBLedgerError):
            call(request, expected_latest_record_sha256=None)
    assert lower_reserve_calls == []
    with pytest.raises(GateBV2RouteError):
        route.consume()


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("entrypoint", ["loader", "store"])
def test_consume_reserve_then_close_cleans_request_lifecycle_and_rejects_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    request_id = id(request)
    lower_reserve_calls: list[str] = []
    reservation = object()

    def lower_reserve(*_args, **_kwargs):
        lower_reserve_calls.append("ledger")
        return reservation

    monkeypatch.setattr(ledger_module, "_reserve_attempt", lower_reserve)
    call = (
        loader_module.reserve_gate_b_attempt
        if entrypoint == "loader"
        else GateBLedgerStore.reserve_attempt
    )
    assert call(request, expected_latest_record_sha256=None) is reservation
    assert request._v2_reservation_state == "consumed"

    close_gate_b_v2_execution_route(route)

    assert request._v2_reservation_state == "closed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RUNTIME_REQUEST_ORIGINS
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_PLANS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_COPY_PROVENANCE
    for reuse in (loader_module.reserve_gate_b_attempt, GateBLedgerStore.reserve_attempt):
        with pytest.raises(GateBLedgerError):
            reuse(request, expected_latest_record_sha256=None)
    assert lower_reserve_calls == ["ledger"]


@WINDOWS_PRODUCTION
def test_reserve_authorization_is_atomic_across_public_entrypoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    barrier = threading.Barrier(2)
    writes: list[str] = []
    reservation = object()

    def reserve(*_args, **_kwargs):
        writes.append("reserved")
        return reservation

    def call(entrypoint):
        barrier.wait()
        try:
            return entrypoint(request, expected_latest_record_sha256=None)
        except GateBLedgerError:
            return "rejected"

    monkeypatch.setattr(ledger_module, "_reserve_attempt", reserve)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            future.result()
            for future in (
                pool.submit(call, GateBLedgerStore.reserve_attempt),
                pool.submit(call, loader_module.reserve_gate_b_attempt),
            )
        )
    assert outcomes.count(reservation) == 1
    assert outcomes.count("rejected") == 1
    assert writes == ["reserved"]
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("entrypoint", ["loader", "store"])
def test_reserve_transaction_excludes_close_before_and_during_lower_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    request_id = id(request)
    batch = request.batch
    readiness = request.readiness
    execution_context = request.execution_context
    root_references = dict(request.roots)
    owners = plan._input_owners
    artifacts = tuple(plan._artifacts.values())
    reservation = object()
    authorization_checked = threading.Event()
    allow_lower_start = threading.Event()
    lower_started = threading.Event()
    allow_lower_finish = threading.Event()
    close_started = threading.Event()
    lower_reserve_calls: list[object] = []
    match_calls = 0
    transaction_match_call = 2 if entrypoint == "loader" else 1
    real_authorization_matches = route_module._authorization_entry_matches

    def ordered_authorization_matches(entry, observed_request, observed_plan):
        nonlocal match_calls
        matches = real_authorization_matches(entry, observed_request, observed_plan)
        if observed_request is request and matches:
            match_calls += 1
            if match_calls == transaction_match_call:
                authorization_checked.set()
                assert allow_lower_start.wait(30)
        return matches

    def assert_request_graph_is_live() -> None:
        assert route.plan is plan and not route._closed
        assert plan.request is request and not plan._closed
        assert request.batch is batch
        assert request.readiness is readiness
        assert request.execution_context is execution_context
        assert dict(request.roots) == root_references
        assert request._v2_reservation_state == "authorized"
        assert request_id in route_module._V2_RUNTIME_REQUEST_ORIGINS
        assert request_id in route_module._V2_RESERVATION_AUTHORIZATIONS
        assert route_module._V2_RUNTIME_REQUEST_PLANS[request_id] is plan
        assert all(not owner._closed for owner in owners)
        assert all(artifact.raw for artifact in artifacts)
        assert all(not root.closed for root in roots.values())

    def lower_reserve(observed_request, *, expected_latest_record_sha256):
        assert observed_request is request
        assert expected_latest_record_sha256 is None
        assert_request_graph_is_live()
        lower_reserve_calls.append(observed_request)
        lower_started.set()
        assert allow_lower_finish.wait(30)
        assert_request_graph_is_live()
        return reservation

    monkeypatch.setattr(
        route_module,
        "_authorization_entry_matches",
        ordered_authorization_matches,
    )
    monkeypatch.setattr(ledger_module, "_reserve_attempt", lower_reserve)
    reserve = (
        loader_module.reserve_gate_b_attempt
        if entrypoint == "loader"
        else GateBLedgerStore.reserve_attempt
    )

    def reserve_worker():
        return reserve(request, expected_latest_record_sha256=None)

    def close_worker():
        close_started.set()
        close_gate_b_v2_execution_route(route)
        return "closed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        reserve_future = pool.submit(reserve_worker)
        assert authorization_checked.wait(30)
        close_future = pool.submit(close_worker)
        assert close_started.wait(30)
        assert not close_future.done()
        assert lower_reserve_calls == []
        assert_request_graph_is_live()

        allow_lower_start.set()
        assert lower_started.wait(30)
        assert not close_future.done()
        assert lower_reserve_calls == [request]
        assert_request_graph_is_live()

        allow_lower_finish.set()
        assert reserve_future.result(timeout=45) is reservation
        assert close_future.result(timeout=45) == "closed"

    assert request._v2_reservation_state == "closed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RUNTIME_REQUEST_ORIGINS
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_PLANS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_COPY_PROVENANCE
    assert route._closed and route.plan is None and route.executor is None
    assert plan.request is None
    assert all(root.closed for root in roots.values())
    for retry in (loader_module.reserve_gate_b_attempt, GateBLedgerStore.reserve_attempt):
        with pytest.raises(GateBLedgerError):
            retry(request, expected_latest_record_sha256=None)
    assert lower_reserve_calls == [request]
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("entrypoint", ["loader", "store"])
def test_lower_reserve_failure_preserves_authorization_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    request_id = id(request)
    reservation = object()
    lower_reserve_calls: list[object] = []

    def lower_reserve(observed_request, *, expected_latest_record_sha256):
        assert observed_request is request
        assert expected_latest_record_sha256 is None
        assert observed_request.batch is request.batch
        assert observed_request.readiness is request.readiness
        assert observed_request.execution_context is request.execution_context
        assert dict(observed_request.roots) == dict(request.roots)
        lower_reserve_calls.append(observed_request)
        if len(lower_reserve_calls) == 1:
            raise GateBLedgerError("forced lower reservation failure")
        return reservation

    monkeypatch.setattr(ledger_module, "_reserve_attempt", lower_reserve)
    reserve = (
        loader_module.reserve_gate_b_attempt
        if entrypoint == "loader"
        else GateBLedgerStore.reserve_attempt
    )

    with pytest.raises(GateBLedgerError, match="forced lower reservation failure"):
        reserve(request, expected_latest_record_sha256=None)

    assert request._v2_reservation_state == "authorized"
    assert request._v2_reservation_authorization is route_module._V2_RESERVATION_AUTHORIZATION_TOKEN
    assert request_id in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert route_module._V2_RUNTIME_REQUEST_PLANS[request_id] is plan
    assert route.plan is plan and plan.request is request
    assert all(not root.closed for root in roots.values())

    assert reserve(request, expected_latest_record_sha256=None) is reservation
    assert lower_reserve_calls == [request, request]
    assert request._v2_reservation_state == "consumed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS

    close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_post_consume_route_tamper_invalidates_reserve_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    writes: list[str] = []
    monkeypatch.setattr(
        ledger_module,
        "_reserve_attempt",
        lambda *_args, **_kwargs: writes.append("reserved"),
    )
    object.__setattr__(route, "_consumed", False)
    with pytest.raises(GateBLedgerError):
        GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None)
    assert writes == []
    with pytest.raises(GateBV2RouteError):
        close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_route_close_releases_registries_object_graph_and_artifact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    artifacts = tuple(plan._artifacts.values())
    owners = plan._input_owners
    root_references = tuple(plan.request.roots.values())
    batch = plan.request.batch
    readiness = plan.request.readiness
    context = plan.request.execution_context
    bundle_evidence = plan.phase6_contract_bundle_evidence
    bundle_artifacts = bundle_evidence.artifacts
    projection = chain.projection
    route, _roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    executor = route.executor
    route_id = id(route)
    plan_id = id(plan)
    close_gate_b_v2_execution_route(route)
    assert route_id not in route_module._PREPARED_REGISTRY
    assert plan_id not in route_module._PLAN_ROUTE_OWNERS
    assert plan_id not in route_module._PLAN_REGISTRY
    assert all(id(artifact) not in route_module._ARTIFACT_REGISTRY for artifact in artifacts)
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in artifacts)
    assert all(owner._closed and not owner.artifacts for owner in owners)
    assert all(
        id(reference) not in route_module._ROOT_REF_REGISTRY for reference in root_references
    )
    assert all(
        reference._anchor_raw is None and not reference._payload for reference in root_references
    )
    assert id(bundle_evidence) not in route_module.contracts_module._BUNDLE_EVIDENCE_REGISTRY
    assert bundle_evidence.root_manifest_raw == b"" and not bundle_evidence.artifacts
    assert all(artifact.raw == b"" for artifact in bundle_artifacts)
    assert batch.raw_bytes == b"" and not batch.payload
    assert readiness._raw == b"" and not readiness.payload
    assert context._raw == b"" and not context.payload
    assert executor._phase6_contract_bundle_evidence is None and not executor._manifest
    assert not chain._artifact_raws and chain.projection is None
    assert projection.canonical_bytes == b""
    assert id(chain) not in route_module.gate_b_contracts_module._V2_TRUST_CHAIN_REGISTRY
    assert id(projection) not in route_module.gate_b_contracts_module._V2_PROJECTION_REGISTRY
    assert route.plan is None and route.executor is None
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("entrypoint", ["loader", "store"])
@pytest.mark.parametrize(
    "corruption",
    ["origin-tuple", "state-list", "origin-marker", "authorization-marker"],
)
def test_public_reserve_rejects_malformed_lifecycle_without_raw_error_and_closes_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    corruption: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    request, _executor = route.consume()
    request_id = id(request)
    owners = plan._input_owners
    owner_artifacts = tuple(artifact for owner in owners for artifact in owner.artifacts.values())
    plan_artifacts = tuple(plan._artifacts.values())
    root_references = tuple(request.roots.values())
    bundle = plan.phase6_contract_bundle_evidence
    bundle_artifacts = bundle.artifacts
    lower_reserve_calls: list[object] = []

    monkeypatch.setattr(
        ledger_module,
        "_reserve_attempt",
        lambda *_args, **_kwargs: lower_reserve_calls.append(request),
    )
    if corruption == "origin-tuple":
        route_module._V2_RUNTIME_REQUEST_ORIGINS[request_id] = (weakref.ref(request),)
    elif corruption == "state-list":
        object.__setattr__(request, "_v2_reservation_state", [])
    elif corruption == "origin-marker":
        object.__setattr__(request, "_v2_reservation_origin", None)
    else:
        object.__setattr__(request, "_v2_reservation_authorization", None)

    reserve = (
        loader_module.reserve_gate_b_attempt
        if entrypoint == "loader"
        else GateBLedgerStore.reserve_attempt
    )
    with pytest.raises(
        GateBLedgerError,
        match="v2 reservation is not authorized by a consumed route",
    ) as captured:
        reserve(request, expected_latest_record_sha256=None)

    assert type(captured.value) is GateBLedgerError
    assert lower_reserve_calls == []
    with pytest.raises(
        GateBV2RouteError,
        match="v2 execution-plan close provenance mismatch",
    ) as close_error:
        close_gate_b_v2_execution_route(route)

    assert type(close_error.value) is GateBV2RouteError
    assert close_error.value.__cause__ is None
    assert close_error.value.__context__ is None
    assert request._v2_reservation_state == "closed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RUNTIME_REQUEST_ORIGINS
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_PLANS
    assert id(route) not in route_module._PREPARED_REGISTRY
    assert id(plan) not in route_module._PLAN_REGISTRY
    assert all(owner._closed and not owner.artifacts and not owner.directories for owner in owners)
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in owner_artifacts)
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in plan_artifacts)
    assert all(
        id(reference) not in route_module._ROOT_REF_REGISTRY
        and reference._anchor_raw is None
        and not reference._payload
        for reference in root_references
    )
    assert all(artifact.raw == b"" for artifact in bundle_artifacts)
    assert bundle.root_manifest_raw == b"" and not bundle.artifacts
    assert chain.projection is None and not chain._artifact_raws
    assert plan._closed and plan.request is None and not plan._artifacts and not plan._input_owners
    assert route._closed and route.plan is None and route.executor is None
    assert all(root.closed for root in roots.values())
    close_gate_b_v2_execution_route(route)


class _ForeignLifecycleEntry:
    pass


_LIFECYCLE_REGISTRY_CORRUPTIONS = (
    ("planned", "origin", "missing"),
    ("authorized", "origin", "foreign"),
    ("consumed", "origin", "malformed"),
    ("planned", "plan", "missing"),
    ("authorized", "plan", "foreign"),
    ("consumed", "plan", "malformed"),
    ("authorized", "authorization", "missing"),
    ("authorized", "authorization", "foreign"),
    ("authorized", "authorization", "malformed"),
    ("planned", "authorization", "unexpected"),
    ("consumed", "authorization", "unexpected"),
)


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("state,registry_name,mutation", _LIFECYCLE_REGISTRY_CORRUPTIONS)
def test_close_lifecycle_registry_corruption_is_canonical_and_releases_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    registry_name: str,
    mutation: str,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route = None
    roots: dict[str, _FakePinnedRoot] = {}
    request = plan.request
    if state in {"authorized", "consumed"}:
        route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
        request, _executor = route.consume()
    if state == "consumed":
        monkeypatch.setattr(ledger_module, "_reserve_attempt", lambda *_a, **_k: object())
        GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None)
    assert request._v2_reservation_state == state

    request_id = id(request)
    owners = plan._input_owners
    owner_artifacts = tuple(artifact for owner in owners for artifact in owner.artifacts.values())
    plan_artifacts = tuple(plan._artifacts.values())
    bundle = plan.phase6_contract_bundle_evidence
    bundle_artifacts = bundle.artifacts
    executor = route.executor if route is not None else None
    foreign_entries: list[object] = []
    registries = {
        "origin": route_module._V2_RUNTIME_REQUEST_ORIGINS,
        "authorization": route_module._V2_RESERVATION_AUTHORIZATIONS,
        "plan": route_module._V2_RUNTIME_REQUEST_PLANS,
    }
    registry = registries[registry_name]
    if mutation == "missing":
        registry.pop(request_id, None)
    elif registry_name == "origin":
        if mutation == "foreign":
            foreign = _ForeignLifecycleEntry()
            foreign_entries.append(foreign)
            registry[request_id] = weakref.ref(foreign)
        else:
            registry[request_id] = (weakref.ref(request),)
    elif registry_name == "plan":
        registry[request_id] = _ForeignLifecycleEntry() if mutation == "foreign" else (plan,)
    elif mutation == "foreign":
        registry[request_id] = (weakref.ref(request), _ForeignLifecycleEntry())
    else:
        registry[request_id] = () if mutation == "malformed" else (weakref.ref(request), object())

    with pytest.raises(GateBV2RouteError) as captured:
        if route is None:
            close_gate_b_v2_execution_plan(plan)
        else:
            close_gate_b_v2_execution_route(route)

    assert type(captured.value) is GateBV2RouteError
    assert str(captured.value) == "v2 execution-plan close provenance mismatch"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert request._v2_reservation_state == "closed"
    assert request._v2_reservation_authorization is None
    assert request_id not in route_module._V2_RUNTIME_REQUEST_ORIGINS
    assert request_id not in route_module._V2_RESERVATION_AUTHORIZATIONS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_PLANS
    assert request_id not in route_module._V2_RUNTIME_REQUEST_COPY_PROVENANCE
    assert id(plan) not in route_module._PLAN_REGISTRY
    assert all(owner._closed and not owner.artifacts and not owner.directories for owner in owners)
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in owner_artifacts)
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in plan_artifacts)
    assert all(artifact.raw == b"" for artifact in bundle_artifacts)
    assert bundle.root_manifest_raw == b"" and not bundle.artifacts
    assert plan._closed and plan.request is None and not plan._artifacts and not plan._input_owners
    assert chain.projection is None and not chain._artifact_raws
    if route is not None:
        assert id(route) not in route_module._PREPARED_REGISTRY
        assert route._closed and route.plan is None and route.executor is None
        assert all(root.closed for root in roots.values())
        assert executor._phase6_contract_bundle_evidence is None and not executor._manifest
        close_gate_b_v2_execution_route(route)
    else:
        close_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_builder_cleanup_allows_runtime_plan_registration_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    bundle = kwargs["phase6_contract_bundle_evidence"]
    registry_baselines = {
        "plans": set(route_module._PLAN_REGISTRY),
        "origins": set(route_module._V2_RUNTIME_REQUEST_ORIGINS),
        "authorizations": set(route_module._V2_RESERVATION_AUTHORIZATIONS),
        "runtime_plans": set(route_module._V2_RUNTIME_REQUEST_PLANS),
    }
    closed_owners = []
    real_close_owner = route_module._close_input_owner

    def recording_close_owner(owner):
        closed_owners.append(owner)
        real_close_owner(owner)

    def reject_final_validation(_plan):
        route_module._fail("forced final plan validation")

    monkeypatch.setattr(route_module, "_close_input_owner", recording_close_owner)
    monkeypatch.setattr(route_module, "validate_gate_b_v2_execution_plan", reject_final_validation)

    with pytest.raises(GateBV2RouteError, match="forced final plan validation"):
        build_gate_b_v2_execution_plan(chain, **kwargs)

    assert set(route_module._PLAN_REGISTRY) == registry_baselines["plans"]
    assert set(route_module._V2_RUNTIME_REQUEST_ORIGINS) == registry_baselines["origins"]
    assert set(route_module._V2_RESERVATION_AUTHORIZATIONS) == registry_baselines["authorizations"]
    assert set(route_module._V2_RUNTIME_REQUEST_PLANS) == registry_baselines["runtime_plans"]
    assert closed_owners
    assert all(
        owner._closed and not owner.artifacts and not owner.directories for owner in closed_owners
    )
    assert bundle.root_manifest_raw == b"" and not bundle.artifacts
    assert chain.projection is None and not chain._artifact_raws


@WINDOWS_PRODUCTION
def test_plan_close_registry_loss_reports_tamper_after_releasing_graph(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    owners = plan._input_owners
    owner_artifacts = tuple(artifact for owner in owners for artifact in owner.artifacts.values())
    plan_artifacts = tuple(plan._artifacts.values())
    bundle = plan.phase6_contract_bundle_evidence
    bundle_artifacts = bundle.artifacts

    route_module._PLAN_REGISTRY.pop(id(plan))
    with pytest.raises(GateBV2RouteError, match="close provenance"):
        close_gate_b_v2_execution_plan(plan)

    assert all(owner._closed and not owner.artifacts for owner in owners)
    assert all(artifact.raw == b"" for artifact in owner_artifacts)
    assert all(artifact.raw == b"" for artifact in plan_artifacts)
    assert all(artifact.raw == b"" for artifact in bundle_artifacts)
    assert bundle.root_manifest_raw == b"" and not bundle.artifacts
    assert plan.request is None and not plan._artifacts and not plan._input_owners


@WINDOWS_PRODUCTION
def test_input_owner_registry_loss_reports_tamper_after_releasing_bytes_and_handles(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    owner = plan._input_owners[0]
    artifacts = tuple(owner.artifacts.values())
    directories = tuple(owner.directories.values())

    route_module._INPUT_OWNER_REGISTRY.pop(id(owner))
    with pytest.raises(GateBV2RouteError, match="close failed closed"):
        close_gate_b_v2_execution_plan(plan)

    assert owner._closed and not owner.artifacts and not owner.directories
    assert all(artifact.raw == b"" and artifact.size_bytes == 0 for artifact in artifacts)
    assert all(directory._closed for directory in directories)
    assert plan.request is None and not plan._input_owners


@WINDOWS_PRODUCTION
def test_prepared_registry_loss_reports_tamper_after_releasing_route_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    owners = plan._input_owners
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    executor = route.executor

    route_module._PREPARED_REGISTRY.pop(id(route))
    with pytest.raises(GateBV2RouteError, match="close provenance"):
        close_gate_b_v2_execution_route(route)

    assert all(root.closed for root in roots.values())
    assert all(owner._closed and not owner.artifacts for owner in owners)
    assert executor._phase6_contract_bundle_evidence is None and not executor._manifest
    assert route.plan is None and route.executor is None and not route._directories


@pytest.mark.skipif(os.name != "nt", reason="Windows storage classification")
@pytest.mark.parametrize(("nested", "drive_type"), [(True, 3), (False, 4)])
def test_fixed_local_path_rejects_nested_mount_and_nonfixed_target_volume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    nested: bool,
    drive_type: int,
) -> None:
    candidate = (tmp_path / "candidate.json").resolve()
    drive_root = f"{candidate.drive}\\"
    mount = f"{candidate.drive}\\nested\\" if nested else drive_root
    monkeypatch.setattr(route_module, "_windows_volume_mount_path", lambda _path: mount)
    monkeypatch.setattr(route_module, "_windows_drive_type", lambda _mount: drive_type)
    with pytest.raises(GateBV2RouteError, match="fixed local volume"):
        route_module.validate_gate_b_v2_fixed_local_path(candidate, "fixture")


@WINDOWS_PRODUCTION
def test_production_bootstrap_reference_prepares_with_all_parent_identities_retained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, _kwargs, reference = _production_bootstrap_reference(tmp_path)
    roots: dict[str, _FakePinnedRoot] = {}
    by_path = {root["absolute_path"]: role for role, root in _plain(chain.roots).items()}
    real_open = route_module.open_gate_b_v2_pinned_directory
    real_verify = route_module.verify_gate_b_v2_pinned_directory
    projection_registry_before = set(route_module.gate_b_contracts_module._V2_PROJECTION_REGISTRY)

    def selective_open(path, **kwargs):
        role = by_path.get(str(path))
        if role is not None:
            roots[role] = _FakePinnedRoot(role, chain)
            return roots[role]
        return real_open(path, **kwargs)

    def selective_verify(directory, **kwargs):
        if isinstance(directory, _FakePinnedRoot):
            return None
        return real_verify(directory, **kwargs)

    monkeypatch.setattr(route_module, "open_gate_b_v2_pinned_directory", selective_open)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_pinned_directory", selective_verify)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_retained_root_topology", lambda *_a: None)
    monkeypatch.setattr(
        route_module,
        "verify_gate_b_v2_runtime_execution_environment",
        lambda request, _context: _evidence(request),
    )
    route = prepare_gate_b_v2_execution_route_from_reference(reference)
    owners = route.plan._input_owners
    assert type(route.executor) is GateBProductionExecutor
    assert len(route.plan._input_owners) == 2
    assert all(not owner._closed for owner in route.plan._input_owners)
    assert all(
        not directory._closed
        for owner in route.plan._input_owners
        for directory in owner.directories.values()
    )
    close_gate_b_v2_execution_route(route)
    assert all(owner._closed and not owner.artifacts for owner in owners)
    assert route.plan is None
    assert route.executor is None
    assert all(root.closed for root in roots.values())
    assert (
        set(route_module.gate_b_contracts_module._V2_PROJECTION_REGISTRY)
        == projection_registry_before
    )


@WINDOWS_PRODUCTION
def test_unsafe_interpreter_startup_rejects_before_bootstrap_artifact_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, _chain, _request, _spec, _kwargs, reference = _production_bootstrap_reference(tmp_path)
    reads: list[str] = []
    monkeypatch.setattr(
        route_module,
        "require_gate_b_v2_source_only_startup",
        lambda: (_ for _ in ()).throw(RuntimeError("unsafe startup")),
    )
    monkeypatch.setattr(
        route_module,
        "_read_v2_bootstrap_reference",
        lambda *_args: reads.append("read"),
    )
    with pytest.raises(GateBV2RouteError, match="source-only startup"):
        prepare_gate_b_v2_execution_route_from_reference(reference)
    assert reads == []


@WINDOWS_PRODUCTION
def test_public_production_reference_runs_real_lifecycle_with_fixture_storage_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, chain, request_payload, spec, kwargs, reference = _production_bootstrap_reference(
        tmp_path
    )
    expected_receipt = {
        "projection_sha256": chain.projection.sha256,
        "execution_binding_sha256": sha256_bytes(kwargs["one_shot_spec_raw"]),
        "loader_request_sha256": sha256_bytes(kwargs["loader_request_raw"]),
        "execution_context_sha256": sha256_bytes(kwargs["execution_context_raw"]),
        "execution_route_attestation_sha256": spec["execution_route_attestation_sha256"],
    }
    assert expected_receipt["loader_request_sha256"] == sha256_bytes(
        canonical_json_bytes(request_payload)
    )
    roots: dict[str, _FakePinnedRoot] = {}
    by_path = {root["absolute_path"]: role for role, root in _plain(chain.roots).items()}
    real_open = route_module.open_gate_b_v2_pinned_directory
    real_verify = route_module.verify_gate_b_v2_pinned_directory
    real_ledger_root = ledger_module._verify_root_ref
    real_pinned_root = ledger_module._verify_pinned_root_descriptor
    real_loader_root = loader_module._validate_root_ref
    real_open_quarantine = orchestrator_module._open_quarantine
    source_roots = {
        role: _plain(source.request.roots[role])
        for role in ("ledger_base", "quarantine_base", "test_root")
    }

    def selective_open(path, **kwargs):
        role = by_path.get(str(path))
        if role is not None:
            roots[role] = _FakePinnedRoot(role, chain)
            return roots[role]
        return real_open(path, **kwargs)

    def selective_verify(directory, **kwargs):
        if isinstance(directory, _FakePinnedRoot):
            return None
        return real_verify(directory, **kwargs)

    monkeypatch.setattr(route_module, "open_gate_b_v2_pinned_directory", selective_open)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_pinned_directory", selective_verify)
    monkeypatch.setattr(route_module, "verify_gate_b_v2_retained_root_topology", lambda *_a: None)
    monkeypatch.setattr(
        route_module,
        "verify_gate_b_v2_runtime_execution_environment",
        lambda request, _context: _evidence(request),
    )

    def mapped_ledger_root(_ref, role):
        return real_ledger_root(source_roots[role], role)

    def mapped_pinned_root(_ref, role, descriptor):
        return real_pinned_root(source_roots[role], role, descriptor)

    def mapped_loader_root(_ref, role):
        return real_loader_root(source_roots[role], role)

    def mapped_open_quarantine(request, _path, expected_sha256):
        path = (
            Path(source_roots["quarantine_base"]["absolute_path"])
            / request.batch.test_batch_hash
            / f"attempt-{request.attempt_ordinal:06d}"
            / "quarantine-manifest.json"
        )
        return real_open_quarantine(request, path, expected_sha256)

    drain = _DrainExecutor(source)
    monkeypatch.setattr(ledger_module, "_verify_root_ref", mapped_ledger_root)
    monkeypatch.setattr(
        ledger_module,
        "_verify_pinned_root_descriptor",
        mapped_pinned_root,
    )
    monkeypatch.setattr(loader_module, "_validate_root_ref", mapped_loader_root)
    monkeypatch.setattr(orchestrator_module, "_open_quarantine", mapped_open_quarantine)
    monkeypatch.setattr(
        GateBProductionExecutor,
        "execute",
        lambda _self, input_capability, quarantine_outputs: drain.execute(
            input_capability,
            quarantine_outputs,
        ),
    )

    receipt = execute_gate_b_v2_once(reference)
    assert receipt["schema_version"] == "phase6-gate-b-cli-execution-receipt-v2"
    assert receipt["operation"] == "execute-once-v2"
    assert receipt["status"] == "sealed"
    assert receipt["attempt_ordinal"] == 1
    assert receipt["state"] == "SEALED"
    assert all(receipt[name] == value for name, value in expected_receipt.items())
    store = GateBLedgerStore(source.request)
    records = []
    previous = None
    retry_catalog = ledger_module._retry_catalog(source.request.batch)
    readiness_hash = sha256_bytes(kwargs["readiness_authorization_raw"])
    for sequence, path in enumerate(sorted(store.directory.glob("record-*.json")), 1):
        previous = ledger_module._record_from(
            path,
            ledger_module._read_pinned(path, "production reference ledger record"),
            previous,
            sequence,
            readiness_hash,
            retry_catalog,
        )
        records.append(previous)
    assert tuple(record.to_state for record in records) == ("RESERVED", "STARTED", "SEALED")
    assert receipt["sealed_record_sha256"] == records[-1].record_sha256
    assert (
        receipt["quarantine_manifest_sha256"] == records[-1].payload["quarantine_manifest_sha256"]
    )
    for name in (
        "projection_sha256",
        "execution_binding_sha256",
        "loader_request_sha256",
        "execution_context_sha256",
        "execution_route_attestation_sha256",
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
    ):
        assert type(receipt[name]) is str and len(receipt[name]) == 64
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_production_route_success_then_replay_never_reserves_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    assert orchestrator_module._gate_b_v2_receipt_bindings(route, plan.request) == {
        "projection_sha256": plan.projection.sha256,
        "execution_binding_sha256": plan.artifact_hashes["one_shot_spec"],
        "loader_request_sha256": plan.request.request_sha256,
        "execution_context_sha256": plan.request.execution_context.sha256,
        "execution_route_attestation_sha256": plan.execution_route_attestation_sha256,
    }
    call_order: list[str] = []

    def reserve(*_args, **_kwargs):
        call_order.append("reserve")
        return object()

    def prepare(*_args, **_kwargs):
        call_order.append("prepare")
        return object()

    def open_input(*_args, **_kwargs):
        call_order.append("open")
        return object()

    def receipt(*_args, **_kwargs):
        call_order.append("receipt")
        return MappingProxyType({"status": "sealed"})

    monkeypatch.setattr(orchestrator_module, "reserve_gate_b_attempt", reserve)
    monkeypatch.setattr(orchestrator_module, "prepare_gate_b_test_open", prepare)
    monkeypatch.setattr(orchestrator_module, "_open_with_callback_classification", open_input)
    monkeypatch.setattr(orchestrator_module, "_gate_b_v2_execution_receipt", receipt)
    assert execute_gate_b_v2_once(route)["status"] == "sealed"
    assert call_order == ["reserve", "prepare", "open", "receipt"]
    assert all(root.closed for root in roots.values())
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert call_order == ["reserve", "prepare", "open", "receipt"]


@WINDOWS_PRODUCTION
@pytest.mark.parametrize("substitution", ["parent", "same-bytes-child"])
def test_retained_artifact_identity_substitution_fails_before_reservation(
    substitution: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    reserved: list[str] = []
    if substitution == "parent":

        def substituted_parent(_directory):
            raise GateBLedgerError("substituted retained parent")

        monkeypatch.setattr(GateBPinnedDirectory, "verify_identity", substituted_parent)
    else:
        original = GateBPinnedDirectory.read_regular

        def substituted_child(directory, name, **expected):
            observed = original(directory, name, **expected)
            return SimpleNamespace(
                raw=observed.raw,
                physical_identity=("ffffffff", "ffffffffffffffff"),
            )

        monkeypatch.setattr(GateBPinnedDirectory, "read_regular", substituted_child)
    monkeypatch.setattr(
        orchestrator_module,
        "reserve_gate_b_attempt",
        lambda *_args, **_kwargs: reserved.append("reserved"),
    )
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert reserved == []
    assert all(root.closed for root in roots.values())


@pytest.mark.parametrize(
    "field",
    [
        "projection_sha256",
        "execution_binding_sha256",
        "loader_request_sha256",
        "execution_context_sha256",
        "execution_route_attestation_sha256",
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
    ],
)
def test_v2_public_receipt_rejects_every_hash_field_tamper(field: str) -> None:
    receipt = {
        "schema_version": orchestrator_module.V2_EXECUTION_RECEIPT_SCHEMA,
        "operation": "execute-once-v2",
        "status": "sealed",
        "attempt_ordinal": 1,
        "state": "SEALED",
        "projection_sha256": "a" * 64,
        "execution_binding_sha256": "b" * 64,
        "loader_request_sha256": "c" * 64,
        "execution_context_sha256": "d" * 64,
        "execution_route_attestation_sha256": "e" * 64,
        "sealed_record_sha256": "f" * 64,
        "quarantine_manifest_sha256": "0" * 64,
    }
    expected_hashes = {
        name: value
        for name, value in receipt.items()
        if name not in {"schema_version", "operation", "status", "attempt_ordinal", "state"}
    }
    receipt[field] = "9" * 64
    with pytest.raises(ValueError):
        orchestrator_module._validate_gate_b_v2_execution_receipt(
            receipt,
            expected_hashes=expected_hashes,
        )


@WINDOWS_PRODUCTION
def test_loader_receipt_is_bound_to_request_executor_and_exact_sealed_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, compatibility, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(compatibility, **kwargs)
    route, _roots = _prepare_with_fake_roots(plan, compatibility, monkeypatch)
    batch_hash = plan.request.batch.test_batch_hash
    records = [
        SimpleNamespace(
            to_state=state,
            attempt_ordinal=1,
            record_sha256=digest,
            payload={
                "test_batch_hash": batch_hash,
                **({"quarantine_manifest_sha256": "4" * 64} if state == "SEALED" else {}),
            },
        )
        for state, digest in (
            ("RESERVED", "1" * 64),
            ("STARTED", "2" * 64),
            ("SEALED", "3" * 64),
        )
    ]
    monkeypatch.setattr(
        orchestrator_module,
        "GateBLedgerStore",
        lambda _request: SimpleNamespace(load_chain=lambda: records),
    )
    values = {
        "test_batch_hash": batch_hash,
        "attempt_ordinal": 1,
        "started_record_sha256": "2" * 64,
        "sealed_record_sha256": "3" * 64,
        "executor_id": route.executor.executor_id,
        "state": "SEALED",
    }
    monkeypatch.setattr(
        orchestrator_module,
        "_open_quarantine",
        lambda *_args, **_kwargs: nullcontext(
            SimpleNamespace(
                manifest={
                    "status": "sealed",
                    "started_record_sha256": values["started_record_sha256"],
                },
                verify_identity=lambda _request: None,
            )
        ),
    )
    result = orchestrator_module._gate_b_v2_execution_receipt(
        route,
        plan.request,
        SimpleNamespace(**values),
    )
    assert result["sealed_record_sha256"] == records[-1].record_sha256
    assert result["quarantine_manifest_sha256"] == "4" * 64
    for field, invalid in (
        ("test_batch_hash", "f" * 64),
        ("attempt_ordinal", 2),
        ("started_record_sha256", "f" * 64),
        ("sealed_record_sha256", "f" * 64),
        ("executor_id", "wrong-executor"),
        ("state", "STARTED"),
    ):
        tampered = dict(values)
        tampered[field] = invalid
        with pytest.raises(ValueError):
            orchestrator_module._gate_b_v2_execution_receipt(
                route,
                plan.request,
                SimpleNamespace(**tampered),
            )
    close_gate_b_v2_execution_route(route)


@WINDOWS_PRODUCTION
def test_production_prepare_internally_builds_exact_executor_before_root_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    assert type(route.executor) is GateBProductionExecutor
    assert route.executor._batch_hash == plan.request.batch.sha256
    close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_retained_roots_close_in_reverse_acquisition_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    close_log: list[str] = []
    route, _roots = _prepare_with_fake_roots(
        plan,
        chain,
        monkeypatch,
        close_log=close_log,
    )
    close_gate_b_v2_execution_route(route)
    assert close_log == ["test_root", "quarantine_base", "ledger_base"]


@WINDOWS_PRODUCTION
def test_production_prepare_rejects_nonproduction_executor_before_retained_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    opened = []
    monkeypatch.setattr(
        route_module.GateBProductionExecutor,
        "from_request",
        classmethod(lambda _cls, *_args, **_kwargs: object()),
    )
    monkeypatch.setattr(
        route_module,
        "open_gate_b_v2_pinned_directory",
        lambda *_args, **_kwargs: opened.append("opened"),
    )
    with pytest.raises(GateBV2RouteError):
        prepare_gate_b_v2_execution_route(
            plan,
        )
    assert opened == []


@WINDOWS_PRODUCTION
def test_prewrite_failure_closes_all_retained_roots_without_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    roots["ledger_base"].drift = True
    reserved = []
    monkeypatch.setattr(
        route_module,
        "open_gate_b_v2_pinned_directory",
        lambda *_args, **_kwargs: pytest.fail("unexpected reopen"),
    )
    monkeypatch.setattr(
        "phase6.gate_b_orchestrator.reserve_gate_b_attempt",
        lambda *_args, **_kwargs: reserved.append("reserved"),
    )
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert reserved == []
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_environment_failure_precedes_reservation_and_closes_retained_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    monkeypatch.setattr(
        route_module,
        "verify_gate_b_v2_runtime_execution_environment",
        lambda *_args: (_ for _ in ()).throw(ValueError("environment drift")),
    )
    reserved = []
    monkeypatch.setattr(
        "phase6.gate_b_orchestrator.reserve_gate_b_attempt",
        lambda *_args, **_kwargs: reserved.append("reserved"),
    )
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert reserved == []
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_stored_artifact_drift_still_closes_registered_retained_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    _write_raw(kwargs["approval_record_path"], b"{}\n")
    reserved = []
    monkeypatch.setattr(
        "phase6.gate_b_orchestrator.reserve_gate_b_attempt",
        lambda *_args, **_kwargs: reserved.append("reserved"),
    )
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert reserved == []
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_closed_state_tamper_cannot_skip_registered_retained_root_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    object.__setattr__(route, "_closed", True)
    with pytest.raises(GateBV2RouteError):
        close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


def test_disposable_v2_dispatcher_runs_one_mock_lifecycle_and_stops_at_sealed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(route_module.tempfile, "gettempdir", lambda: str(tmp_path.parent))
    authority = route_module._create_disposable_gate_b_v2_fixture_authority(tmp_path)
    source = _build_fixture(authority.root / "case")
    executor = _DrainExecutor(source)
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    route = route_module._prepare_disposable_gate_b_v2_fixture_route(
        authority,
        source.request,
        executor=executor,
    )
    receipt = execute_gate_b_v2_once(route)
    assert receipt["schema_version"] == "phase6-gate-b-cli-execution-receipt-v2"
    assert receipt["operation"] == "execute-once-v2"
    assert receipt["status"] == "sealed"
    assert receipt["attempt_ordinal"] == 1
    assert receipt["state"] == "SEALED"
    for name in (
        "projection_sha256",
        "execution_binding_sha256",
        "loader_request_sha256",
        "execution_context_sha256",
        "execution_route_attestation_sha256",
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
    ):
        assert len(receipt[name]) == 64
    roots_hash = sha256_bytes(canonical_json_bytes(_plain(source.request.roots)))
    binding_hash = sha256_bytes(
        canonical_json_bytes(
            {
                "projection_sha256": roots_hash,
                "loader_request_sha256": source.request.request_sha256,
                "execution_context_sha256": source.request.execution_context.sha256,
                "batch_manifest_sha256": source.request.batch.sha256,
            }
        )
    )
    assert receipt["projection_sha256"] == roots_hash
    assert receipt["execution_binding_sha256"] == binding_hash
    assert receipt["loader_request_sha256"] == source.request.request_sha256
    assert receipt["execution_context_sha256"] == source.request.execution_context.sha256
    assert receipt["execution_route_attestation_sha256"] == binding_hash
    chain_records = GateBLedgerStore(source.request).load_chain()
    assert [record.to_state for record in chain_records] == ["RESERVED", "STARTED", "SEALED"]
    assert receipt["sealed_record_sha256"] == chain_records[-1].record_sha256
    assert (
        receipt["quarantine_manifest_sha256"]
        == chain_records[-1].payload["quarantine_manifest_sha256"]
    )
    manifest_path = (
        Path(source.request.roots["quarantine_base"]["absolute_path"])
        / source.request.batch.test_batch_hash
        / "attempt-000001"
        / "quarantine-manifest.json"
    )
    manifest_raw = ledger_module._read_pinned(manifest_path, "sealed quarantine manifest")
    assert receipt["quarantine_manifest_sha256"] == sha256_bytes(manifest_raw)
    assert route._closed is True
    assert route._consumed is True
    assert id(route) not in route_module._DISPOSABLE_ROUTE_REGISTRY
    assert route.request is None and route.executor is None and route.authority is None
    close_gate_b_v2_execution_route(route)
    with pytest.raises(GateBV2RouteError):
        route.consume()
    with pytest.raises(GateBV2RouteError):
        route_module._prepare_disposable_gate_b_v2_fixture_route(
            authority,
            source.request,
            executor=_DrainExecutor(source),
        )


def test_post_seal_route_error_is_canonical_preflight_and_route_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(route_module.tempfile, "gettempdir", lambda: str(tmp_path.parent))
    authority = route_module._create_disposable_gate_b_v2_fixture_authority(tmp_path)
    source = _build_fixture(authority.root / "case")
    route = route_module._prepare_disposable_gate_b_v2_fixture_route(
        authority,
        source.request,
        executor=_DrainExecutor(source),
    )
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "_gate_b_v2_execution_receipt",
        lambda *_args: (_ for _ in ()).throw(GateBV2RouteError("post-seal drift")),
    )
    with pytest.raises(GateBPreflightError):
        execute_gate_b_v2_once(route)
    assert GateBLedgerStore(source.request).load_chain()[-1].to_state == "SEALED"
    assert route._closed is True


def test_post_seal_manifest_byte_tamper_is_rejected_before_public_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(route_module.tempfile, "gettempdir", lambda: str(tmp_path.parent))
    authority = route_module._create_disposable_gate_b_v2_fixture_authority(tmp_path)
    source = _build_fixture(authority.root / "case")
    route = route_module._prepare_disposable_gate_b_v2_fixture_route(
        authority,
        source.request,
        executor=_DrainExecutor(source),
    )
    monkeypatch.setattr(
        loader_module,
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    real_open = orchestrator_module._open_with_callback_classification

    def open_then_tamper(prepared, executor):
        receipt = real_open(prepared, executor)
        request = prepared.request
        manifest_path = (
            Path(request.roots["quarantine_base"]["absolute_path"])
            / request.batch.test_batch_hash
            / f"attempt-{request.attempt_ordinal:06d}"
            / "quarantine-manifest.json"
        )
        descriptor = ledger_module._open_existing_descriptor(manifest_path, writable=True)
        try:
            os.ftruncate(descriptor, 0)
            assert os.write(descriptor, b"{}\n") == 3
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return receipt

    monkeypatch.setattr(
        orchestrator_module,
        "_open_with_callback_classification",
        open_then_tamper,
    )
    with pytest.raises(GateBPostSealValidationError):
        execute_gate_b_v2_once(route)
    assert GateBLedgerStore(source.request).load_chain()[-1].to_state == "SEALED"
    assert route._closed is True


def test_disposable_authority_rejects_request_outside_its_fresh_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(route_module.tempfile, "gettempdir", lambda: str(tmp_path.parent))
    authority = route_module._create_disposable_gate_b_v2_fixture_authority(tmp_path)
    outside = _build_fixture(tmp_path / "outside-case")
    with pytest.raises(GateBV2RouteError):
        route_module._prepare_disposable_gate_b_v2_fixture_route(
            authority,
            outside.request,
            executor=_DrainExecutor(outside),
        )
