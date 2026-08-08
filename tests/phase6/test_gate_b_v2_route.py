from __future__ import annotations

import copy
import os
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
from test_gate_b_executor import _build_genuine_evidence, _genuine_evidence
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
from phase6.gate_b_orchestrator import GateBPreflightError, execute_gate_b_v2_once
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

EXACT_ROUTE_COMMIT = "6f86497e35d2002be19cbcb9f894b1b6c0eba95d"
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
    bundle_evidence = _genuine_evidence()

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
    assert {
        "phase6.gate_b_v2_route",
        "phase6.gate_b_orchestrator",
        "phase6.gate_b_v2_cli",
        "phase6.gate_b_executor",
    } <= {name for name, _path in loader_module.GATE_B_V2_ROUTE_MODULE_PATHS}
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
def test_unprepared_plan_has_explicit_idempotent_close_and_unregisters_request(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    owners = plan._input_owners
    assert route_module.is_gate_b_v2_runtime_request(plan.request)
    close_gate_b_v2_execution_plan(plan)
    assert all(owner._closed for owner in owners)
    assert not route_module.is_gate_b_v2_runtime_request(plan.request)
    close_gate_b_v2_execution_plan(plan)


@WINDOWS_PRODUCTION
def test_plan_owner_inventory_tamper_still_closes_registered_original_handles(
    tmp_path: Path,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    original_owners = plan._input_owners
    object.__setattr__(plan, "_input_owners", ())
    with pytest.raises(GateBV2RouteError):
        close_gate_b_v2_execution_plan(plan)
    assert all(owner._closed for owner in original_owners)
    assert not route_module.is_gate_b_v2_runtime_request(plan.request)


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
    with pytest.raises(loader_module.GateBLoaderError):
        loader_module.reserve_gate_b_attempt(
            plan.request,
            expected_latest_record_sha256=None,
        )
    assert writes == []


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

    monkeypatch.setattr(loader_module, "_reserve_attempt", reserve)
    assert (
        loader_module.reserve_gate_b_attempt(
            request,
            expected_latest_record_sha256=None,
        )
        is reservation
    )
    with pytest.raises(loader_module.GateBLoaderError):
        loader_module.reserve_gate_b_attempt(
            request,
            expected_latest_record_sha256=None,
        )
    assert writes == ["reserved"]
    close_gate_b_v2_execution_route(route)
    assert all(root.closed for root in roots.values())


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
    assert type(route.executor) is GateBProductionExecutor
    assert len(route.plan._input_owners) == 2
    assert all(not owner._closed for owner in route.plan._input_owners)
    assert all(
        not directory._closed
        for owner in route.plan._input_owners
        for directory in owner.directories.values()
    )
    close_gate_b_v2_execution_route(route)
    assert all(owner._closed for owner in route.plan._input_owners)
    assert all(root.closed for root in roots.values())


@WINDOWS_PRODUCTION
def test_public_production_reference_runs_existing_one_shot_call_graph_without_real_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, _kwargs, reference = _production_bootstrap_reference(tmp_path)
    roots: dict[str, _FakePinnedRoot] = {}
    by_path = {root["absolute_path"]: role for role, root in _plain(chain.roots).items()}
    real_open = route_module.open_gate_b_v2_pinned_directory
    real_verify = route_module.verify_gate_b_v2_pinned_directory

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

    monkeypatch.setattr(loader_module, "_reserve_attempt", reserve)
    monkeypatch.setattr(orchestrator_module, "prepare_gate_b_test_open", prepare)
    monkeypatch.setattr(orchestrator_module, "_open_with_callback_classification", open_input)
    monkeypatch.setattr(orchestrator_module, "_gate_b_v2_execution_receipt", receipt)
    assert execute_gate_b_v2_once(reference)["status"] == "sealed"
    assert call_order == ["reserve", "prepare", "open", "receipt"]
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
    with pytest.raises(GateBLedgerError):
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
