from __future__ import annotations

import copy
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
from test_gate_b_loader import _build_fixture, _DrainExecutor, _evidence

import phase6.gate_b_ledger as ledger_module
import phase6.gate_b_loader as loader_module
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
    close_gate_b_v2_execution_route,
    prepare_gate_b_v2_execution_route,
    validate_gate_b_v2_execution_plan,
)

EXACT_ROUTE_COMMIT = "6f86497e35d2002be19cbcb9f894b1b6c0eba95d"


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


def test_v2_plan_rejects_runtime_request_object_setattr_tamper(tmp_path: Path) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    plain_roots = MappingProxyType(
        {role: MappingProxyType(dict(root)) for role, root in _plain(plan.request.roots).items()}
    )
    object.__setattr__(plan.request, "roots", plain_roots)
    with pytest.raises(GateBV2RouteError):
        validate_gate_b_v2_execution_plan(plan)


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
        "verify_gate_b_execution_environment",
        lambda request, _context: _evidence(request),
    )
    route = prepare_gate_b_v2_execution_route(
        plan,
    )
    return route, roots


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


def test_environment_failure_precedes_reservation_and_closes_retained_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, chain, _request, _spec, kwargs = _production_plan_fixture(tmp_path)
    plan = build_gate_b_v2_execution_plan(chain, **kwargs)
    route, roots = _prepare_with_fake_roots(plan, chain, monkeypatch)
    monkeypatch.setattr(
        route_module,
        "verify_gate_b_execution_environment",
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
        "sealed_record_sha256",
        "quarantine_manifest_sha256",
    ):
        assert len(receipt[name]) == 64
    chain_records = GateBLedgerStore(source.request).load_chain()
    assert [record.to_state for record in chain_records] == ["RESERVED", "STARTED", "SEALED"]
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
