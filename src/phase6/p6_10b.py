"""Closed-world P6-10B confidence and provider ablation implementation.

The module is additive to P6-9 and P6-10A.  It builds two separately hashed
series, executes their common-random-number Validation replay as one atomic
attempt, writes a distinct P6-10B schema, and keeps P6-10/Gate-B flags false.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes, sha256_bytes
from .p6_7 import REPETITION_SEEDS, STREAM_NAMES, PrimaryCandidate, derive_stream_root
from .p6_10 import (
    ABL_CONFIDENCE_MVP_ID,
    ABL_PROVIDER_RULE_ID,
    P6_9_SELECTED_CONFIG_SHA256,
    P6_9_VALIDATION_BATCH_SHA256,
    P69Snapshot,
    verify_p6_10a_run_manifest,
)
from .training_runner import HORIZONS
from .validation_backend import P610BValidationExecutionBackend
from .validation_execution import (
    ValidationArtifactRecord,
    run_p6_10b_candidate_execution,
)
from .validation_runner import ValidationSessionKey

P6_10B_CLI_VERSION = "phase6-p6-10b-cli-v1"
P6_10B_ENTRYPOINT = "cli/phase6_p6_10b_v1.py"
P6_10B_ATTEMPT_ID = "p6-10b-confidence-provider-precision-fix-attempt-001"
P6_10B_ATTEMPT_MARKER = "p6_10b_attempt_in_progress.json"
P6_10B_FAILURE_RECORD = "p6_10b_failure_record.json"
P6_10B_RUN_MANIFEST = "phase6_p6_10b_run_manifest.json"
P6_10B_BATCH_MANIFEST = "p6_10b_batch_manifest.json"
P6_10B_RESULT_ROOT = "p6_10b_result_root.json"
P6_10B_REPORT = "p6_10b_contract_closure_report.json"
P6_10B_ARTIFACT_DIRECTORY = "p6-10b-artifacts"
P6_10B_PHYSICAL_DIRECTORY = "confidence-provider-ablation"

P6_10B_CONFIG_SCHEMA_VERSION = "phase6-p6-10b-ablation-config-v1"
P6_10B_BATCH_SCHEMA_VERSION = "phase6-p6-10b-batch-manifest-v1"
P6_10B_ARTIFACT_SCHEMA_VERSION = "phase6-p6-10b-artifact-v1"
P6_10B_REPORT_SCHEMA_VERSION = "phase6-p6-10b-contract-closure-report-v1"
P6_10B_RESULT_ROOT_SCHEMA_VERSION = "phase6-p6-10b-result-root-v1"
P6_10B_RUN_SCHEMA_VERSION = "phase6-p6-10b-run-manifest-v1"
P6_10B_ATTEMPT_SCHEMA_VERSION = "phase6-p6-10b-attempt-marker-v1"
P6_10B_FAILURE_SCHEMA_VERSION = "phase6-p6-10b-failure-record-v1"

P6_10B_BASELINE = "e1c794566bfd5811582556eb56183d5940efda14"
P6_10A_BATCH_SHA256 = "dd5a6b66a7da822470d6cde7285e87473c2dbe152c71a9ba94c5b134bf9a2104"
P6_10A_RUN_SHA256 = "6ebe49fb794be047572adbd5185b05e693db1232b74d06f8c1f874e305dd9cce"
P6_10A_RESULT_ROOT_SHA256 = "6ed643e11cf44cb811778bccbdc1f2e7d13c39a63bee6d554eceec7834441e82"
P6_10A_REPORT_SHA256 = "22bf99c2cb4bd58d3fa0cf508b28122ff632f8f3bc30660f119a454c96012914"
P6_10A_GAP_SHA256 = "08cfdbd44e5700990f39ec61036357059918f1a6f0f8e782c33c6d248aeaa792"

_STANDARD_TYPES = (
    "validation_terminal_candidate_snapshots",
    "validation_hero_policy_snapshots",
    "validation_exact_ev_cells",
    "validation_calibration_cells",
    "validation_aggregate_metrics",
)
_TYPE_SUFFIXES = (
    "terminal_candidate_snapshots",
    "hero_policy_snapshots",
    "exact_ev_cells",
    "calibration_cells",
    "aggregate_metrics",
)
_ABLATION_IDS = (ABL_CONFIDENCE_MVP_ID, ABL_PROVIDER_RULE_ID)
_EXPECTED_CARDINALITY = {
    "ablation_count": 2,
    "candidate_count": 2,
    "config_count": 2,
    "series_count": 2,
    "opponent_count": 9,
    "horizon_count": 3,
    "repetition_count": 30,
    "session_count": 1620,
    "session_record_count_per_type": 1620,
    "candidate_record_count_per_type": 2,
    "unique_stream_root_count": 3240,
    "stream_root_reference_count": 6480,
    "atomic_group_count": 54,
    "artifact_file_count": 10,
}
_SHA256_CHARS = frozenset("0123456789abcdef")

_INDEPENDENT_VERIFIER_SOURCE = r"""
import copy
import hashlib
import json
import math
import sys
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
from pathlib import Path, PurePosixPath


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def load_canonical(path, label):
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical(value) != raw:
        raise ValueError(label + " is not canonical JSON")
    return value, raw


def load_source(path, label):
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(label + " source artifact must be an object")
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require_exact(actual, expected, label):
    if actual != expected:
        raise ValueError("independent " + label + " mismatch")


def decimal_wire(value):
    wire = format(Decimal.from_float(value), "f")
    if "." in wire:
        wire = wire.rstrip("0").rstrip(".")
    return "0" if wire in {"", "-0"} else wire


def decimal_token(value):
    wire = format(value, "f")
    if "." in wire:
        wire = wire.rstrip("0").rstrip(".")
    return "0" if wire in {"", "-0"} else wire


def estimand_delta(ablation_value, primary_value):
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        difference = Decimal(ablation_value) - Decimal(primary_value)
    return decimal_token(difference)


def decimal_mean(values):
    if not values:
        return None
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        total = Decimal(0)
        for value in values:
            total += value
        return total / Decimal(len(values))


def binary64(value, label):
    if not isinstance(value, dict) or set(value) != {"binary64_hex", "exact_decimal"}:
        raise ValueError(label + " binary64 evidence is not closed-world")
    parsed = float.fromhex(value["binary64_hex"])
    if not math.isfinite(parsed) or parsed.hex() != value["binary64_hex"]:
        raise ValueError(label + " binary64 hex is invalid")
    if decimal_wire(parsed) != value["exact_decimal"]:
        raise ValueError(label + " exact decimal differs from binary64")
    return parsed


def binary_evidence(value):
    return {"binary64_hex": value.hex(), "exact_decimal": decimal_wire(value)}


def canonical_no_lf(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def stream_root(opponent_id, horizon, repetition_id, stream_name):
    version = "phase6-domain-separated-sha256-v2"
    repetition_index = int(repetition_id[1:])
    payload = {
        "derivation_version": version,
        "horizon": horizon,
        "master_seed": 620000 + repetition_index,
        "opponent_id": opponent_id,
        "repetition_id": repetition_id,
        "split": "validation",
        "stream_name": stream_name,
    }
    value = hashlib.sha256(version.encode() + b"\0" + canonical_no_lf(payload)).hexdigest()
    return {"payload": payload, "digest": value}


def draw_digest(root, decision_index, variate_index=0, attempt_index=0):
    require_exact(root, stream_root(
        root["payload"]["opponent_id"], root["payload"]["horizon"],
        root["payload"]["repetition_id"], root["payload"]["stream_name"]),
        "stream root reconstruction")
    if not 0 <= decision_index < root["payload"]["horizon"]:
        raise ValueError("independent draw decision index is outside horizon")
    coordinates = (decision_index.to_bytes(8, "big")
                   + variate_index.to_bytes(4, "big")
                   + attempt_index.to_bytes(4, "big"))
    return hashlib.sha256(
        b"phase6-digest-draw-v2\0" + bytes.fromhex(root["digest"]) + coordinates
    ).hexdigest()


def weighted_choice(outcomes, weights, value):
    exact = [Fraction(*weight.as_integer_ratio()) for weight in weights]
    total = sum(exact, start=Fraction(0))
    x = int(value, 16)
    cumulative = Fraction(0)
    for outcome, weight in zip(outcomes, exact):
        cumulative += weight
        if Fraction(x) * total < Fraction(1 << 256) * cumulative:
            return outcome
    raise ValueError("independent weighted choice exhausted outcomes")


def uniform_action(actions, root, decision_index):
    limit = (1 << 256) - ((1 << 256) % len(actions))
    for attempt in range(1 << 32):
        value = draw_digest(root, decision_index, attempt_index=attempt)
        x = int(value, 16)
        if x < limit:
            return actions[x % len(actions)], value, attempt
    raise ValueError("independent uniform action exhausted attempts")


def execution_action(final_policy, actions, epsilon, decision_index, roots):
    hero_value = draw_digest(roots["hero_action"], decision_index)
    branch_value = draw_digest(roots["epsilon_branch"], decision_index)
    epsilon_action, epsilon_value, attempt = uniform_action(
        actions, roots["epsilon_action"], decision_index)
    hero_action = weighted_choice(
        actions, [final_policy[action] for action in actions], hero_value)
    epsilon_fraction = Fraction(Decimal(epsilon))
    fired = (int(branch_value, 16) * epsilon_fraction.denominator
             < epsilon_fraction.numerator * (1 << 256))
    return {
        "final_action": epsilon_action if fired else hero_action,
        "branch_fired": fired,
        "hero_action": hero_action,
        "epsilon_action": epsilon_action,
        "hero_draw_digest": hero_value,
        "epsilon_branch_draw_digest": branch_value,
        "epsilon_action_draw_digest": epsilon_value,
        "hero_draw_status": "unused" if fired else "used",
        "epsilon_action_draw_status": "used" if fired else "unused",
        "epsilon_action_attempt": attempt,
    }


def record_key(record):
    return (record["candidate_id"], record["opponent_id"],
            record["horizon"], record["repetition_id"])


def profile_from_payload(value):
    return {infoset: {action: float.fromhex(probability)
                      for action, probability in distribution.items()}
            for infoset, distribution in value.items()}


def posterior(k, n, baseline=0.5, tau=0.25):
    q = baseline + tau
    trials = n + 1
    terms = [math.lgamma(trials + 1) - math.lgamma(j + 1)
             - math.lgamma(trials - j + 1) + j * math.log(q)
             + (trials - j) * math.log1p(-q) for j in range(k + 1)]
    maximum = max(terms)
    return min(1.0, max(0.0, math.exp(maximum)
                       * math.fsum(math.exp(item - maximum) for item in terms)))


def reach_weight(infoset, equilibrium, oop_combos, ip_combos):
    actor, combo, phase = infoset.split(":")
    if actor != "IP":
        raise ValueError("independent verifier expected an IP infoset")
    action = "CHECK" if phase == "vs_check" else "BET"
    return math.fsum((1.0 / 9.0) * equilibrium[f"OOP:{oop}:start"][action]
                     for oop in oop_combos)


def opponent_profile(config, equilibrium, oop_combos, ip_combos):
    profile = copy.deepcopy(equilibrium)
    leaks = config["leak_vector"]
    if not leaks:
        return profile
    if len(leaks) != 1:
        raise ValueError("independent verifier requires one synthetic leak")
    reason, delta_wire = next(iter(leaks.items()))
    mapping = {"LEAK_R001": ("vs_bet", "FOLD"),
               "LEAK_R007": ("vs_check", "CHECK"),
               "LEAK_R008": ("vs_check", "BET")}
    phase, action = mapping[reason]
    infosets = [name for name in equilibrium
                if name.startswith("IP:") and name.endswith(":" + phase)]
    weights = [reach_weight(name, equilibrium, oop_combos, ip_combos)
               for name in infosets]
    denominator = math.fsum(weights)
    baseline = math.fsum(weight * equilibrium[name][action]
                         for name, weight in zip(infosets, weights)) / denominator
    target = baseline + float(Decimal(delta_wire))
    if target <= baseline:
        scale = 0.0 if baseline == 0.0 else target / baseline
        values = {name: equilibrium[name][action] * scale for name in infosets}
    else:
        complement = 1.0 - baseline
        scale = 0.0 if complement == 0.0 else (1.0 - target) / complement
        values = {name: 1.0 - (1.0 - equilibrium[name][action]) * scale
                  for name in infosets}
    for name, probability in values.items():
        other = next(item for item in equilibrium[name] if item != action)
        profile[name] = {action: probability, other: 1.0 - probability}
    return profile


def showdown(oop, ip, amount):
    ranks = {"5h5c": 1, "6h6c": 2, "JhJd": 3,
             "7h7d": 4, "QsQd": 5, "AhAd": 6}
    if ranks[oop] > ranks[ip]:
        return amount
    if ranks[oop] < ranks[ip]:
        return -amount
    return 0.0


def exact_ev(hero, opponent, oop_combos, ip_combos):
    leaves = []
    for oop in oop_combos:
        start = hero[f"OOP:{oop}:start"]
        response = hero[f"OOP:{oop}:vs_bet"]
        for ip in ip_combos:
            vs_bet = opponent[f"IP:{ip}:vs_bet"]
            vs_check = opponent[f"IP:{ip}:vs_check"]
            bet_value = (vs_bet["CALL"] * showdown(oop, ip, 10.0)
                         + vs_bet["FOLD"] * 4.0)
            checked_value = (vs_check["CHECK"] * showdown(oop, ip, 4.0)
                             + vs_check["BET"]
                             * (response["CALL"] * showdown(oop, ip, 10.0)
                                + response["FOLD"] * -4.0))
            leaves.append((1.0 / 9.0)
                          * (start["BET"] * bet_value
                             + start["CHECK"] * checked_value))
    return math.fsum(leaves)


def action_values(equilibrium, oop_combos, ip_combos, infoset):
    oop = infoset.split(":")[1]
    reaches = [(1.0 / 9.0) * equilibrium[f"IP:{ip}:vs_check"]["BET"]
               for ip in ip_combos]
    total = math.fsum(reaches)
    return ({"CALL": math.fsum(reach * showdown(oop, ip, 10.0)
                                for reach, ip in zip(reaches, ip_combos)) / total,
             "FOLD": -4.0}, total)


def require_fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(label + " is not closed-world")
    return value


def load_fixed_equilibrium(repo_root, fixed_catalog):
    relative_value = (
        "configs/opponents/equilibria/"
        "river-large-bet-equilibrium-v1.equilibrium.json"
    )
    relative = PurePosixPath(relative_value)
    root = repo_root.resolve()
    path = (root / Path(*relative.parts)).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("frozen equilibrium path escapes the repository") from exc
    payload = load_source(path, "frozen equilibrium")
    require_fields(payload, {
        "schema_version", "artifact_type", "equilibrium_version", "game",
        "strategy", "solver", "artifact_sha256"}, "frozen equilibrium")
    if payload["schema_version"] != "1.0.0" \
            or payload["artifact_type"] != "frozen-equilibrium" \
            or payload["equilibrium_version"] != "river-large-bet-equilibrium-v1":
        raise ValueError("frozen equilibrium identity mismatch")
    game = require_fields(payload["game"], {
        "builder", "builder_version", "pot", "bet_fraction", "board",
        "oop_range", "ip_range"}, "frozen equilibrium game")
    if game["builder"] != "poker_solver.river_tree.build_river_game" \
            or game["builder_version"] != "river-single-bet-v1":
        raise ValueError("frozen equilibrium game identity mismatch")
    solver = require_fields(payload["solver"], {
        "algorithm", "implementation", "iterations", "average_delay"},
        "frozen equilibrium solver")
    if not all(isinstance(solver[name], str) and solver[name]
               for name in ("algorithm", "implementation")):
        raise ValueError("frozen equilibrium solver identity mismatch")
    if any(isinstance(solver[name], bool) or not isinstance(solver[name], int)
           or solver[name] < 0 for name in ("iterations", "average_delay")):
        raise ValueError("frozen equilibrium solver count mismatch")
    if not isinstance(game["board"], str) or not game["board"] \
            or not isinstance(game["oop_range"], dict) or not game["oop_range"] \
            or not isinstance(game["ip_range"], dict) or not game["ip_range"] \
            or not isinstance(payload["strategy"], dict) or not payload["strategy"]:
        raise ValueError("frozen equilibrium payload shape mismatch")
    declared = payload["artifact_sha256"]
    if not isinstance(declared, str) or len(declared) != 64 \
            or any(character not in "0123456789abcdef" for character in declared):
        raise ValueError("frozen equilibrium declared SHA-256 is invalid")
    content = {name: value for name, value in payload.items()
               if name != "artifact_sha256"}
    actual = digest(canonical_no_lf(content))
    if actual != declared:
        raise ValueError("frozen equilibrium content hash mismatch")
    catalog_hashes = {entry["equilibrium_artifact_sha256"]
                      for entry in fixed_catalog["opponents"]}
    if catalog_hashes != {actual}:
        raise ValueError("frozen equilibrium opponent catalog SHA-256 mismatch")
    return payload


def require_evidence_shape(evidence, ablation_id):
    if ablation_id == "abl_confidence_mvp__v1":
        require_fields(evidence, {
            "ablation_id", "estimator_method_version", "confidence_value_semantics",
            "dpl_semantic_version", "source", "observed_rate", "deviation",
            "confidence_value", "score_binary64_hex", "score_exact_decimal",
            "candidate_eligibility", "exploit_provider", "safety_alpha",
            "provider_result", "pi_base", "pi_exploit", "pi_final"},
            "confidence ablation evidence")
        require_fields(evidence["source"], {
            "k", "n", "baseline_rate", "tau", "sample_floor",
            "detector_threshold", "provider_threshold"}, "confidence evidence source")
        binary64(evidence["source"]["baseline_rate"], "confidence evidence baseline")
        binary64(evidence["observed_rate"], "confidence evidence observed rate")
        binary64(evidence["deviation"], "confidence evidence deviation")
        require_fields(evidence["candidate_eligibility"], {
            "structurally_eligible", "sample_gate", "deviation_gate",
            "confidence_gate", "emitted"}, "confidence eligibility")
        require_fields(evidence["provider_result"], {
            "node_lock_applied", "solver_result_id"}, "confidence provider result")
        return
    require_fields(evidence, {
        "ablation_id", "estimator_method_version", "dpl_semantic_version",
        "exploit_provider", "provider_config", "detected_leaks", "infosets",
        "safety_alpha", "pi_base", "pi_exploit", "pi_final"},
        "provider ablation evidence")
    require_fields(evidence["provider_config"], {
        "min_confidence", "min_ev_delta", "max_call_probability_shift",
        "supported_reason"}, "provider evidence config")
    if not isinstance(evidence["detected_leaks"], list) \
            or not isinstance(evidence["infosets"], list):
        raise ValueError("independent provider evidence lists are invalid")
    for leak in evidence["detected_leaks"]:
        require_fields(leak, {"reason_id", "observed_rate", "baseline_rate",
                              "effective_sample_size", "confidence"},
                       "provider detected leak")
        binary64(leak["observed_rate"], "provider leak observed rate")
        binary64(leak["baseline_rate"], "provider leak baseline rate")
        binary64(leak["confidence"], "provider leak confidence")
    for item in evidence["infosets"]:
        require_fields(item, {"infoset", "action_ev_contract", "action_ev",
                              "base_policy", "provider_policy",
                              "applied_leak_reason_ids", "trigger_reasons",
                              "exploit_source", "solver_result_id", "final_policy"},
                       "provider infoset evidence")
        require_fields(item["action_ev"], {"CALL", "FOLD"},
                       "provider action-EV map")
        for details in item["action_ev"].values():
            require_fields(details, {"value_binary64_hex", "value_exact_decimal",
                                     "counterfactual_reach_binary64_hex",
                                     "counterfactual_reach_exact_decimal"},
                           "provider action-EV evidence")


def interim_final_profile(ablation_id, k, n, expected_base, equilibrium,
                          oop_combos, ip_combos, baseline):
    exploit = copy.deepcopy(expected_base)
    if ablation_id == "abl_confidence_mvp__v1":
        score = min(1.0, max(0.0,
            ((k / n) - baseline) * 2.0 * min(1.0, n / 10)))
        emitted = n >= 10 and (k / n) - baseline >= 0.25 and score >= 0.9
        if emitted:
            raise ValueError("independent legacy transcript unexpectedly emitted")
    else:
        confidence = posterior(k, n, baseline=baseline)
        emitted = n >= 10 and (k / n) - baseline >= 0.25 and confidence >= 0.9
        if emitted:
            for oop in oop_combos:
                infoset = f"OOP:{oop}:vs_bet"
                values, _reach = action_values(
                    equilibrium, oop_combos, ip_combos, infoset)
                base_dist = expected_base[infoset]
                shift = min(base_dist["FOLD"], 0.5 * confidence)
                candidate = {"FOLD": base_dist["FOLD"] - shift,
                             "CALL": base_dist["CALL"] + shift}
                base_ev = math.fsum(base_dist[a] * values[a] for a in base_dist)
                candidate_ev = math.fsum(candidate[a] * values[a] for a in candidate)
                if candidate_ev - base_ev > 0.0:
                    exploit[infoset] = candidate
    return {
        infoset: {action: 0.5 * expected_base[infoset][action]
                  + 0.5 * exploit[infoset][action]
                  for action in expected_base[infoset]}
        for infoset in expected_base
    }


def reconstruct_execution(ablation_id, opponent_id, horizon, repetition_id,
                          opponent, expected_base, equilibrium, oop_combos,
                          ip_combos, baseline, epsilon):
    roots = {name: stream_root(opponent_id, horizon, repetition_id, name)
             for name in ("observation", "hero_action",
                          "epsilon_branch", "epsilon_action")}
    outcomes = [f"{oop}|{ip}" for oop in oop_combos for ip in ip_combos]
    outcome_weights = [1.0 / 9.0] * len(outcomes)
    counts = {"BET": 0, "CHECK": 0}
    events = []
    audits = []
    transcript = hashlib.sha256()
    for decision_index in range(horizon):
        deal_value = draw_digest(roots["observation"], decision_index)
        outcome = weighted_choice(outcomes, outcome_weights, deal_value)
        oop, ip = outcome.split("|")
        opponent_value = draw_digest(
            roots["observation"], decision_index, variate_index=1)
        opponent_actions = ["CHECK", "BET"]
        distribution = opponent[f"IP:{ip}:vs_check"]
        opponent_action = weighted_choice(
            opponent_actions, [distribution[action] for action in opponent_actions],
            opponent_value)
        counts[opponent_action] += 1
        event = {
            "decision_index": decision_index,
            "deal_draw_digest": deal_value,
            "deal_outcome_id": outcome,
            "opponent_action_draw_digest": opponent_value,
            "opponent_action": opponent_action,
            "hero_action": None,
        }
        if opponent_action == "BET":
            final = interim_final_profile(
                ablation_id, counts["BET"], decision_index + 1, expected_base,
                equilibrium, oop_combos, ip_combos, baseline)
            action = execution_action(
                final[f"OOP:{oop}:vs_bet"], ["FOLD", "CALL"], epsilon,
                decision_index, roots)
            event["hero_action"] = action
            audits.append({"decision_index": decision_index,
                           "legal_actions": ["FOLD", "CALL"], "audit": action})
        transcript.update(canonical(event))
        events.append(event)
    return events, audits, counts, transcript.hexdigest()


def metric(value, status, count):
    return {"value": None if value is None else decimal_token(value),
            "status": status, "record_count": count}


def mean_metric(values, empty_status="undefined_no_eligible_records"):
    if not values:
        return metric(None, empty_status, 0)
    return metric(decimal_mean(values), "defined", len(values))


def ratio_metric(numerator, denominator, empty_status):
    if denominator == 0:
        return metric(None, empty_status, 0)
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        value = Decimal(numerator) / Decimal(denominator)
    return metric(value, "defined", denominator)


def reliability(cells):
    bins = []
    total = len(cells)
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        for index in range(10):
            selected = [cell for cell in cells if cell["bin_index"] == index]
            lower = Decimal(index) / Decimal(10)
            upper = Decimal(index + 1) / Decimal(10)
            if not selected:
                bins.append({"index": index, "lower": decimal_token(lower),
                             "upper": decimal_token(upper),
                             "upper_inclusive": index == 9, "count": 0,
                             "mean_confidence": None, "empirical_rate": None,
                             "gap": None, "contribution": "0"})
                continue
            confidence = decimal_mean([cell["confidence"] for cell in selected])
            empirical = decimal_mean([Decimal(cell["label"]) for cell in selected])
            gap = abs(confidence - empirical)
            contribution = Decimal(len(selected)) / Decimal(total) * gap
            bins.append({"index": index, "lower": decimal_token(lower),
                         "upper": decimal_token(upper),
                         "upper_inclusive": index == 9, "count": len(selected),
                         "mean_confidence": decimal_token(confidence),
                         "empirical_rate": decimal_token(empirical),
                         "gap": decimal_token(gap),
                         "contribution": decimal_token(contribution)})
    if not total:
        return bins, metric(None, "undefined_no_eligible_records", 0)
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        value = sum((Decimal(item["contribution"]) for item in bins), Decimal(0))
    return bins, metric(value, "defined", total)


def calibration_metrics(cells):
    eligible = [cell for cell in cells if cell["label"] is not None]
    brier = mean_metric([cell["brier"] for cell in eligible])
    bins, ece = reliability(eligible)
    tp = sum(cell["predicted"] and cell["label"] == 1 for cell in eligible)
    fp = sum(cell["predicted"] and cell["label"] == 0 for cell in eligible)
    fn = sum(not cell["predicted"] and cell["label"] == 1 for cell in eligible)
    tn = sum(not cell["predicted"] and cell["label"] == 0 for cell in eligible)
    return {
        "brier": brier,
        "ece": ece,
        "precision": ratio_metric(tp, tp + fp, "undefined_no_predicted_positive"),
        "recall": ratio_metric(tp, tp + fn, "undefined_no_actual_positive"),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "reliability": bins,
    }


def compare_calibration(saved, expected, label):
    for name in ("brier", "ece", "precision", "recall", "confusion", "reliability"):
        if saved[name] != expected[name]:
            raise ValueError(
                "independent " + label + " " + name + " mismatch: "
                + repr({"expected": expected[name], "saved": saved[name]})
            )


def verify_oracle(oracle, opponent, oop_combos, ip_combos):
    for oop in oop_combos:
        response = oracle[f"OOP:{oop}:vs_bet"]
        if set(response.values()) != {0.0, 1.0}:
            raise ValueError("independent oracle response is not pure")
        response_values = {}
        for action in ("CALL", "FOLD"):
            response_values[action] = math.fsum(
                opponent[f"IP:{ip}:vs_check"]["BET"]
                * (showdown(oop, ip, 10.0) if action == "CALL" else -4.0)
                for ip in ip_combos)
        chosen_response = next(action for action, probability in response.items()
                               if probability == 1.0)
        if response_values[chosen_response] < max(response_values.values()) - 1e-12:
            raise ValueError("independent oracle response is suboptimal")
        start = oracle[f"OOP:{oop}:start"]
        if set(start.values()) != {0.0, 1.0}:
            raise ValueError("independent oracle start policy is not pure")
        bet_value = math.fsum(
            opponent[f"IP:{ip}:vs_bet"]["CALL"] * showdown(oop, ip, 10.0)
            + opponent[f"IP:{ip}:vs_bet"]["FOLD"] * 4.0 for ip in ip_combos)
        check_value = math.fsum(
            opponent[f"IP:{ip}:vs_check"]["CHECK"] * showdown(oop, ip, 4.0)
            + opponent[f"IP:{ip}:vs_check"]["BET"]
            * (response["CALL"] * showdown(oop, ip, 10.0)
               + response["FOLD"] * -4.0) for ip in ip_combos)
        chosen_start = next(action for action, probability in start.items()
                            if probability == 1.0)
        chosen_value = bet_value if chosen_start == "BET" else check_value
        if chosen_value < max(bet_value, check_value) - 1e-12:
            raise ValueError("independent oracle start policy is suboptimal")


def exact_values(cell, opponent, oop_combos, ip_combos):
    require_fields(cell, {"game_id", "opponent_id", "hero_player", "profiles",
                          "base_ev", "final_ev", "oracle_br_ev",
                          "gain_binary64_hex", "opportunity_binary64_hex",
                          "efficiency_binary64_hex", "efficiency_status"},
                   "exact-EV cell")
    profiles = {name: profile_from_payload(value)
                for name, value in cell["profiles"].items()}
    if set(profiles) != {"base", "final", "oracle_br"}:
        raise ValueError("independent exact-EV profiles are not closed-world")
    verify_oracle(profiles["oracle_br"], opponent, oop_combos, ip_combos)
    values = {}
    for name in ("base", "final", "oracle_br"):
        expected = exact_ev(profiles[name], opponent, oop_combos, ip_combos)
        saved = cell[name + "_ev"]
        require_fields(saved, {"production_binary64_hex",
                               "independent_leaves_binary64_hex"}, name + " EV")
        production = float.fromhex(saved["production_binary64_hex"])
        independent = float.fromhex(saved["independent_leaves_binary64_hex"])
        if not math.isclose(expected, production, rel_tol=0.0, abs_tol=1e-12) \
                or not math.isclose(expected, independent, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("independent " + name + " EV reconstruction mismatch")
        values[name] = production
    gain = float(values["final"] - values["base"])
    opportunity = float(values["oracle_br"] - values["base"])
    efficiency = None if abs(opportunity) <= 1e-12 else gain / opportunity
    status = "zero_or_near_zero_opportunity" if efficiency is None else "defined"
    if cell["gain_binary64_hex"] != gain.hex() \
            or cell["opportunity_binary64_hex"] != opportunity.hex() \
            or cell["efficiency_status"] != status \
            or cell["efficiency_binary64_hex"] != (
                None if efficiency is None else efficiency.hex()):
        raise ValueError(
            "independent gain/opportunity/efficiency mismatch: "
            + repr({"expected": (gain.hex(), opportunity.hex(),
                                 None if efficiency is None else efficiency.hex(), status),
                    "saved": (cell["gain_binary64_hex"],
                              cell["opportunity_binary64_hex"],
                              cell["efficiency_binary64_hex"],
                              cell["efficiency_status"])})
        )
    return values, efficiency


APPROVED_SOURCE_SNAPSHOT = {
    "target_commit": "e1c794566bfd5811582556eb56183d5940efda14",
    "p6_10a_batch_manifest": {
        "name": "p6_10a_batch_manifest",
        "path": ("experiments_output/p6_10a_comparator_ablation_run_20260719/"
                 "p6-10a-artifacts/comparator-ablation/p6_10a_batch_manifest.json"),
        "sha256": "dd5a6b66a7da822470d6cde7285e87473c2dbe152c71a9ba94c5b134bf9a2104",
        "size_bytes": 1107587,
    },
    "p6_10a_run_manifest": {
        "name": "p6_10a_run_manifest",
        "path": ("experiments_output/p6_10a_comparator_ablation_run_20260719/"
                 "phase6_p6_10a_run_manifest.json"),
        "sha256": "6ebe49fb794be047572adbd5185b05e693db1232b74d06f8c1f874e305dd9cce",
        "size_bytes": 4459,
    },
    "p6_10a_result_root": {
        "name": "p6_10a_result_root",
        "path": ("experiments_output/p6_10a_comparator_ablation_run_20260719/"
                 "p6-10a-artifacts/comparator-ablation/p6_10a_result_root.json"),
        "sha256": "6ed643e11cf44cb811778bccbdc1f2e7d13c39a63bee6d554eceec7834441e82",
        "size_bytes": 3428,
    },
    "comparator_ablation_report": {
        "name": "comparator_ablation_report",
        "path": ("experiments_output/p6_10a_comparator_ablation_run_20260719/"
                 "p6-10a-artifacts/comparator-ablation/comparator_ablation_report.json"),
        "sha256": "22bf99c2cb4bd58d3fa0cf508b28122ff632f8f3bc30660f119a454c96012914",
        "size_bytes": 317868,
    },
    "gate_b_readiness_gap_packet": {
        "name": "gate_b_readiness_gap_packet",
        "path": ("experiments_output/p6_10a_comparator_ablation_run_20260719/"
                 "p6-10a-artifacts/comparator-ablation/gate_b_readiness_gap_packet.json"),
        "sha256": "08cfdbd44e5700990f39ec61036357059918f1a6f0f8e782c33c6d248aeaa792",
        "size_bytes": 2313,
    },
}
APPROVED_P6_9_SOURCE_SNAPSHOT = {
    "baseline_commit": "c21ff7180e3417e0f418e1e993e5eaacdd3bb5cf",
    "exact_ev_cells_sha256": "422d45135f52d06f6ddf92b3b2875243a6d64c6d95c15d379d062038c19f938b",
    "p6_9_dependency_lock_sha256": (
        "ad56a49af345f5f768cc49b9400c0391"
        "91b98267bf415c4b0e3d372b81ed65d6"),
    "p6_9_result_root": {
        "path": ("experiments_output/p6_9_production_validation_run_20260718_c21ff71/"
                 "validation-artifacts/validation/validation_result_root.json"),
        "sha256": "b0a16209a143be697a38506fc4ad465a30a5cac8630ba86a42fcbb36830a8ba8",
    },
    "p6_9_run_manifest": {
        "path": ("experiments_output/p6_9_production_validation_run_20260718_c21ff71/"
                 "phase6_validation_run_manifest.json"),
        "sha256": "39d18561709e6e1f5d16464b4e6d61cb712d900efff510e5301d5c14a84dfd3f",
    },
    "pinned_verifier": {
        "existing_verifier_semantics_changed": False,
        "historical_repository_commit": "c21ff7180e3417e0f418e1e993e5eaacdd3bb5cf",
        "mode": "unchanged_p6_9_verifier_with_direct_child_git_adapter",
        "verified_repository_commit": "e1c794566bfd5811582556eb56183d5940efda14",
    },
    "primary_selection_report_sha256": (
        "36a2e11a7fe1a1d60f0f639e29e68554"
        "a3936cec8d80d613d3dbdbd63cc27b59"),
    "selected_config_lock_sha256": (
        "bc4387bd1306add4a2d48bb4cc0acaa3"
        "fa5404d672940df30891a7d31395485d"),
    "selected_config_sha256": "05c1e5a2ddbdc979ef7998cdda57af73f1b2ed8d540fe3fa37565e167ac0c54a",
    "validation_batch_manifest_sha256": (
        "71eda21f82849ba0ee519705d607af793"
        "00fca621dd34c1072d3b37f25c8d64b"),
}


def safe_source_path(repo_root, base, reference, fields, label):
    require_fields(reference, fields, label + " reference")
    value = reference["path"]
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError(label + " path is not canonical POSIX repository-relative")
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value \
            or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(label + " path is not canonical POSIX repository-relative")
    root = repo_root.resolve()
    anchor = base.resolve()
    path = (anchor / Path(*relative.parts)).resolve()
    try:
        anchor.relative_to(root)
        path.relative_to(anchor)
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(label + " path escapes the repository") from exc
    return path


def verify_source_snapshot(repo_root, root):
    require_exact(root["source_snapshot"], APPROVED_SOURCE_SNAPSHOT,
                  "approved source snapshot")
    verified = {}
    for name in ("p6_10a_batch_manifest", "p6_10a_run_manifest",
                 "p6_10a_result_root", "comparator_ablation_report",
                 "gate_b_readiness_gap_packet"):
        ref = root["source_snapshot"][name]
        path = safe_source_path(
            repo_root, repo_root, ref,
            {"name", "path", "sha256", "size_bytes"}, name)
        value, raw = load_canonical(path, name)
        if digest(raw) != ref["sha256"] or len(raw) != ref["size_bytes"]:
            raise ValueError("independent approved source bytes mismatch")
        verified[name] = (path, value)
    return verified


def source_records(repo_root, root, names, verified=None):
    verified = verify_source_snapshot(repo_root, root) if verified is None else verified
    run_path, run = verified["p6_10a_run_manifest"]
    require_exact(run["inputs"]["source_snapshot"], APPROVED_P6_9_SOURCE_SNAPSHOT,
                  "approved P6-9 source snapshot")
    p69_ref = run["inputs"]["source_snapshot"]["p6_9_result_root"]
    p69_path = safe_source_path(
        repo_root, repo_root, p69_ref, {"path", "sha256"}, "P6-9 result root")
    p69, raw = load_canonical(p69_path, "P6-9 result root")
    if digest(raw) != p69_ref["sha256"]:
        raise ValueError("independent P6-9 result-root reference mismatch")
    expected_names = ["validation_batch_manifest",
                      "validation_terminal_candidate_snapshots",
                      "validation_hero_policy_snapshots", "validation_exact_ev_cells",
                      "validation_calibration_cells", "validation_aggregate_metrics",
                      "primary_selection_report", "selected_config_lock"]
    if not isinstance(p69["artifacts"], list) \
            or [item.get("name") for item in p69["artifacts"]] != expected_names:
        raise ValueError("independent P6-9 source artifact set/order mismatch")
    refs = {item["name"]: item for item in p69["artifacts"]}
    result = {}
    for name in names:
        ref = refs[name]
        path = safe_source_path(
            repo_root, p69_path.parent, ref,
            {"name", "path", "sha256", "size_bytes"}, "P6-9 " + name)
        value, raw = load_canonical(path, "P6-9 " + name)
        if digest(raw) != ref["sha256"] or len(raw) != ref["size_bytes"]:
            raise ValueError("independent P6-9 source artifact mismatch")
        result[name] = value if name == "validation_batch_manifest" else value["records"]
    return result


def paired_delta(ablation, primary):
    primary_by_key = {(item["opponent_id"], item["horizon"], item["repetition_id"]): item
                      for item in primary}
    cells = []
    grouped = {}
    for item in ablation:
        key = (item["opponent_id"], item["horizon"], item["repetition_id"])
        left = float.fromhex(item["payload"]["result"]["cell"]
                             ["final_ev"]["production_binary64_hex"])
        right = float.fromhex(primary_by_key[key]["payload"]["result"]["cell"]
                              ["final_ev"]["production_binary64_hex"])
        delta = Decimal.from_float(left) - Decimal.from_float(right)
        cells.append({"opponent_id": key[0], "horizon": key[1],
                      "repetition_id": key[2], "delta": decimal_token(delta)})
        grouped.setdefault(key[:2], []).append(delta)
    groups = [{"opponent_id": key[0], "horizon": key[1],
               "mean_delta": decimal_token(decimal_mean(values)),
               "cell_count": len(values)} for key, values in sorted(grouped.items())]
    return {"cells": cells, "groups": groups,
            "macro_mean_delta": decimal_token(decimal_mean(
                [Decimal(item["mean_delta"]) for item in groups])),
            "micro_mean_delta": decimal_token(decimal_mean(
                [Decimal(item["delta"]) for item in cells]))}


root_path = Path(sys.argv[1]).resolve()
expected_root = sys.argv[2]
repo_root = Path(sys.argv[3]).resolve()
root, root_raw = load_canonical(root_path, "result root")
if digest(root_raw) != expected_root:
    raise ValueError("independent result-root hash mismatch")
root_fields = {"schema_version", "artifact_type", "scope", "physical_directory",
               "source_snapshot", "p6_10b_batch_manifest_sha256",
               "expected_cardinality", "manual_override", "series_pooling",
               "primary_selection_recomputed", "p6_9_artifacts_modified",
               "p6_10a_artifacts_modified", "p6_10_complete", "gate_b_ready",
               "human_approval_required", "artifacts"}
require_fields(root, root_fields, "result root")
expected_cardinality = {"ablation_count": 2, "candidate_count": 2,
                        "config_count": 2, "series_count": 2, "opponent_count": 9,
                        "horizon_count": 3, "repetition_count": 30,
                        "session_count": 1620, "session_record_count_per_type": 1620,
                        "candidate_record_count_per_type": 2,
                        "unique_stream_root_count": 3240,
                        "stream_root_reference_count": 6480,
                        "atomic_group_count": 54, "artifact_file_count": 10}
if root["schema_version"] != "phase6-p6-10b-result-root-v1" \
        or root["artifact_type"] != "p6_10b_result_root" \
        or root["scope"] != "p6_10b_confidence_provider_ablation" \
        or root["physical_directory"] != "confidence-provider-ablation" \
        or root["expected_cardinality"] != expected_cardinality:
    raise ValueError("independent result-root identity mismatch")
for flag in ("manual_override", "series_pooling", "primary_selection_recomputed",
             "p6_9_artifacts_modified", "p6_10a_artifacts_modified",
             "p6_10_complete", "gate_b_ready"):
    if root[flag] is not False:
        raise ValueError("independent result-root false flag mismatch")
if root["human_approval_required"] is not True:
    raise ValueError("independent human stop flag mismatch")
approved_sources = verify_source_snapshot(repo_root, root)
if root_path.name != "p6_10b_result_root.json" \
        or root_path.parent.name != "confidence-provider-ablation" \
        or root_path.parent.parent.name != "p6-10b-artifacts":
    raise ValueError("independent result-root path is noncanonical")
refs = root.get("artifacts")
expected_names = ["p6_10b_batch_manifest",
                  "abl_confidence_mvp__v1__terminal_candidate_snapshots",
                  "abl_confidence_mvp__v1__hero_policy_snapshots",
                  "abl_confidence_mvp__v1__exact_ev_cells",
                  "abl_confidence_mvp__v1__calibration_cells",
                  "abl_confidence_mvp__v1__aggregate_metrics",
                  "abl_provider_rule__v1__terminal_candidate_snapshots",
                  "abl_provider_rule__v1__hero_policy_snapshots",
                  "abl_provider_rule__v1__exact_ev_cells",
                  "abl_provider_rule__v1__calibration_cells",
                  "abl_provider_rule__v1__aggregate_metrics",
                  "p6_10b_contract_closure_report"]
if not isinstance(refs, list) or [item.get("name") for item in refs] != expected_names:
    raise ValueError("independent artifact reference set/order mismatch")
expected_files = {"p6_10b_result_root.json", "p6_10b_batch_manifest.json",
                  "p6_10b_contract_closure_report.json"} | {
                      name + ".json" for name in expected_names[1:-1]}
if {item.name for item in root_path.parent.iterdir()} != expected_files \
        or any(not item.is_file() for item in root_path.parent.iterdir()):
    raise ValueError("independent result directory is not closed-world")
if {item.name for item in root_path.parent.parent.iterdir()} != {
        "confidence-provider-ablation"}:
    raise ValueError("independent artifact parent is not closed-world")
expected_paths = {"p6_10b_batch_manifest": "p6_10b_batch_manifest.json",
                  "p6_10b_contract_closure_report":
                  "p6_10b_contract_closure_report.json"}
expected_paths.update({name: name + ".json" for name in expected_names[1:-1]})
if [item.get("path") for item in refs] != [expected_paths[name]
                                             for name in expected_names]:
    raise ValueError("independent artifact name/path mapping mismatch")
artifacts = {}
for ref in refs:
    if not isinstance(ref, dict) or set(ref) != {"name", "path", "sha256", "size_bytes"}:
        raise ValueError("independent artifact reference is not closed-world")
    relative = Path(ref["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("independent artifact path escapes result root")
    path = (root_path.parent / relative).resolve()
    if path.parent != root_path.parent:
        raise ValueError("independent artifact path is not a direct child")
    value, raw = load_canonical(path, ref["name"])
    if len(raw) != ref["size_bytes"] or digest(raw) != ref["sha256"]:
        raise ValueError("independent artifact reference mismatch")
    artifacts[ref["name"]] = value

batch = artifacts["p6_10b_batch_manifest"]
fixed_validation = source_records(
    repo_root, root, ("validation_batch_manifest",), approved_sources)[
        "validation_batch_manifest"]
fixed_sampling = fixed_validation["sampling_contract"]
fixed_catalog = fixed_validation["validation_catalog_index"]
batch_fields = {"schema_version", "artifact_type", "scope", "source_snapshot",
                "selected_primary", "ablation_configs", "sampling_contract",
                "opponent_catalog", "horizons", "repetitions", "sessions",
                "stream_roots", "stream_root_reference_count", "expected_cardinality",
                "metric_contract", "series_non_pooling", "manual_override",
                "primary_selection_recomputed"}
require_fields(batch, batch_fields, "batch manifest")
batch_sha = digest(canonical(batch))
expected_metric_contract = {
    "abl_confidence_mvp__v1": {"primary": "macro.brier",
        "delta": "ablation_minus_selected_primary", "final_ev": "secondary"},
    "abl_provider_rule__v1": {"primary": "macro.mean_cell_efficiency",
        "delta": "ablation_minus_selected_primary", "final_ev": "secondary",
        "calibration_invariance": True}}
if batch["schema_version"] != "phase6-p6-10b-batch-manifest-v1" \
        or batch["artifact_type"] != "p6_10b_batch_manifest" \
        or batch["scope"] != "p6_10b_confidence_provider_ablation" \
        or batch["source_snapshot"] != root["source_snapshot"] \
        or batch_sha != root["p6_10b_batch_manifest_sha256"] \
        or batch["expected_cardinality"] != expected_cardinality \
        or batch["metric_contract"] != expected_metric_contract \
        or batch["series_non_pooling"] is not True \
        or batch["manual_override"] is not False \
        or batch["primary_selection_recomputed"] is not False:
    raise ValueError("independent batch contract mismatch")
if len(batch["sessions"]) != 1620 or len(batch["stream_roots"]) != 3240 \
        or batch["stream_root_reference_count"] != 6480:
    raise ValueError("independent batch cardinality mismatch")
expected_primary = {
    "candidate_id": ("primary_bb_v2__"
        "05c1e5a2ddbdc979ef7998cdda57af73f1b2ed8d540fe3fa37565e167ac0c54a"),
    "config_sha256": "05c1e5a2ddbdc979ef7998cdda57af73f1b2ed8d540fe3fa37565e167ac0c54a",
    "series_id": "4bc47549458fc3ee78e2ccbbe90ffa21cc44d0ef153ac3b24ab62572c8542d97",
    "manual_override": False,
}
require_exact(batch["selected_primary"], expected_primary, "selected primary")
require_exact(batch["sampling_contract"], fixed_sampling,
              "fixed-source sampling contract")
require_exact(batch["opponent_catalog"], fixed_catalog,
              "fixed-source opponent catalog")
require_fields(batch["sampling_contract"], {"payload", "sha256"},
               "sampling contract reference")
if digest(canonical(batch["sampling_contract"]["payload"])) \
        != batch["sampling_contract"]["sha256"]:
    raise ValueError("independent sampling contract hash mismatch")
require_fields(batch["opponent_catalog"], {"schema_version", "split", "opponents"},
               "opponent catalog")
if batch["opponent_catalog"]["schema_version"] != "phase6-validation-catalog-index-v1" \
        or batch["opponent_catalog"]["split"] != "validation" \
        or len(batch["opponent_catalog"]["opponents"]) != 9:
    raise ValueError("independent opponent catalog envelope mismatch")
for opponent_entry in batch["opponent_catalog"]["opponents"]:
    require_fields(opponent_entry, {"opponent_id", "config", "config_sha256",
                                    "strategy_sha256", "equilibrium_artifact_sha256",
                                    "primary_true_deltas", "control_role", "coverage"},
                   "opponent catalog entry")
    require_fields(opponent_entry["config"], {"schema_version", "opponent_id",
        "opponent_version", "generator_version", "split", "opponent_position",
        "equilibrium_version", "equilibrium_artifact_sha256", "lock_mode",
        "unlocked_policy_mode", "combo_allocation", "leak_vector", "seed"},
        "opponent catalog config")
    if opponent_entry["opponent_id"] != opponent_entry["config"]["opponent_id"] \
            or opponent_entry["equilibrium_artifact_sha256"] \
            != opponent_entry["config"]["equilibrium_artifact_sha256"]:
        raise ValueError("independent opponent catalog config mismatch")
catalog_entries = {item["opponent_id"]: item
                   for item in fixed_catalog["opponents"]}
if len(catalog_entries) != 9:
    raise ValueError("independent opponent catalog contains duplicate IDs")
ablation_order = ("abl_confidence_mvp__v1", "abl_provider_rule__v1")
if [item.get("ablation_id") for item in batch["ablation_configs"]] != list(ablation_order):
    raise ValueError("independent ablation identity mismatch")
configs = {item["ablation_id"]: item for item in batch["ablation_configs"]}
for ablation_id, entry in configs.items():
    require_fields(entry, {"ablation_id", "config", "config_sha256", "candidate_id",
                           "series_id", "intervention"}, "ablation projection")
    confidence_ablation = ablation_id == "abl_confidence_mvp__v1"
    intervention = ({"leak_confidence_estimator": {
        "from": "beta-binomial-upper-tail-v1", "to": "mvp-confidence-heuristic-v1"}}
        if confidence_ablation else {"exploit_provider": {
            "from": "nodelock-provider-r008-v2",
            "to": "rule-exploit-provider-r008-v1"}})
    expected_config = {
        "schema_version": "phase6-p6-10b-ablation-config-v1",
        "ablation_id": ablation_id,
        "source_primary_candidate_id": expected_primary["candidate_id"],
        "source_primary_config_sha256": expected_primary["config_sha256"],
        "source_primary_series_id": expected_primary["series_id"],
        "intervention": intervention,
        "retained_primary_config": {
            "grid_version": "phase6-primary-grid-v1", "epsilon": "0.05",
            "sample_floor": 10, "detector_confidence": "0.9",
            "provider_confidence": "0.9", "safety_alpha": "0.5",
            "sampling_contract_sha256": fixed_sampling["sha256"]},
        "estimator_contract": {
            "method_version": ("mvp-confidence-heuristic-v1" if confidence_ablation
                               else "beta-binomial-upper-tail-v1"),
            "confidence_value_semantics": (
                "bounded_legacy_score_not_probability" if confidence_ablation
                else "posterior_probability"),
            "dpl_semantic_version": "1.0.0" if confidence_ablation else "2.0.0",
            "legacy_arithmetic": (
                "historical-binary64-with-hex-and-exact-decimal"
                if confidence_ablation else None)},
        "provider_contract": {
            "provider_version": ("nodelock-provider-r008-v2" if confidence_ablation
                                 else "rule-exploit-provider-r008-v1"),
            "min_confidence": "0.9", "min_ev_delta": "0",
            "max_call_probability_shift": "0.5", "supported_reason": "LEAK_R008",
            "solver_result_id": None},
        "action_ev_contract": {
            "version": ("nodelock-solver-action-policy-v2" if confidence_ablation
                        else "equilibrium-counterfactual-action-value-v1"),
            "counterfactual_reach": (None if confidence_ablation
                else "chance_probability_x_frozen_equilibrium_ip_probability"),
            "hero_reach_included": False, "zero_counterfactual_reach": "hard_failure"},
        "sampling_contract_sha256": fixed_sampling["sha256"],
        "opponent_catalog_sha256": digest(canonical(fixed_catalog)),
        "horizon_set": [50, 200, 1000],
        "repetition_set": [f"r{index:03d}" for index in range(1, 31)],
        "evaluator_versions": {"calibration": "all-candidate-calibration-v1",
                               "exact_ev": "p6-5-exact-ev-cell-v2"},
        "decimal_contract": {"precision": 50, "rounding": "ROUND_HALF_EVEN",
                             "wire": "finite-fixed-point-canonical"},
        "manual_override": False,
        "primary_selection_recomputed": False,
    }
    require_exact(entry["config"], expected_config, "retained ablation config")
    config_hash = digest(canonical(entry["config"]))
    expected_series = digest(canonical({"config": entry["config"],
        "opponents": fixed_catalog["opponents"],
        "candidate_dimensions": [{"rule_id": "LEAK_R008",
            "situation_key": "river_vs_check", "action_group": ["BET"],
            "tau": "0.25"}]}))
    if entry["config_sha256"] != config_hash \
            or entry["candidate_id"] != ablation_id + "__" + config_hash \
            or entry["series_id"] != expected_series \
            or entry["intervention"] != entry["config"]["intervention"]:
        raise ValueError("independent ablation hash/identity mismatch")
if len({expected_primary["series_id"],
        *(entry["series_id"] for entry in configs.values())}) != 3:
    raise ValueError("independent primary/ablation series IDs are not unique")
expected_repetitions = [{"repetition_id": f"r{index:03d}",
                         "master_seed": 620000 + index} for index in range(1, 31)]
if batch["horizons"] != [50, 200, 1000] \
        or batch["repetitions"] != expected_repetitions:
    raise ValueError("independent batch horizon/repetition contract mismatch")
coordinates = sorted((item["opponent_id"], horizon, repetition["repetition_id"])
                     for item in fixed_catalog["opponents"]
                     for horizon in batch["horizons"]
                     for repetition in batch["repetitions"])
expected_roots = [
    stream_root(opponent_id, horizon, repetition_id, stream_name)
    for opponent_id, horizon, repetition_id in coordinates
    for stream_name in ("observation", "hero_action", "epsilon_branch", "epsilon_action")]
require_exact(batch["stream_roots"], expected_roots, "stream-root exact product")
expected_sessions = [
    {"candidate_id": configs[ablation_id]["candidate_id"],
     "opponent_id": opponent_id, "horizon": horizon,
     "repetition_id": repetition_id}
    for ablation_id in ablation_order
    for opponent_id, horizon, repetition_id in coordinates]
if batch["sessions"] != expected_sessions or len({
        (item["candidate_id"], item["opponent_id"], item["horizon"],
         item["repetition_id"]) for item in batch["sessions"]}) != 1620:
    raise ValueError("independent batch session product/order mismatch")
equilibrium_payload = load_fixed_equilibrium(repo_root, fixed_catalog)
equilibrium = {name: {action: float(Decimal(probability))
                      for action, probability in distribution.items()}
               for name, distribution in equilibrium_payload["strategy"].items()}
oop_combos = list(equilibrium_payload["game"]["oop_range"])
ip_combos = list(equilibrium_payload["game"]["ip_range"])
r008_infosets = [name for name in equilibrium
                 if name.startswith("IP:") and name.endswith(":vs_check")]
r008_weights = [reach_weight(name, equilibrium, oop_combos, ip_combos)
                for name in r008_infosets]
r008_baseline = math.fsum(
    weight * equilibrium[name]["BET"]
    for name, weight in zip(r008_infosets, r008_weights)) / math.fsum(r008_weights)
opponents = {}
for path in sorted((repo_root / "configs/opponents/validation").glob("*.opponent.json")):
    raw = path.read_bytes()
    config = json.loads(raw)
    entry = catalog_entries.get(config.get("opponent_id"))
    if entry is None or entry["config"] != config \
            or entry["config_sha256"] != digest(canonical_no_lf(config)):
        raise ValueError("independent opponent catalog differs from frozen config bytes")
    opponents[config["opponent_id"]] = opponent_profile(
        config, equilibrium, oop_combos, ip_combos)
if len(opponents) != 9:
    raise ValueError("independent opponent catalog cardinality mismatch")
opponent_roles = {item["opponent_id"]: item["control_role"]
                  for item in fixed_catalog["opponents"]}
if set(opponent_roles) != set(opponents):
    raise ValueError("independent opponent-role catalog mismatch")

suffixes = ("terminal_candidate_snapshots", "hero_policy_snapshots", "exact_ev_cells",
            "calibration_cells", "aggregate_metrics")
exact_by_ablation = {}
aggregate_by_ablation = {}
calibration_by_ablation = {}
for ablation_id, config_entry in configs.items():
    files = [artifacts[f"{ablation_id}__{suffix}"] for suffix in suffixes]
    for suffix, artifact in zip(suffixes, files):
        fields = {"schema_version", "artifact_type", "status", "ablation_id",
                  "p6_10b_batch_manifest_sha256", "p6_10a_result_root_sha256",
                  "source_validation_batch_manifest_sha256", "candidate_id",
                  "config_sha256", "series_id", "series_pooling", "records"}
        require_fields(artifact, fields, "artifact envelope")
        name = f"{ablation_id}__{suffix}"
        if artifact["schema_version"] != "phase6-p6-10b-artifact-v1" \
                or artifact["artifact_type"] != name \
                or artifact["status"] != "completed_and_verified" \
                or artifact["ablation_id"] != ablation_id \
                or artifact["p6_10b_batch_manifest_sha256"] != batch_sha \
                or artifact["p6_10a_result_root_sha256"] \
                != root["source_snapshot"]["p6_10a_result_root"]["sha256"] \
                or artifact["source_validation_batch_manifest_sha256"] \
                != "71eda21f82849ba0ee519705d607af79300fca621dd34c1072d3b37f25c8d64b" \
                or artifact["candidate_id"] != config_entry["candidate_id"] \
                or artifact["config_sha256"] != config_entry["config_sha256"] \
                or artifact["series_id"] != config_entry["series_id"] \
                or artifact["series_pooling"] is not False:
            raise ValueError("independent artifact envelope mismatch")
    rows_by_type = [item["records"] for item in files]
    if [len(rows) for rows in rows_by_type] != [810, 810, 810, 1, 1]:
        raise ValueError("independent record cardinality mismatch")
    wrapper_fields = (
        {"record", "execution_events", "action_draw_audits", "ablation_evidence"},
        {"record", "ablation_evidence"}, {"record"}, {"record"}, {"record"})
    parsed = []
    for rows, expected_wrapper_fields in zip(rows_by_type, wrapper_fields):
        current = []
        for row in rows:
            require_fields(row, expected_wrapper_fields, "artifact row wrapper")
            record = row["record"]
            require_fields(record, {"candidate_id", "opponent_id", "horizon",
                                    "repetition_id", "payload", "payload_sha256"},
                           "artifact record")
            if digest(canonical(record["payload"])) != record["payload_sha256"]:
                raise ValueError("independent record payload hash mismatch")
            current.append(record)
        parsed.append(current)
    if [record_key(item) for item in parsed[0]] != [record_key(item) for item in parsed[1]] \
            or [record_key(item) for item in parsed[0]] != [record_key(item) for item in parsed[2]]:
        raise ValueError("independent session join/order mismatch")
    session_offset = ablation_order.index(ablation_id) * 810
    expected_record_keys = [
        (item["candidate_id"], item["opponent_id"], item["horizon"], item["repetition_id"])
        for item in expected_sessions[session_offset:session_offset + 810]]
    actual_record_keys = [record_key(item) for item in parsed[0]]
    if actual_record_keys != expected_record_keys or len(set(actual_record_keys)) != 810:
        raise ValueError("independent artifact session product/order mismatch")
    for singleton in parsed[3:]:
        item = singleton[0]
        if (item["candidate_id"] != config_entry["candidate_id"]
                or item["opponent_id"] is not None or item["horizon"] is not None
                or item["repetition_id"] is not None):
            raise ValueError("independent candidate aggregate identity mismatch")
    computed_confidence = {}
    computed_efficiency = {}
    for terminal_row, policy_row, exact_row, terminal_wrap, policy_wrap in zip(
            parsed[0], parsed[1], parsed[2], rows_by_type[0], rows_by_type[1]):
        terminal = terminal_row["payload"]["result"]
        policy = policy_row["payload"]["result"]
        exact = exact_row["payload"]["result"]
        if digest(canonical(terminal)) != policy["source_terminal_sha256"] \
                or digest(canonical(terminal)) != exact["source_terminal_sha256"] \
                or digest(canonical(policy)) != exact["source_hero_policy_sha256"]:
            raise ValueError("independent terminal-policy-EV hash chain mismatch")
        evidence = terminal_wrap["ablation_evidence"]
        if evidence != policy_wrap["ablation_evidence"]:
            raise ValueError("independent evidence wrapper mismatch")
        require_evidence_shape(evidence, ablation_id)
        n = terminal["opportunity_count"]
        k = terminal["action_counts"]["BET"]
        base = profile_from_payload(policy["base_hero_policy"])
        final = profile_from_payload(policy["final_hero_policy"])
        expected_base = {name: distribution for name, distribution in equilibrium.items()
                         if name.startswith("OOP:")}
        if base != expected_base or evidence["pi_base"] != expected_base:
            raise ValueError("independent frozen-equilibrium base policy mismatch")
        coordinate = (terminal_row["opponent_id"], terminal_row["horizon"],
                      terminal_row["repetition_id"])
        expected_events, expected_audits, expected_counts, expected_transcript = \
            reconstruct_execution(
                ablation_id, coordinate[0], coordinate[1], coordinate[2],
                opponents[coordinate[0]], expected_base, equilibrium, oop_combos,
                ip_combos, r008_baseline,
                config_entry["config"]["retained_primary_config"]["epsilon"])
        require_fields(terminal, {"schema_version", "evaluator_version", "session",
                                  "action_counts", "opportunity_count",
                                  "transcript_sha256"}, "terminal result")
        expected_session = {"candidate_id": config_entry["candidate_id"],
                            "opponent_id": coordinate[0], "horizon": coordinate[1],
                            "repetition_id": coordinate[2]}
        if terminal["schema_version"] != "phase6-validation-terminal-result-v1" \
                or terminal["evaluator_version"] != "all-candidate-calibration-v1" \
                or terminal["session"] != expected_session \
                or terminal["opportunity_count"] != coordinate[1] \
                or terminal["action_counts"] != expected_counts \
                or terminal["transcript_sha256"] != expected_transcript:
            raise ValueError("independent terminal transcript reconstruction mismatch")
        require_exact(terminal_wrap["execution_events"], expected_events,
                      "execution event transcript")
        require_exact(terminal_wrap["action_draw_audits"], expected_audits,
                      "action draw audit transcript")
        expected_exploit = copy.deepcopy(expected_base)
        if ablation_id == "abl_confidence_mvp__v1":
            observed = k / n
            deviation = observed - r008_baseline
            score = min(1.0, max(0.0,
                deviation * 2.0 * min(1.0, n / 10)))
            if evidence["score_binary64_hex"] != score.hex() \
                    or evidence["score_exact_decimal"] != decimal_wire(score) \
                    or evidence["confidence_value"] != decimal_wire(score):
                raise ValueError("independent legacy score mismatch")
            expected_emit = (n >= 10 and deviation >= 0.25
                             and score >= 0.9)
            expected_eligibility = {
                "structurally_eligible": True,
                "sample_gate": n >= 10,
                "deviation_gate": (k / n) - r008_baseline >= 0.25,
                "confidence_gate": score >= 0.9,
                "emitted": expected_emit,
            }
            require_exact(evidence["candidate_eligibility"], expected_eligibility,
                          "legacy eligibility gate")
            expected_source = {"k": k, "n": n,
                "baseline_rate": binary_evidence(r008_baseline), "tau": "0.25",
                "sample_floor": 10, "detector_threshold": "0.9",
                "provider_threshold": "0.9"}
            if evidence["ablation_id"] != ablation_id \
                    or evidence["estimator_method_version"] \
                    != "mvp-confidence-heuristic-v1" \
                    or evidence["confidence_value_semantics"] \
                    != "bounded_legacy_score_not_probability" \
                    or evidence["dpl_semantic_version"] != "1.0.0" \
                    or evidence["source"] != expected_source \
                    or evidence["observed_rate"] != binary_evidence(observed) \
                    or evidence["deviation"] != binary_evidence(deviation) \
                    or evidence["exploit_provider"] != "nodelock-provider-r008-v2" \
                    or evidence["safety_alpha"] != "0.5" \
                    or evidence["provider_result"] != {
                        "node_lock_applied": expected_emit, "solver_result_id": None}:
                raise ValueError("independent confidence evidence reconstruction mismatch")
            if expected_emit:
                raise ValueError("independent frozen legacy series unexpectedly emitted")
            confidence = score
            calibration_confidence = Decimal(decimal_wire(confidence))
        else:
            confidence = posterior(k, n, baseline=r008_baseline)
            detected = evidence["detected_leaks"]
            expected_emit = (n >= 10 and (k / n) - r008_baseline >= 0.25
                             and confidence >= 0.9)
            expected_detected = ([{
                "reason_id": "LEAK_R008", "observed_rate": binary_evidence(k / n),
                "baseline_rate": binary_evidence(r008_baseline),
                "effective_sample_size": n,
                "confidence": binary_evidence(confidence)}] if expected_emit else [])
            if detected != expected_detected:
                raise ValueError("independent posterior emit gate mismatch")
            if evidence["ablation_id"] != ablation_id \
                    or evidence["estimator_method_version"] \
                    != "beta-binomial-upper-tail-v1" \
                    or evidence["dpl_semantic_version"] != "2.0.0" \
                    or evidence["exploit_provider"] != "rule-exploit-provider-r008-v1" \
                    or evidence["provider_config"] != {
                        "min_confidence": "0.9", "min_ev_delta": "0",
                        "max_call_probability_shift": "0.5",
                        "supported_reason": "LEAK_R008"} \
                    or evidence["safety_alpha"] != "0.5":
                raise ValueError("independent provider evidence reconstruction mismatch")
            expected_infosets = {f"OOP:{oop}:vs_bet" for oop in oop_combos}
            if {item.get("infoset") for item in evidence["infosets"]} != expected_infosets \
                    or len(evidence["infosets"]) != len(expected_infosets):
                raise ValueError("independent Rule infoset product mismatch")
            for item in evidence["infosets"]:
                values, reach = action_values(equilibrium, oop_combos, ip_combos,
                                              item["infoset"])
                for action, expected in values.items():
                    saved = item["action_ev"][action]
                    if saved["value_binary64_hex"] != expected.hex() \
                            or saved["value_exact_decimal"] != decimal_wire(expected) \
                            or saved["counterfactual_reach_binary64_hex"] != reach.hex() \
                            or saved["counterfactual_reach_exact_decimal"] != decimal_wire(reach):
                        raise ValueError("independent Rule action-EV mismatch")
                base_dist = expected_base[item["infoset"]]
                if item["base_policy"] != base_dist:
                    raise ValueError("independent Rule base-policy evidence mismatch")
                expected_policy = dict(base_dist)
                if expected_emit:
                    shift = min(base_dist["FOLD"], 0.5 * confidence)
                    candidate = {"FOLD": base_dist["FOLD"] - shift,
                                 "CALL": base_dist["CALL"] + shift}
                    base_ev = math.fsum(base_dist[a] * values[a] for a in base_dist)
                    candidate_ev = math.fsum(candidate[a] * values[a] for a in candidate)
                    if candidate_ev - base_ev > 0.0:
                        expected_policy = candidate
                if item["provider_policy"] != expected_policy:
                    raise ValueError("independent Rule provider policy mismatch")
                applied = expected_emit and expected_policy != base_dist
                if item["action_ev_contract"] \
                        != "equilibrium-counterfactual-action-value-v1" \
                        or item["applied_leak_reason_ids"] \
                        != (["LEAK_R008"] if applied else []) \
                        or item["trigger_reasons"] \
                        != (["TRG_R001", "TRG_R002"] if applied else []) \
                        or item["exploit_source"] != "rule_based" \
                        or item["solver_result_id"] is not None:
                    raise ValueError("independent Rule nested evidence mismatch")
                expected_exploit[item["infoset"]] = expected_policy
            calibration_confidence = Decimal(str(confidence))
        computed_confidence[coordinate] = (calibration_confidence, expected_emit)
        if evidence["pi_exploit"] != expected_exploit:
            raise ValueError("independent exploit-policy reconstruction mismatch")
        expected_final_profile = {}
        for infoset in expected_base:
            expected_final = {action: 0.5 * expected_base[infoset][action]
                              + 0.5 * expected_exploit[infoset][action]
                              for action in expected_base[infoset]}
            expected_final_profile[infoset] = expected_final
            if any(final[infoset][action].hex() != value.hex()
                   for action, value in expected_final.items()):
                raise ValueError("independent SafetyMixer mismatch")
        if evidence["pi_final"] != expected_final_profile:
            raise ValueError("independent final-policy evidence mismatch")
        if ablation_id == "abl_provider_rule__v1":
            for item in evidence["infosets"]:
                if item["final_policy"] != expected_final_profile[item["infoset"]]:
                    raise ValueError("independent Rule final-policy evidence mismatch")
        cell = exact["cell"]
        _values, efficiency = exact_values(
            cell, opponents[terminal_row["opponent_id"]], oop_combos, ip_combos)
        computed_efficiency[coordinate] = efficiency
    calibration = parsed[3][0]["payload"]["result"]
    aggregate = parsed[4][0]["payload"]["result"]
    independent_cells = []
    for cell in calibration["cells"]:
        key = cell["key"]
        coordinate = (key[1], key[4], key[5])
        confidence, predicted = computed_confidence[coordinate]
        if key[0] != config_entry["series_id"] \
                or cell["confidence"] != decimal_token(confidence) \
                or cell["predicted_positive"] is not predicted:
            raise ValueError(
                "independent calibration confidence/emit join mismatch: "
                + repr({"coordinate": coordinate,
                        "expected": (config_entry["series_id"],
                                     decimal_token(confidence), predicted),
                        "saved": (key[0], cell["confidence"],
                                  cell["predicted_positive"])})
            )
        label = cell["label"]
        with localcontext() as context:
            context.prec = 50
            context.rounding = ROUND_HALF_EVEN
            brier = None if label is None else (confidence - Decimal(label)) ** 2
        bin_index = None if label is None else min(int(confidence * 10), 9)
        if cell["brier_component"] != (None if brier is None else decimal_token(brier)) \
                or cell["bin_index"] != bin_index:
            raise ValueError(
                "independent calibration component mismatch: "
                + repr({"coordinate": coordinate,
                        "expected": (None if brier is None else decimal_token(brier),
                                     bin_index),
                        "saved": (cell["brier_component"], cell["bin_index"]),
                        "confidence": decimal_token(confidence), "label": label})
            )
        independent_cells.append({"coordinate": coordinate, "confidence": confidence,
                                  "predicted": predicted, "label": label,
                                  "brier": brier, "bin_index": bin_index})
    grouped_cells = {}
    grouped_efficiency = {}
    for cell in independent_cells:
        grouped_cells.setdefault(cell["coordinate"][:2], []).append(cell)
    for coordinate, value in computed_efficiency.items():
        if value is not None:
            grouped_efficiency.setdefault(coordinate[:2], []).append(
                Decimal.from_float(value))
    if len(grouped_cells) != 27 or any(len(values) != 30 for values in grouped_cells.values()):
        raise ValueError("independent calibration group cardinality mismatch")
    expected_groups = {}
    for key in sorted(grouped_cells):
        calibration_expected = calibration_metrics(grouped_cells[key])
        efficiency_expected = mean_metric(
            grouped_efficiency.get(key, []), "undefined_no_defined_efficiency_cells")
        expected_groups[key] = (calibration_expected, efficiency_expected)
    if len(aggregate["atomic_groups"]) != 27:
        raise ValueError("independent aggregate group cardinality mismatch")
    require_exact(
        [(item.get("opponent_id"), item.get("horizon"))
         for item in aggregate["atomic_groups"]],
        list(expected_groups),
        "aggregate group key sequence",
    )
    for saved_group in aggregate["atomic_groups"]:
        key = (saved_group["opponent_id"], saved_group["horizon"])
        calibration_expected, efficiency_expected = expected_groups[key]
        compare_calibration(saved_group["calibration"], calibration_expected,
                            "atomic-group calibration")
        if saved_group["mean_cell_efficiency"] != efficiency_expected:
            raise ValueError("independent atomic-group efficiency mismatch")
    macro = aggregate["macro"]
    for name in ("brier", "ece", "precision", "recall"):
        defined = [Decimal(values[0][name]["value"]) for values in expected_groups.values()
                   if values[0][name]["value"] is not None]
        expected = mean_metric(defined, "undefined_no_defined_groups")
        if macro[name] != expected \
                or macro["undefined_" + name + "_groups"] != 27 - len(defined):
            raise ValueError("independent macro " + name + " mismatch")
    defined_efficiency = [Decimal(values[1]["value"]) for values in expected_groups.values()
                          if values[1]["value"] is not None]
    if macro["mean_cell_efficiency"] != mean_metric(
            defined_efficiency, "undefined_no_defined_groups") \
            or macro["undefined_efficiency_groups"] != 27 - len(defined_efficiency):
        raise ValueError("independent macro efficiency mismatch")
    micro_expected = calibration_metrics(independent_cells)
    compare_calibration(aggregate["micro"]["calibration"], micro_expected,
                        "micro calibration")
    all_efficiency = [Decimal.from_float(value) for value in computed_efficiency.values()
                      if value is not None]
    if aggregate["micro"]["micro_mean_cell_efficiency"] != mean_metric(
            all_efficiency, "undefined_no_defined_efficiency_cells"):
        raise ValueError("independent micro efficiency mismatch")
    gto_ids = {key for key, role in opponent_roles.items()
               if role == "gto_negative_control"}
    gto_groups = []
    total_fp = 0
    total_denominator = 0
    for key in sorted(grouped_cells):
        if key[0] not in gto_ids:
            continue
        eligible = [cell for cell in grouped_cells[key] if cell["label"] is not None]
        if any(cell["label"] != 0 for cell in eligible):
            raise ValueError("independent GTO label mismatch")
        fp = sum(cell["predicted"] for cell in eligible)
        denominator = len(eligible)
        rate = ratio_metric(fp, denominator, "undefined_no_eligible_records")
        gto_groups.append({"opponent_id": key[0], "horizon": key[1],
                           "rate": {"numerator": fp, "denominator": denominator,
                                    "value": rate["value"], "status": rate["status"]}})
        total_fp += fp
        total_denominator += denominator
    group_rates = [Decimal(item["rate"]["value"]) for item in gto_groups]
    micro_rate = ratio_metric(total_fp, total_denominator,
                              "undefined_no_eligible_records")
    expected_gto = {"metric_id": "gto_negative_control_micro_fpr_v1",
                    "groups": gto_groups,
                    "macro": mean_metric(group_rates, "undefined_no_defined_groups"),
                    "micro": {"numerator": total_fp, "denominator": total_denominator,
                              "value": micro_rate["value"], "status": micro_rate["status"]}}
    if aggregate["gto_fpr"] != expected_gto:
        raise ValueError("independent GTO FPR mismatch")
    exact_by_ablation[ablation_id] = parsed[2]
    aggregate_by_ablation[ablation_id] = aggregate
    calibration_by_ablation[ablation_id] = calibration

report = artifacts["p6_10b_contract_closure_report"]
report_fields = {"schema_version", "artifact_type", "scope", "source_snapshot",
                 "selected_primary", "metric_contract", "ablations",
                 "artifact_references", "paired_join_contract", "manual_override",
                 "primary_selection_recomputed", "p6_9_artifacts_modified",
                 "p6_10a_artifacts_modified", "p6_10_complete", "gate_b_ready",
                 "human_approval_required", "interpretation_limits"}
require_fields(report, report_fields, "contract-closure report")
if report["schema_version"] != "phase6-p6-10b-contract-closure-report-v1" \
        or report["artifact_type"] != "p6_10b_contract_closure_report" \
        or report["scope"] != "p6_10b_confidence_provider_ablation" \
        or report["source_snapshot"] != root["source_snapshot"] \
        or report["selected_primary"] != batch["selected_primary"] \
        or report["metric_contract"] != expected_metric_contract \
        or report["artifact_references"] != refs[1:-1]:
    raise ValueError("independent report binding mismatch")
for flag in ("manual_override", "primary_selection_recomputed", "p6_9_artifacts_modified",
             "p6_10a_artifacts_modified", "p6_10_complete", "gate_b_ready"):
    if report[flag] is not False:
        raise ValueError("independent report false flag mismatch")
if report["human_approval_required"] is not True:
    raise ValueError("independent report human stop mismatch")
if report["paired_join_contract"] != {
        "coordinates": ["opponent_id", "horizon", "repetition_id"],
        "cell_count_per_ablation": 810,
        "atomic_group_count_per_ablation": 27,
        "series_pooling": False} \
        or report["interpretation_limits"] != [
            "fixed-nine-opponent-validation-snapshot-only",
            "no-test-generalization", "no-primary-selection-change",
            "no-p6-10-completion-or-gate-b-readiness-claim"]:
    raise ValueError("independent report join/interpretation contract mismatch")
primary_source = source_records(repo_root, root,
    ("validation_exact_ev_cells", "validation_calibration_cells",
     "validation_aggregate_metrics"), approved_sources)
primary_id = batch["selected_primary"]["candidate_id"]
primary_exact = [item for item in primary_source["validation_exact_ev_cells"]
                 if item["candidate_id"] == primary_id]
primary_calibration_records = [item for item in primary_source["validation_calibration_cells"]
                               if item["candidate_id"] == primary_id]
primary_aggregate_records = [item for item in primary_source["validation_aggregate_metrics"]
                             if item["candidate_id"] == primary_id]
if len(primary_exact) != 810 or len(primary_calibration_records) != 1 \
        or len(primary_aggregate_records) != 1:
    raise ValueError("independent selected-primary source cardinality mismatch")
primary_calibration = primary_calibration_records[0]["payload"]["result"]
primary_aggregate = primary_aggregate_records[0]["payload"]["result"]
primary_truth = {(cell["key"][1], cell["key"][4], cell["key"][5]): {
    "key_tail": cell["key"][1:5], "q": cell["q"], "true_rate": cell["true_rate"],
    "reach_weight": cell["reach_weight"],
    "structurally_eligible": cell["structurally_eligible"], "label": cell["label"],
    "exclusion_status": cell["exclusion_status"]}
    for cell in primary_calibration["cells"]}
confidence_truth = {}
for cell in calibration_by_ablation["abl_confidence_mvp__v1"]["cells"]:
    coordinate = (cell["key"][1], cell["key"][4], cell["key"][5])
    confidence_truth[coordinate] = {
        "key_tail": cell["key"][1:5], "q": cell["q"],
        "true_rate": cell["true_rate"], "reach_weight": cell["reach_weight"],
        "structurally_eligible": cell["structurally_eligible"], "label": cell["label"],
        "exclusion_status": cell["exclusion_status"]}
if len(primary_truth) != 810 or confidence_truth != primary_truth:
    raise ValueError("independent confidence ground-truth join mismatch")
primary_brier_groups = {}
for cell in primary_calibration["cells"]:
    if cell["label"] is not None:
        with localcontext() as context:
            context.prec = 50
            context.rounding = ROUND_HALF_EVEN
            component = (Decimal(cell["confidence"]) - Decimal(cell["label"])) ** 2
        if cell["brier_component"] != decimal_token(component):
            raise ValueError("independent primary Brier component mismatch")
        primary_brier_groups.setdefault((cell["key"][1], cell["key"][4]), []).append(component)
primary_macro_brier = decimal_token(decimal_mean(
    [decimal_mean(values) for values in primary_brier_groups.values()]))
primary_efficiency_groups = {}
for item in primary_exact:
    coordinate = (item["opponent_id"], item["horizon"], item["repetition_id"])
    _values, efficiency = exact_values(item["payload"]["result"]["cell"],
        opponents[item["opponent_id"]], oop_combos, ip_combos)
    if efficiency is not None:
        primary_efficiency_groups.setdefault(coordinate[:2], []).append(
            Decimal.from_float(efficiency))
primary_macro_efficiency = decimal_token(decimal_mean(
    [decimal_mean(values) for values in primary_efficiency_groups.values()]))
if primary_aggregate["macro"]["brier"]["value"] != primary_macro_brier \
        or primary_aggregate["macro"]["mean_cell_efficiency"]["value"] \
        != primary_macro_efficiency:
    raise ValueError("independent primary estimand reconstruction mismatch")
require_exact([item.get("ablation_id") for item in report["ablations"]],
              list(ablation_order), "report ablation identity/order")
report_rows = {item["ablation_id"]: item for item in report["ablations"]}
for ablation_id, entry in configs.items():
    row = report_rows[ablation_id]
    require_fields(row, {"ablation_id", "candidate_id", "config_sha256", "series_id",
                         "status", "intervention", "cardinality", "primary_estimand",
                         "secondary_metrics", "paired_exact_ev_delta",
                         "interpretation_limits"}, "report ablation row")
    aggregate = aggregate_by_ablation[ablation_id]
    primary_value = (primary_macro_brier if ablation_id == "abl_confidence_mvp__v1"
                     else primary_macro_efficiency)
    ablation_value = (aggregate["macro"]["brier"]["value"]
                      if ablation_id == "abl_confidence_mvp__v1"
                      else aggregate["macro"]["mean_cell_efficiency"]["value"])
    estimand = ("delta_validation_macro_brier"
                if ablation_id == "abl_confidence_mvp__v1"
                else "delta_validation_macro_exploitation_efficiency")
    expected_estimand = {"name": estimand, "ablation_value": ablation_value,
                         "selected_primary_value": primary_value,
                         "delta": estimand_delta(ablation_value, primary_value),
                         "direction": "ablation_minus_selected_primary"}
    expected_limits = (["bounded-legacy-score-not-posterior-probability",
        "estimator-method-only-not-threshold-alpha-epsilon-or-floor",
        "fixed-nine-opponent-validation-snapshot-only", "no-test-generalization",
        "no-primary-selection-change"] if ablation_id == "abl_confidence_mvp__v1"
        else ["provider-only-not-detector-threshold-alpha-or-epsilon",
              "fixed-nine-opponent-validation-snapshot-only", "no-test-generalization",
              "no-primary-selection-change"])
    expected_row_cardinality = {"sessions": 810, "stream_root_references": 3240,
        "terminal_policy_exact_ev_records": 810, "calibration_cells": 810,
        "atomic_groups": 27}
    if row["ablation_id"] != ablation_id \
            or row["candidate_id"] != entry["candidate_id"] \
            or row["config_sha256"] != entry["config_sha256"] \
            or row["series_id"] != entry["series_id"] \
            or row["status"] != "completed_and_verified" \
            or row["intervention"] != entry["intervention"] \
            or row["cardinality"] != expected_row_cardinality \
            or row["interpretation_limits"] != expected_limits \
            or row["primary_estimand"] != expected_estimand \
            or row["secondary_metrics"] != {"micro": aggregate["micro"],
                "macro": aggregate["macro"], "gto_fpr": aggregate["gto_fpr"]} \
            or row["paired_exact_ev_delta"] != paired_delta(
                exact_by_ablation[ablation_id], primary_exact):
        raise ValueError("independent report row reconstruction mismatch")
primary_cells = [{**cell, "key": cell["key"][1:]}
                 for cell in primary_calibration["cells"]]
provider_cells = [{**cell, "key": cell["key"][1:]}
                  for cell in calibration_by_ablation["abl_provider_rule__v1"]["cells"]]
if provider_cells != primary_cells:
    raise ValueError("independent Rule-provider calibration invariance mismatch")
print(json.dumps({"status": "verified", "sessions": 1620,
                  "root_sha256": expected_root}, sort_keys=True, separators=(",", ":")))
"""


@dataclass(frozen=True, slots=True)
class P610BSnapshot:
    repo_root: Path
    p6_10a_run_path: Path
    p6_10a_run: dict[str, Any]
    p6_10a_result_path: Path
    p6_10a_result: dict[str, Any]
    p6_10a_artifacts: dict[str, dict[str, Any]]
    p6_10a_raw: dict[str, bytes]
    p69: P69Snapshot


@dataclass(frozen=True, slots=True)
class P610BAblationPlan:
    ablation_id: str
    config: dict[str, Any]
    config_sha256: str
    candidate: PrimaryCandidate
    series_id: str


@dataclass(frozen=True, slots=True)
class P610BBatchPlan:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    manifest_sha256: str
    ablations: tuple[P610BAblationPlan, ...]
    sessions: tuple[ValidationSessionKey, ...]


@dataclass(frozen=True, slots=True)
class P610BResultBundle:
    root: Path
    root_manifest_path: Path
    root_manifest_sha256: str
    report_path: Path


def _metric_contract() -> dict[str, object]:
    return {
        ABL_CONFIDENCE_MVP_ID: {
            "primary": "macro.brier",
            "delta": "ablation_minus_selected_primary",
            "final_ev": "secondary",
        },
        ABL_PROVIDER_RULE_ID: {
            "primary": "macro.mean_cell_efficiency",
            "delta": "ablation_minus_selected_primary",
            "final_ev": "secondary",
            "calibration_invariance": True,
        },
    }


def load_p6_10a_snapshot(run_manifest_path: Path | str, *, repo_root: Path | str) -> P610BSnapshot:
    """Load and reverify only the approved P6-10A/P6-9 source snapshot."""
    repository_root = Path(repo_root).resolve()
    run_path = Path(run_manifest_path).resolve()
    run_raw = run_path.read_bytes()
    if sha256_bytes(run_raw) != P6_10A_RUN_SHA256:
        raise ValueError("P6-10A run manifest hash differs from the approved snapshot")
    run, p69 = _run_pinned_p6_10a_verifier(run_path, repo_root=repository_root)
    inputs = _closed_object(
        run.get("inputs"),
        {
            "freeze_manifest",
            "freeze_hash_sidecar",
            "dependency_lock",
            "p6_10a_batch_manifest",
            "source_snapshot",
        },
        "P6-10A inputs",
    )
    if inputs["p6_10a_batch_manifest"].get("sha256") != P6_10A_BATCH_SHA256:
        raise ValueError("P6-10A batch hash differs from the approved snapshot")
    source = inputs["source_snapshot"]
    expected_p69_path = _safe_repo_relative(repository_root, source["p6_9_run_manifest"]["path"])
    if p69.run_manifest_path != expected_p69_path:
        raise ValueError("P6-10A verifier returned a different P6-9 source path")
    outputs = _closed_object(run.get("outputs"), {"p6_10a_result_root"}, "P6-10A outputs")
    result_ref = outputs["p6_10a_result_root"]
    if result_ref.get("sha256") != P6_10A_RESULT_ROOT_SHA256:
        raise ValueError("P6-10A result root hash differs from the approved snapshot")
    result_path = _safe_child(run_path.parent, result_ref["path"], "P6-10A result root")
    result_raw = result_path.read_bytes()
    if (
        len(result_raw) != result_ref["size_bytes"]
        or sha256_bytes(result_raw) != P6_10A_RESULT_ROOT_SHA256
    ):
        raise ValueError("P6-10A result root bytes differ from the approved snapshot")
    result = _strict_object(result_raw, "P6-10A result root")
    payloads: dict[str, dict[str, Any]] = {}
    raw_by_name: dict[str, bytes] = {}
    for value in result.get("artifacts", []):
        ref = _closed_object(value, {"name", "path", "sha256", "size_bytes"}, "P6-10A ref")
        path = _safe_child(result_path.parent, ref["path"], f"P6-10A {ref['name']}")
        raw = path.read_bytes()
        if len(raw) != ref["size_bytes"] or sha256_bytes(raw) != ref["sha256"]:
            raise ValueError("P6-10A artifact size/hash mismatch")
        payloads[ref["name"]] = _strict_object(raw, f"P6-10A {ref['name']}")
        raw_by_name[ref["name"]] = raw
    fixed = {
        "comparator_ablation_report": P6_10A_REPORT_SHA256,
        "gate_b_readiness_gap_packet": P6_10A_GAP_SHA256,
        "p6_10a_batch_manifest": P6_10A_BATCH_SHA256,
    }
    for name, digest in fixed.items():
        if name not in raw_by_name or sha256_bytes(raw_by_name[name]) != digest:
            raise ValueError(f"P6-10A {name} differs from the approved snapshot")
    return P610BSnapshot(
        repository_root,
        run_path,
        run,
        result_path,
        result,
        payloads,
        raw_by_name,
        p69,
    )


def build_p6_10b_batch(snapshot: P610BSnapshot) -> P610BBatchPlan:
    """Build the fixed two-ablation, 1,620-session atomic batch."""
    selected = snapshot.p69.selected_candidate
    validation_manifest = snapshot.p69.plan.manifest
    catalog = validation_manifest["validation_catalog_index"]
    catalog_sha256 = sha256_bytes(canonical_json_bytes(catalog))
    sampling_sha256 = validation_manifest["sampling_contract"]["sha256"]
    plans = []
    for ablation_id in _ABLATION_IDS:
        intervention = (
            {
                "leak_confidence_estimator": {
                    "from": "beta-binomial-upper-tail-v1",
                    "to": "mvp-confidence-heuristic-v1",
                }
            }
            if ablation_id == ABL_CONFIDENCE_MVP_ID
            else {
                "exploit_provider": {
                    "from": "nodelock-provider-r008-v2",
                    "to": "rule-exploit-provider-r008-v1",
                }
            }
        )
        estimator = {
            "method_version": (
                "mvp-confidence-heuristic-v1"
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else "beta-binomial-upper-tail-v1"
            ),
            "confidence_value_semantics": (
                "bounded_legacy_score_not_probability"
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else "posterior_probability"
            ),
            "dpl_semantic_version": ("1.0.0" if ablation_id == ABL_CONFIDENCE_MVP_ID else "2.0.0"),
            "legacy_arithmetic": (
                "historical-binary64-with-hex-and-exact-decimal"
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else None
            ),
        }
        provider = {
            "provider_version": (
                "nodelock-provider-r008-v2"
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else "rule-exploit-provider-r008-v1"
            ),
            "min_confidence": selected.provider_confidence,
            "min_ev_delta": "0",
            "max_call_probability_shift": "0.5",
            "supported_reason": "LEAK_R008",
            "solver_result_id": None,
        }
        action_ev = {
            "version": (
                "nodelock-solver-action-policy-v2"
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else "equilibrium-counterfactual-action-value-v1"
            ),
            "counterfactual_reach": (
                None
                if ablation_id == ABL_CONFIDENCE_MVP_ID
                else "chance_probability_x_frozen_equilibrium_ip_probability"
            ),
            "hero_reach_included": False,
            "zero_counterfactual_reach": "hard_failure",
        }
        config = {
            "schema_version": P6_10B_CONFIG_SCHEMA_VERSION,
            "ablation_id": ablation_id,
            "source_primary_candidate_id": selected.candidate_id,
            "source_primary_config_sha256": P6_9_SELECTED_CONFIG_SHA256,
            "source_primary_series_id": _selected_primary_series_id(snapshot),
            "intervention": intervention,
            "retained_primary_config": selected.canonical_payload(),
            "estimator_contract": estimator,
            "provider_contract": provider,
            "action_ev_contract": action_ev,
            "sampling_contract_sha256": sampling_sha256,
            "opponent_catalog_sha256": catalog_sha256,
            "horizon_set": list(HORIZONS),
            "repetition_set": [item[0] for item in REPETITION_SEEDS],
            "evaluator_versions": {
                "calibration": "all-candidate-calibration-v1",
                "exact_ev": "p6-5-exact-ev-cell-v2",
            },
            "decimal_contract": {
                "precision": 50,
                "rounding": "ROUND_HALF_EVEN",
                "wire": "finite-fixed-point-canonical",
            },
            "manual_override": False,
            "primary_selection_recomputed": False,
        }
        config_hash = sha256_bytes(canonical_json_bytes(config))
        candidate = PrimaryCandidate(
            f"{ablation_id}__{config_hash}",
            selected.epsilon,
            selected.sample_floor,
            selected.detector_confidence,
            selected.provider_confidence,
            selected.safety_alpha,
            selected.sampling_contract_sha256,
        )
        series_id = sha256_bytes(
            canonical_json_bytes(
                {
                    "config": config,
                    "opponents": catalog["opponents"],
                    "candidate_dimensions": [
                        {
                            "rule_id": "LEAK_R008",
                            "situation_key": "river_vs_check",
                            "action_group": ["BET"],
                            "tau": "0.25",
                        }
                    ],
                }
            )
        )
        plans.append(P610BAblationPlan(ablation_id, config, config_hash, candidate, series_id))
    plans_tuple = tuple(plans)
    coordinates = sorted(
        {
            (key.opponent_id, key.horizon, key.repetition_id)
            for key in snapshot.p69.plan.sessions
            if key.candidate_id == selected.candidate_id
        }
    )
    sessions = tuple(
        ValidationSessionKey(plan.candidate.candidate_id, opponent_id, horizon, repetition_id)
        for plan in plans_tuple
        for opponent_id, horizon, repetition_id in coordinates
    )
    roots = []
    for opponent_id, horizon, repetition_id in coordinates:
        for stream_name in STREAM_NAMES:
            root = derive_stream_root(
                split="validation",
                opponent_id=opponent_id,
                horizon=horizon,
                repetition_id=repetition_id,
                stream_name=stream_name,
            )
            roots.append({"payload": root.payload, "digest": root.digest})
    manifest = {
        "schema_version": P6_10B_BATCH_SCHEMA_VERSION,
        "artifact_type": "p6_10b_batch_manifest",
        "scope": "p6_10b_confidence_provider_ablation",
        "source_snapshot": _source_snapshot(snapshot),
        "selected_primary": {
            "candidate_id": selected.candidate_id,
            "config_sha256": P6_9_SELECTED_CONFIG_SHA256,
            "series_id": _selected_primary_series_id(snapshot),
            "manual_override": False,
        },
        "ablation_configs": [_ablation_projection(item) for item in plans_tuple],
        "sampling_contract": validation_manifest["sampling_contract"],
        "opponent_catalog": catalog,
        "horizons": list(HORIZONS),
        "repetitions": [
            {"repetition_id": repetition_id, "master_seed": seed}
            for repetition_id, seed in REPETITION_SEEDS
        ],
        "sessions": [key.canonical_payload() for key in sessions],
        "stream_roots": roots,
        "stream_root_reference_count": 6480,
        "expected_cardinality": dict(_EXPECTED_CARDINALITY),
        "metric_contract": _metric_contract(),
        "series_non_pooling": True,
        "manual_override": False,
        "primary_selection_recomputed": False,
    }
    raw = canonical_json_bytes(manifest)
    batch = P610BBatchPlan(manifest, raw, sha256_bytes(raw), plans_tuple, sessions)
    verify_p6_10b_batch(batch, snapshot=snapshot)
    return batch


def verify_p6_10b_batch(batch: P610BBatchPlan, *, snapshot: P610BSnapshot) -> None:
    """Fail closed on config, intervention, product, and source drift."""
    if not isinstance(batch, P610BBatchPlan):
        raise TypeError("P6-10B batch verifier requires P610BBatchPlan")
    if (
        canonical_json_bytes(batch.manifest) != batch.manifest_bytes
        or sha256_bytes(batch.manifest_bytes) != batch.manifest_sha256
    ):
        raise ValueError("P6-10B batch bytes/hash are not canonical")
    manifest = batch.manifest
    required = {
        "schema_version",
        "artifact_type",
        "scope",
        "source_snapshot",
        "selected_primary",
        "ablation_configs",
        "sampling_contract",
        "opponent_catalog",
        "horizons",
        "repetitions",
        "sessions",
        "stream_roots",
        "stream_root_reference_count",
        "expected_cardinality",
        "metric_contract",
        "series_non_pooling",
        "manual_override",
        "primary_selection_recomputed",
    }
    if (
        set(manifest) != required
        or manifest["schema_version"] != P6_10B_BATCH_SCHEMA_VERSION
        or manifest["artifact_type"] != "p6_10b_batch_manifest"
        or manifest["scope"] != "p6_10b_confidence_provider_ablation"
    ):
        raise ValueError("P6-10B batch identity is invalid")
    if manifest["source_snapshot"] != _source_snapshot(snapshot):
        raise ValueError("P6-10B source snapshot drifted")
    if (
        manifest["expected_cardinality"] != _EXPECTED_CARDINALITY
        or manifest["stream_root_reference_count"] != 6480
    ):
        raise ValueError("P6-10B batch cardinality is invalid")
    if (
        manifest["series_non_pooling"] is not True
        or manifest["manual_override"] is not False
        or manifest["primary_selection_recomputed"] is not False
    ):
        raise ValueError("P6-10B non-pooling/selection flags are invalid")
    if (
        len(batch.ablations) != 2
        or tuple(item.ablation_id for item in batch.ablations) != _ABLATION_IDS
    ):
        raise ValueError("P6-10B requires the two canonical ablations")
    if manifest["ablation_configs"] != [_ablation_projection(item) for item in batch.ablations]:
        raise ValueError("P6-10B ablation config projections do not join")
    if (
        len({item.config_sha256 for item in batch.ablations}) != 2
        or len({item.series_id for item in batch.ablations}) != 2
    ):
        raise ValueError("P6-10B configs/series must remain distinct")
    selected = snapshot.p69.selected_candidate
    if (
        len({_selected_primary_series_id(snapshot), *(item.series_id for item in batch.ablations)})
        != 3
    ):
        raise ValueError("P6-10B primary/ablation series IDs must remain distinct")
    validation_manifest = snapshot.p69.plan.manifest
    catalog = validation_manifest["validation_catalog_index"]
    sampling = validation_manifest["sampling_contract"]
    expected_selected = {
        "candidate_id": selected.candidate_id,
        "config_sha256": P6_9_SELECTED_CONFIG_SHA256,
        "series_id": _selected_primary_series_id(snapshot),
        "manual_override": False,
    }
    expected_repetitions = [
        {"repetition_id": repetition_id, "master_seed": seed}
        for repetition_id, seed in REPETITION_SEEDS
    ]
    if (
        manifest["selected_primary"] != expected_selected
        or manifest["sampling_contract"] != sampling
        or manifest["opponent_catalog"] != catalog
        or manifest["horizons"] != list(HORIZONS)
        or manifest["repetitions"] != expected_repetitions
        or manifest["metric_contract"] != _metric_contract()
    ):
        raise ValueError("P6-10B retained source contract drifted")
    config_fields = {
        "schema_version",
        "ablation_id",
        "source_primary_candidate_id",
        "source_primary_config_sha256",
        "source_primary_series_id",
        "intervention",
        "retained_primary_config",
        "estimator_contract",
        "provider_contract",
        "action_ev_contract",
        "sampling_contract_sha256",
        "opponent_catalog_sha256",
        "horizon_set",
        "repetition_set",
        "evaluator_versions",
        "decimal_contract",
        "manual_override",
        "primary_selection_recomputed",
    }
    for item in batch.ablations:
        confidence_ablation = item.ablation_id == ABL_CONFIDENCE_MVP_ID
        expected_intervention = (
            {
                "leak_confidence_estimator": {
                    "from": "beta-binomial-upper-tail-v1",
                    "to": "mvp-confidence-heuristic-v1",
                }
            }
            if confidence_ablation
            else {
                "exploit_provider": {
                    "from": "nodelock-provider-r008-v2",
                    "to": "rule-exploit-provider-r008-v1",
                }
            }
        )
        expected_estimator = {
            "method_version": (
                "mvp-confidence-heuristic-v1"
                if confidence_ablation
                else "beta-binomial-upper-tail-v1"
            ),
            "confidence_value_semantics": (
                "bounded_legacy_score_not_probability"
                if confidence_ablation
                else "posterior_probability"
            ),
            "dpl_semantic_version": "1.0.0" if confidence_ablation else "2.0.0",
            "legacy_arithmetic": (
                "historical-binary64-with-hex-and-exact-decimal" if confidence_ablation else None
            ),
        }
        expected_provider = {
            "provider_version": (
                "nodelock-provider-r008-v2"
                if confidence_ablation
                else "rule-exploit-provider-r008-v1"
            ),
            "min_confidence": selected.provider_confidence,
            "min_ev_delta": "0",
            "max_call_probability_shift": "0.5",
            "supported_reason": "LEAK_R008",
            "solver_result_id": None,
        }
        expected_action_ev = {
            "version": (
                "nodelock-solver-action-policy-v2"
                if confidence_ablation
                else "equilibrium-counterfactual-action-value-v1"
            ),
            "counterfactual_reach": (
                None
                if confidence_ablation
                else "chance_probability_x_frozen_equilibrium_ip_probability"
            ),
            "hero_reach_included": False,
            "zero_counterfactual_reach": "hard_failure",
        }
        config = item.config
        retained = item.config["retained_primary_config"]
        if (
            set(config) != config_fields
            or config["schema_version"] != P6_10B_CONFIG_SCHEMA_VERSION
            or config["ablation_id"] != item.ablation_id
            or config["source_primary_candidate_id"] != selected.candidate_id
            or config["source_primary_config_sha256"] != P6_9_SELECTED_CONFIG_SHA256
            or config["source_primary_series_id"] != _selected_primary_series_id(snapshot)
            or config["intervention"] != expected_intervention
            or config["estimator_contract"] != expected_estimator
            or config["provider_contract"] != expected_provider
            or config["action_ev_contract"] != expected_action_ev
            or config["sampling_contract_sha256"] != sampling["sha256"]
            or config["opponent_catalog_sha256"] != sha256_bytes(canonical_json_bytes(catalog))
            or config["horizon_set"] != list(HORIZONS)
            or config["repetition_set"] != [item[0] for item in REPETITION_SEEDS]
            or config["evaluator_versions"]
            != {"calibration": "all-candidate-calibration-v1", "exact_ev": "p6-5-exact-ev-cell-v2"}
            or config["decimal_contract"]
            != {
                "precision": 50,
                "rounding": "ROUND_HALF_EVEN",
                "wire": "finite-fixed-point-canonical",
            }
            or config["manual_override"] is not False
            or config["primary_selection_recomputed"] is not False
            or retained != snapshot.p69.selected_candidate.canonical_payload()
            or retained["detector_confidence"] != "0.9"
            or retained["provider_confidence"] != "0.9"
        ):
            raise ValueError("P6-10B ablation config differs from the closed-world contract")
        expected_config_hash = sha256_bytes(canonical_json_bytes(config))
        expected_series_id = sha256_bytes(
            canonical_json_bytes(
                {
                    "config": config,
                    "opponents": catalog["opponents"],
                    "candidate_dimensions": [
                        {
                            "rule_id": "LEAK_R008",
                            "situation_key": "river_vs_check",
                            "action_group": ["BET"],
                            "tau": "0.25",
                        }
                    ],
                }
            )
        )
        if (
            item.config_sha256 != expected_config_hash
            or item.candidate.candidate_id != f"{item.ablation_id}__{expected_config_hash}"
            or item.candidate.canonical_payload() != retained
            or item.series_id != expected_series_id
        ):
            raise ValueError("P6-10B config/candidate/series hash binding mismatch")
    coordinates = sorted(
        {
            (key.opponent_id, key.horizon, key.repetition_id)
            for key in snapshot.p69.plan.sessions
            if key.candidate_id == selected.candidate_id
        }
    )
    expected_sessions = tuple(
        ValidationSessionKey(plan.candidate.candidate_id, opponent_id, horizon, repetition_id)
        for plan in batch.ablations
        for opponent_id, horizon, repetition_id in coordinates
    )
    if batch.sessions != expected_sessions or manifest["sessions"] != [
        key.canonical_payload() for key in expected_sessions
    ]:
        raise ValueError("P6-10B session product is invalid")
    expected_roots = []
    for opponent_id, horizon, repetition_id in coordinates:
        for stream_name in STREAM_NAMES:
            root = derive_stream_root(
                split="validation",
                opponent_id=opponent_id,
                horizon=horizon,
                repetition_id=repetition_id,
                stream_name=stream_name,
            )
            expected_roots.append({"payload": root.payload, "digest": root.digest})
    if manifest["stream_roots"] != expected_roots:
        raise ValueError("P6-10B stream roots are invalid")


def execute_p6_10b(
    snapshot: P610BSnapshot,
    batch: P610BBatchPlan,
    result_root: Path | str,
    *,
    repo_root: Path | str,
) -> P610BResultBundle:
    """Execute both ablations and save them as one all-or-nothing result tree."""
    verify_p6_10b_batch(batch, snapshot=snapshot)
    root = Path(result_root).resolve()
    if root.name != P6_10B_PHYSICAL_DIRECTORY or root.parent.name != P6_10B_ARTIFACT_DIRECTORY:
        raise ValueError("P6-10B result root has a noncanonical namespace")
    root.mkdir(parents=False, exist_ok=False)
    by_id = {item.ablation_id: item for item in batch.ablations}
    confidence = by_id[ABL_CONFIDENCE_MVP_ID]
    provider = by_id[ABL_PROVIDER_RULE_ID]
    backend = P610BValidationExecutionBackend(
        snapshot.p69.plan,
        repo_root=repo_root,
        confidence_candidate=confidence.candidate,
        provider_candidate=provider.candidate,
    )
    records_by_ablation: dict[str, dict[str, tuple[ValidationArtifactRecord, ...]]] = {}
    records_by_ablation[ABL_CONFIDENCE_MVP_ID] = run_p6_10b_candidate_execution(
        snapshot.p69.plan,
        confidence.candidate,
        backend,
        repo_root=repo_root,
        p6_10b_series_id=confidence.series_id,
        confidence_values=lambda key: _confidence_value_from_backend(backend, key),
    )
    records_by_ablation[ABL_PROVIDER_RULE_ID] = run_p6_10b_candidate_execution(
        snapshot.p69.plan,
        provider.candidate,
        backend,
        repo_root=repo_root,
        p6_10b_series_id=provider.series_id,
    )
    payloads: dict[str, bytes] = {}
    for plan in batch.ablations:
        records = records_by_ablation[plan.ablation_id]
        for standard_type, suffix in zip(_STANDARD_TYPES, _TYPE_SUFFIXES, strict=True):
            name = f"{plan.ablation_id}__{suffix}"
            rows = []
            for record in records[standard_type]:
                row: dict[str, object] = {"record": record.canonical_payload()}
                if standard_type == "validation_terminal_candidate_snapshots":
                    key = record.session_key()
                    row["execution_events"] = list(backend.execution_events(key))
                    row["action_draw_audits"] = list(backend.action_draw_audits(key))
                    row["ablation_evidence"] = backend.ablation_evidence(key)
                elif standard_type == "validation_hero_policy_snapshots":
                    row["ablation_evidence"] = backend.ablation_evidence(record.session_key())
                rows.append(row)
            payloads[name] = canonical_json_bytes(
                {
                    "schema_version": P6_10B_ARTIFACT_SCHEMA_VERSION,
                    "artifact_type": name,
                    "status": "completed_and_verified",
                    "ablation_id": plan.ablation_id,
                    "p6_10b_batch_manifest_sha256": batch.manifest_sha256,
                    "p6_10a_result_root_sha256": P6_10A_RESULT_ROOT_SHA256,
                    "source_validation_batch_manifest_sha256": P6_9_VALIDATION_BATCH_SHA256,
                    "candidate_id": plan.candidate.candidate_id,
                    "config_sha256": plan.config_sha256,
                    "series_id": plan.series_id,
                    "series_pooling": False,
                    "records": rows,
                }
            )
    artifact_refs = _write_payloads_exclusive(root, payloads)
    report = _build_report(snapshot, batch, records_by_ablation, artifact_refs)
    report_raw = canonical_json_bytes(report)
    report_path = root / P6_10B_REPORT
    _write_exclusive(report_path, report_raw)
    report_ref = _reference("p6_10b_contract_closure_report", P6_10B_REPORT, report_raw)
    batch_path = root / P6_10B_BATCH_MANIFEST
    _write_exclusive(batch_path, batch.manifest_bytes)
    batch_ref = _reference("p6_10b_batch_manifest", P6_10B_BATCH_MANIFEST, batch.manifest_bytes)
    result = {
        "schema_version": P6_10B_RESULT_ROOT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_result_root",
        "scope": "p6_10b_confidence_provider_ablation",
        "physical_directory": P6_10B_PHYSICAL_DIRECTORY,
        "source_snapshot": _source_snapshot(snapshot),
        "p6_10b_batch_manifest_sha256": batch.manifest_sha256,
        "expected_cardinality": dict(_EXPECTED_CARDINALITY),
        "manual_override": False,
        "series_pooling": False,
        "primary_selection_recomputed": False,
        "p6_9_artifacts_modified": False,
        "p6_10a_artifacts_modified": False,
        "p6_10_complete": False,
        "gate_b_ready": False,
        "human_approval_required": True,
        "artifacts": [batch_ref, *artifact_refs, report_ref],
    }
    root_raw = canonical_json_bytes(result)
    root_path = root / P6_10B_RESULT_ROOT
    _write_exclusive(root_path, root_raw)
    digest = sha256_bytes(root_raw)
    verify_p6_10b_result_root(
        root_path,
        expected_sha256=digest,
        repo_root=repo_root,
        snapshot=snapshot,
    )
    return P610BResultBundle(root, root_path, digest, report_path)


def verify_p6_10b_result_root(
    root_manifest_path: Path | str,
    *,
    expected_sha256: str,
    repo_root: Path | str,
    snapshot: P610BSnapshot | None = None,
) -> dict[str, Any]:
    """Rehash and reconstruct the P6-10B batch, records, metrics, and report."""
    _validate_sha256(expected_sha256, "P6-10B result root hash")
    repository_root = Path(repo_root).resolve()
    path = Path(root_manifest_path).resolve()
    root = path.parent
    if (
        path.name != P6_10B_RESULT_ROOT
        or root.name != P6_10B_PHYSICAL_DIRECTORY
        or root.parent.name != P6_10B_ARTIFACT_DIRECTORY
    ):
        raise ValueError("P6-10B result root path is noncanonical")
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("P6-10B result root hash mismatch")
    payload = _strict_object(raw, "P6-10B result root")
    fields = {
        "schema_version",
        "artifact_type",
        "scope",
        "physical_directory",
        "source_snapshot",
        "p6_10b_batch_manifest_sha256",
        "expected_cardinality",
        "manual_override",
        "series_pooling",
        "primary_selection_recomputed",
        "p6_9_artifacts_modified",
        "p6_10a_artifacts_modified",
        "p6_10_complete",
        "gate_b_ready",
        "human_approval_required",
        "artifacts",
    }
    if (
        set(payload) != fields
        or payload["schema_version"] != P6_10B_RESULT_ROOT_SCHEMA_VERSION
        or payload["artifact_type"] != "p6_10b_result_root"
        or payload["scope"] != "p6_10b_confidence_provider_ablation"
        or payload["physical_directory"] != P6_10B_PHYSICAL_DIRECTORY
        or payload["expected_cardinality"] != _EXPECTED_CARDINALITY
    ):
        raise ValueError("P6-10B result root identity is invalid")
    false_flags = (
        "manual_override",
        "series_pooling",
        "primary_selection_recomputed",
        "p6_9_artifacts_modified",
        "p6_10a_artifacts_modified",
        "p6_10_complete",
        "gate_b_ready",
    )
    if (
        any(payload[name] is not False for name in false_flags)
        or payload["human_approval_required"] is not True
    ):
        raise ValueError("P6-10B result stop/immutability flags are invalid")
    if snapshot is None:
        run_path = _safe_repo_relative(
            repository_root,
            payload["source_snapshot"]["p6_10a_run_manifest"]["path"],
        )
        snapshot = load_p6_10a_snapshot(run_path, repo_root=repository_root)
    if payload["source_snapshot"] != _source_snapshot(snapshot):
        raise ValueError("P6-10B result source snapshot mismatch")
    refs = payload["artifacts"]
    expected_names = [
        "p6_10b_batch_manifest",
        *[f"{ablation_id}__{suffix}" for ablation_id in _ABLATION_IDS for suffix in _TYPE_SUFFIXES],
        "p6_10b_contract_closure_report",
    ]
    if not isinstance(refs, list) or [item.get("name") for item in refs] != expected_names:
        raise ValueError("P6-10B result artifact set/order is invalid")
    expected_paths = {
        "p6_10b_batch_manifest": P6_10B_BATCH_MANIFEST,
        "p6_10b_contract_closure_report": P6_10B_REPORT,
        **{name: f"{name}.json" for name in expected_names[1:-1]},
    }
    if [item.get("path") for item in refs] != [expected_paths[name] for name in expected_names]:
        raise ValueError("P6-10B result artifact name/path mapping is invalid")
    expected_files = {P6_10B_RESULT_ROOT, P6_10B_BATCH_MANIFEST, P6_10B_REPORT} | {
        f"{name}.json" for name in expected_names[1:-1]
    }
    if {item.name for item in root.iterdir()} != expected_files or any(
        not item.is_file() for item in root.iterdir()
    ):
        raise ValueError("P6-10B result directory is not closed-world")
    if {item.name for item in root.parent.iterdir()} != {P6_10B_PHYSICAL_DIRECTORY} or any(
        not item.is_dir() for item in root.parent.iterdir()
    ):
        raise ValueError("P6-10B artifact parent is not closed-world")
    payloads: dict[str, dict[str, Any]] = {}
    raw_by_name: dict[str, bytes] = {}
    for value in refs:
        ref = _closed_object(value, {"name", "path", "sha256", "size_bytes"}, "P6-10B ref")
        artifact_path = _safe_child(root, ref["path"], f"P6-10B {ref['name']}")
        artifact_raw = artifact_path.read_bytes()
        if len(artifact_raw) != ref["size_bytes"] or sha256_bytes(artifact_raw) != ref["sha256"]:
            raise ValueError("P6-10B artifact size/hash mismatch")
        payloads[ref["name"]] = _strict_object(artifact_raw, f"P6-10B {ref['name']}")
        raw_by_name[ref["name"]] = artifact_raw
    batch_payload = payloads["p6_10b_batch_manifest"]
    batch = _batch_from_payload(batch_payload, raw_by_name["p6_10b_batch_manifest"])
    if batch.manifest_sha256 != payload["p6_10b_batch_manifest_sha256"]:
        raise ValueError("P6-10B result batch hash mismatch")
    verify_p6_10b_batch(batch, snapshot=snapshot)
    by_id = {item.ablation_id: item for item in batch.ablations}
    verification_backend = P610BValidationExecutionBackend(
        snapshot.p69.plan,
        repo_root=repository_root,
        confidence_candidate=by_id[ABL_CONFIDENCE_MVP_ID].candidate,
        provider_candidate=by_id[ABL_PROVIDER_RULE_ID].candidate,
    )
    records_by_ablation: dict[str, dict[str, tuple[ValidationArtifactRecord, ...]]] = {}
    for plan in batch.ablations:
        typed: dict[str, tuple[ValidationArtifactRecord, ...]] = {}
        confidence_values: dict[ValidationSessionKey, tuple[Decimal, bool]] = {}
        terminal_wrappers: dict[ValidationSessionKey, dict[str, object]] = {}
        policy_evidence: dict[ValidationSessionKey, object] = {}
        for standard_type, suffix in zip(_STANDARD_TYPES, _TYPE_SUFFIXES, strict=True):
            name = f"{plan.ablation_id}__{suffix}"
            artifact = payloads[name]
            envelope_fields = {
                "schema_version",
                "artifact_type",
                "status",
                "ablation_id",
                "p6_10b_batch_manifest_sha256",
                "p6_10a_result_root_sha256",
                "source_validation_batch_manifest_sha256",
                "candidate_id",
                "config_sha256",
                "series_id",
                "series_pooling",
                "records",
            }
            if (
                set(artifact) != envelope_fields
                or artifact["schema_version"] != P6_10B_ARTIFACT_SCHEMA_VERSION
                or artifact["artifact_type"] != name
                or artifact["status"] != "completed_and_verified"
                or artifact["ablation_id"] != plan.ablation_id
                or artifact["p6_10b_batch_manifest_sha256"] != batch.manifest_sha256
                or artifact["p6_10a_result_root_sha256"] != P6_10A_RESULT_ROOT_SHA256
                or artifact["source_validation_batch_manifest_sha256"]
                != P6_9_VALIDATION_BATCH_SHA256
                or artifact["candidate_id"] != plan.candidate.candidate_id
                or artifact["config_sha256"] != plan.config_sha256
                or artifact["series_id"] != plan.series_id
                or artifact["series_pooling"] is not False
            ):
                raise ValueError("P6-10B artifact envelope is invalid")
            rows = artifact["records"]
            expected_count = 810 if standard_type in _STANDARD_TYPES[:3] else 1
            if not isinstance(rows, list) or len(rows) != expected_count:
                raise ValueError("P6-10B artifact cardinality is invalid")
            parsed = tuple(_artifact_record(row["record"]) for row in rows)
            typed[standard_type] = parsed
            if standard_type == "validation_terminal_candidate_snapshots":
                for row, record in zip(rows, parsed, strict=True):
                    if set(row) != {
                        "record",
                        "execution_events",
                        "action_draw_audits",
                        "ablation_evidence",
                    }:
                        raise ValueError("P6-10B terminal wrapper is not closed-world")
                    evidence = row["ablation_evidence"]
                    if evidence.get("ablation_id") != plan.ablation_id:
                        raise ValueError("P6-10B terminal evidence identity mismatch")
                    terminal_wrappers[record.session_key()] = {
                        "execution_events": row["execution_events"],
                        "action_draw_audits": row["action_draw_audits"],
                        "ablation_evidence": evidence,
                    }
                    if plan.ablation_id == ABL_CONFIDENCE_MVP_ID:
                        score = {
                            "binary64_hex": evidence["score_binary64_hex"],
                            "exact_decimal": evidence["score_exact_decimal"],
                        }
                        _verify_binary64_evidence(score, "legacy confidence")
                        if evidence["confidence_value"] != evidence["score_exact_decimal"]:
                            raise ValueError("P6-10B confidence_value differs from legacy score")
                        confidence_values[record.session_key()] = (
                            Decimal(score["exact_decimal"]),
                            evidence["candidate_eligibility"]["emitted"],
                        )
            elif standard_type == "validation_hero_policy_snapshots":
                if any(set(row) != {"record", "ablation_evidence"} for row in rows):
                    raise ValueError("P6-10B policy wrapper is not closed-world")
                policy_evidence = {
                    record.session_key(): row["ablation_evidence"]
                    for row, record in zip(rows, parsed, strict=True)
                }
            elif any(set(row) != {"record"} for row in rows):
                raise ValueError("P6-10B record wrapper is not closed-world")
        replayed = run_p6_10b_candidate_execution(
            snapshot.p69.plan,
            plan.candidate,
            verification_backend,
            repo_root=repository_root,
            p6_10b_series_id=plan.series_id,
            confidence_values=(
                (lambda key: _confidence_value_from_backend(verification_backend, key))
                if plan.ablation_id == ABL_CONFIDENCE_MVP_ID
                else None
            ),
        )
        if typed != replayed:
            raise ValueError("P6-10B saved records differ from deterministic replay")
        expected_keys = tuple(record.session_key() for record in typed[_STANDARD_TYPES[0]])
        if set(terminal_wrappers) != set(expected_keys) or set(policy_evidence) != set(
            expected_keys
        ):
            raise ValueError("P6-10B evidence wrappers do not cover the session product")
        for key in expected_keys:
            expected_evidence = verification_backend.ablation_evidence(key)
            expected_wrapper = {
                "execution_events": list(verification_backend.execution_events(key)),
                "action_draw_audits": list(verification_backend.action_draw_audits(key)),
                "ablation_evidence": expected_evidence,
            }
            if (
                terminal_wrappers[key] != expected_wrapper
                or policy_evidence[key] != expected_evidence
            ):
                raise ValueError("P6-10B replay evidence differs from saved wrapper")
        records_by_ablation[plan.ablation_id] = typed
    expected_report = _build_report(snapshot, batch, records_by_ablation, refs[1:-1])
    if payloads["p6_10b_contract_closure_report"] != expected_report:
        raise ValueError("P6-10B report does not reconstruct")
    run_p6_10b_independent_verifier(
        path,
        expected_sha256=expected_sha256,
        repo_root=repository_root,
    )
    return payload


def run_p6_10b_independent_verifier(
    root_manifest_path: Path | str,
    *,
    expected_sha256: str,
    repo_root: Path | str,
) -> dict[str, Any]:
    """Verify saved bytes in an isolated stdlib-only subprocess."""
    _validate_sha256(expected_sha256, "P6-10B independent result root hash")
    command = (
        sys.executable,
        "-I",
        "-S",
        "-c",
        "import sys;exec(compile(sys.stdin.read(), '<p6-10b-independent>', 'exec'))",
        str(Path(root_manifest_path).resolve()),
        expected_sha256,
        str(Path(repo_root).resolve()),
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            input=_INDEPENDENT_VERIFIER_SOURCE,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("P6-10B independent verifier timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = "" if not detail else f": {detail[-1]}"
        raise ValueError(f"P6-10B independent verifier failed{suffix}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("P6-10B independent verifier returned invalid JSON") from exc
    expected = {
        "root_sha256": expected_sha256,
        "sessions": 1620,
        "status": "verified",
    }
    if result != expected:
        raise ValueError("P6-10B independent verifier returned a noncanonical result")
    return result


def run_p6_10b_from_freeze(
    freeze_manifest_path: Path | str,
    freeze_hash_sidecar_path: Path | str,
    *,
    repo_root: Path | str,
) -> Path:
    """Reserve and execute the single frozen production attempt."""
    from .p6_10b_freeze import verify_p6_10b_freeze_manifest

    repository_root = Path(repo_root).resolve()
    verified = verify_p6_10b_freeze_manifest(
        freeze_manifest_path, freeze_hash_sidecar_path, repo_root=repository_root
    )
    output_root = Path(verified["paths"]["output_root"]).resolve()
    if os.path.lexists(output_root):
        raise FileExistsError("P6-10B production output must remain fresh")
    output_root.mkdir(parents=False, exist_ok=False)
    marker = {
        "schema_version": P6_10B_ATTEMPT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_attempt_marker",
        "attempt_id": P6_10B_ATTEMPT_ID,
        "attempt_number": 1,
        "retry_count": 0,
        "status": "reserved_in_progress",
        "target_commit": verified["git"]["expected_target_commit"],
        "freeze_manifest_sha256": verified["manifest_sha256"],
        "p6_10b_batch_manifest_sha256": verified["p6_10b_batch_manifest"]["sha256"],
        "partial_retention": "preserve_without_cleanup",
    }
    marker_path = output_root / P6_10B_ATTEMPT_MARKER
    _write_exclusive(marker_path, canonical_json_bytes(marker))
    started = _utc_now()
    try:
        snapshot = load_p6_10a_snapshot(
            _safe_repo_relative(
                repository_root,
                verified["source_snapshot"]["p6_10a_run_manifest"]["path"],
            ),
            repo_root=repository_root,
        )
        batch_path = Path(verified["p6_10b_batch_manifest"]["path"])
        batch_raw = batch_path.read_bytes()
        batch = _batch_from_payload(_strict_object(batch_raw, "frozen P6-10B batch"), batch_raw)
        verify_p6_10b_batch(batch, snapshot=snapshot)
        result_parent = output_root / P6_10B_ARTIFACT_DIRECTORY
        result_parent.mkdir(exist_ok=False)
        bundle = execute_p6_10b(
            snapshot,
            batch,
            result_parent / P6_10B_PHYSICAL_DIRECTORY,
            repo_root=repository_root,
        )
        run = {
            "schema_version": P6_10B_RUN_SCHEMA_VERSION,
            "artifact_type": "phase6_p6_10b_run_manifest",
            "cli_version": P6_10B_CLI_VERSION,
            "status": "completed_and_verified",
            "scope": "p6_10b_confidence_provider_ablation",
            "git": verified["git"],
            "runtime": verified["runtime"],
            "timing": {"started_at_utc": started, "finished_at_utc": _utc_now()},
            "inputs": {
                "freeze_manifest": _absolute_reference(Path(freeze_manifest_path).resolve()),
                "freeze_hash_sidecar": _absolute_reference(
                    Path(freeze_hash_sidecar_path).resolve()
                ),
                "dependency_lock": verified["dependency_lock"],
                "p6_10b_batch_manifest": verified["p6_10b_batch_manifest"],
                "source_snapshot": verified["source_snapshot"],
            },
            "attempt": {
                "attempt_id": P6_10B_ATTEMPT_ID,
                "attempt_number": 1,
                "retry_count": 0,
                "marker": _relative_reference(output_root, marker_path),
            },
            "outputs": {
                "p6_10b_result_root": _relative_reference(output_root, bundle.root_manifest_path)
            },
            "p6_10_complete": False,
            "gate_b_ready": False,
            "human_approval_required": True,
        }
        run_path = output_root / P6_10B_RUN_MANIFEST
        _write_exclusive(run_path, canonical_json_bytes(run))
        verify_p6_10b_run_manifest(run_path, repo_root=repository_root)
        return run_path
    except BaseException as exc:
        failure_path = output_root / P6_10B_FAILURE_RECORD
        if not os.path.lexists(failure_path):
            observed = []
            for child in sorted(output_root.rglob("*")):
                if child.is_file() and child != failure_path:
                    observed.append(_relative_reference(output_root, child))
            failure = {
                "schema_version": P6_10B_FAILURE_SCHEMA_VERSION,
                "artifact_type": "p6_10b_failure_record",
                "attempt_id": P6_10B_ATTEMPT_ID,
                "attempt_number": 1,
                "retry_count": 0,
                "status": (
                    "failed_timeout"
                    if isinstance(exc, TimeoutError)
                    else "failed_verification"
                    if isinstance(exc, (ValueError, RuntimeError))
                    else "failed_nonzero"
                ),
                "failure_type": type(exc).__name__,
                "observed_files": observed,
                "partial_retention": "preserve_without_cleanup",
            }
            _write_exclusive(failure_path, canonical_json_bytes(failure))
        raise


def verify_p6_10b_run_manifest(
    manifest_path: Path | str, *, repo_root: Path | str
) -> dict[str, Any]:
    """Verify successful run, immutable marker, freeze, source, and result root."""
    from .p6_10b_freeze import verify_p6_10b_freeze_manifest

    repository_root = Path(repo_root).resolve()
    path = Path(manifest_path).resolve()
    if path.name != P6_10B_RUN_MANIFEST:
        raise ValueError("P6-10B run manifest name is noncanonical")
    payload = _strict_object(path.read_bytes(), "P6-10B run manifest")
    fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "scope",
        "git",
        "runtime",
        "timing",
        "inputs",
        "attempt",
        "outputs",
        "p6_10_complete",
        "gate_b_ready",
        "human_approval_required",
    }
    if (
        set(payload) != fields
        or payload["schema_version"] != P6_10B_RUN_SCHEMA_VERSION
        or payload["artifact_type"] != "phase6_p6_10b_run_manifest"
        or payload["cli_version"] != P6_10B_CLI_VERSION
        or payload["status"] != "completed_and_verified"
        or payload["scope"] != "p6_10b_confidence_provider_ablation"
    ):
        raise ValueError("P6-10B run manifest identity is invalid")
    if (
        payload["p6_10_complete"] is not False
        or payload["gate_b_ready"] is not False
        or payload["human_approval_required"] is not True
    ):
        raise ValueError("P6-10B run stop flags are invalid")
    timing = _closed_object(payload["timing"], {"started_at_utc", "finished_at_utc"}, "timing")
    if _parse_utc(timing["finished_at_utc"]) < _parse_utc(timing["started_at_utc"]):
        raise ValueError("P6-10B run finished before it started")
    inputs = _closed_object(
        payload["inputs"],
        {
            "freeze_manifest",
            "freeze_hash_sidecar",
            "dependency_lock",
            "p6_10b_batch_manifest",
            "source_snapshot",
        },
        "inputs",
    )
    freeze_path = Path(inputs["freeze_manifest"]["path"]).resolve()
    sidecar_path = Path(inputs["freeze_hash_sidecar"]["path"]).resolve()
    _verify_absolute_reference(inputs["freeze_manifest"], freeze_path, "freeze manifest")
    _verify_absolute_reference(inputs["freeze_hash_sidecar"], sidecar_path, "freeze sidecar")
    frozen = verify_p6_10b_freeze_manifest(
        freeze_path,
        sidecar_path,
        repo_root=repository_root,
        allow_existing_output=True,
    )
    frozen_output_root = Path(frozen["paths"]["output_root"]).resolve()
    if path.parent != frozen_output_root:
        raise ValueError("P6-10B run is outside the frozen canonical output root")
    if (
        payload["git"] != frozen["git"]
        or payload["runtime"] != frozen["runtime"]
        or inputs["dependency_lock"] != frozen["dependency_lock"]
        or inputs["p6_10b_batch_manifest"] != frozen["p6_10b_batch_manifest"]
        or inputs["source_snapshot"] != frozen["source_snapshot"]
    ):
        raise ValueError("P6-10B run differs from its freeze")
    attempt = _closed_object(
        payload["attempt"],
        {"attempt_id", "attempt_number", "retry_count", "marker"},
        "attempt",
    )
    if (
        attempt["attempt_id"] != P6_10B_ATTEMPT_ID
        or attempt["attempt_number"] != 1
        or attempt["retry_count"] != 0
    ):
        raise ValueError("P6-10B attempt identity is invalid")
    marker_path = _safe_child(path.parent, attempt["marker"]["path"], "attempt marker")
    _verify_relative_reference(path.parent, marker_path, attempt["marker"], "attempt marker")
    marker = _strict_object(marker_path.read_bytes(), "P6-10B attempt marker")
    expected_marker = {
        "schema_version": P6_10B_ATTEMPT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_attempt_marker",
        "attempt_id": P6_10B_ATTEMPT_ID,
        "attempt_number": 1,
        "retry_count": 0,
        "status": "reserved_in_progress",
        "target_commit": frozen["git"]["expected_target_commit"],
        "freeze_manifest_sha256": frozen["manifest_sha256"],
        "p6_10b_batch_manifest_sha256": frozen["p6_10b_batch_manifest"]["sha256"],
        "partial_retention": "preserve_without_cleanup",
    }
    if marker != expected_marker:
        raise ValueError("P6-10B attempt marker was mutated")
    outputs = _closed_object(payload["outputs"], {"p6_10b_result_root"}, "outputs")
    result_path = _safe_child(path.parent, outputs["p6_10b_result_root"]["path"], "result root")
    _verify_relative_reference(
        path.parent, result_path, outputs["p6_10b_result_root"], "result root"
    )
    result = verify_p6_10b_result_root(
        result_path,
        expected_sha256=outputs["p6_10b_result_root"]["sha256"],
        repo_root=repository_root,
    )
    if result["p6_10b_batch_manifest_sha256"] != frozen["p6_10b_batch_manifest"]["sha256"]:
        raise ValueError("P6-10B result batch differs from the frozen batch")
    allowed = {P6_10B_ATTEMPT_MARKER, P6_10B_RUN_MANIFEST, P6_10B_ARTIFACT_DIRECTORY}
    if {item.name for item in path.parent.iterdir()} != allowed:
        raise ValueError("P6-10B successful output namespace is not closed-world")
    return payload


def _build_report(
    snapshot: P610BSnapshot,
    batch: P610BBatchPlan,
    records_by_ablation: Mapping[str, Mapping[str, Sequence[ValidationArtifactRecord]]],
    artifact_refs: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    primary_aggregate_record = _selected_source_record(snapshot, "validation_aggregate_metrics")
    primary_calibration_record = _selected_source_record(snapshot, "validation_calibration_cells")
    primary_exact_records = _selected_source_records(snapshot, "validation_exact_ev_cells")
    rows = []
    for plan in batch.ablations:
        records = records_by_ablation[plan.ablation_id]
        aggregate = records["validation_aggregate_metrics"][0].payload["result"]
        if plan.ablation_id == ABL_CONFIDENCE_MVP_ID:
            metric_path = ("macro", "brier", "value")
            estimand = "delta_validation_macro_brier"
        else:
            _verify_provider_calibration_invariance(
                aggregate,
                primary_aggregate_record.payload["result"],
                records["validation_calibration_cells"][0].payload["result"],
                primary_calibration_record.payload["result"],
            )
            metric_path = ("macro", "mean_cell_efficiency", "value")
            estimand = "delta_validation_macro_exploitation_efficiency"
        ablation_value = _nested(aggregate, metric_path)
        primary_value = _nested(primary_aggregate_record.payload["result"], metric_path)
        delta = _decimal_difference(ablation_value, primary_value)
        exact_delta = _paired_final_ev_delta(
            records["validation_exact_ev_cells"], primary_exact_records
        )
        rows.append(
            {
                "ablation_id": plan.ablation_id,
                "candidate_id": plan.candidate.candidate_id,
                "config_sha256": plan.config_sha256,
                "series_id": plan.series_id,
                "status": "completed_and_verified",
                "intervention": plan.config["intervention"],
                "cardinality": {
                    "sessions": 810,
                    "stream_root_references": 3240,
                    "terminal_policy_exact_ev_records": 810,
                    "calibration_cells": 810,
                    "atomic_groups": 27,
                },
                "primary_estimand": {
                    "name": estimand,
                    "ablation_value": ablation_value,
                    "selected_primary_value": primary_value,
                    "delta": delta,
                    "direction": "ablation_minus_selected_primary",
                },
                "secondary_metrics": {
                    "micro": aggregate["micro"],
                    "macro": aggregate["macro"],
                    "gto_fpr": aggregate["gto_fpr"],
                },
                "paired_exact_ev_delta": exact_delta,
                "interpretation_limits": _interpretation_limits(plan.ablation_id),
            }
        )
    return {
        "schema_version": P6_10B_REPORT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_contract_closure_report",
        "scope": "p6_10b_confidence_provider_ablation",
        "source_snapshot": _source_snapshot(snapshot),
        "selected_primary": batch.manifest["selected_primary"],
        "metric_contract": batch.manifest["metric_contract"],
        "ablations": rows,
        "artifact_references": [dict(item) for item in artifact_refs],
        "paired_join_contract": {
            "coordinates": ["opponent_id", "horizon", "repetition_id"],
            "cell_count_per_ablation": 810,
            "atomic_group_count_per_ablation": 27,
            "series_pooling": False,
        },
        "manual_override": False,
        "primary_selection_recomputed": False,
        "p6_9_artifacts_modified": False,
        "p6_10a_artifacts_modified": False,
        "p6_10_complete": False,
        "gate_b_ready": False,
        "human_approval_required": True,
        "interpretation_limits": [
            "fixed-nine-opponent-validation-snapshot-only",
            "no-test-generalization",
            "no-primary-selection-change",
            "no-p6-10-completion-or-gate-b-readiness-claim",
        ],
    }


def _paired_final_ev_delta(
    ablation_records: Sequence[ValidationArtifactRecord],
    primary_records: Sequence[ValidationArtifactRecord],
) -> dict[str, object]:
    def key(record: ValidationArtifactRecord) -> tuple[str, int, str]:
        if record.opponent_id is None or record.horizon is None or record.repetition_id is None:
            raise ValueError("exact-EV record lacks session coordinates")
        return record.opponent_id, record.horizon, record.repetition_id

    primary = {key(record): record for record in primary_records}
    if len(primary) != 810 or len(ablation_records) != 810:
        raise ValueError("paired exact-EV delta requires 810 records per series")
    cells = []
    group_values: dict[tuple[str, int], list[Decimal]] = {}
    for record in ablation_records:
        coordinate = key(record)
        if coordinate not in primary:
            raise ValueError("ablation exact-EV coordinate does not join primary")
        ablation_hex = record.payload["result"]["cell"]["final_ev"]["production_binary64_hex"]
        primary_hex = primary[coordinate].payload["result"]["cell"]["final_ev"][
            "production_binary64_hex"
        ]
        delta = Decimal.from_float(float.fromhex(ablation_hex)) - Decimal.from_float(
            float.fromhex(primary_hex)
        )
        wire = _decimal_wire(delta)
        cells.append(
            {
                "opponent_id": coordinate[0],
                "horizon": coordinate[1],
                "repetition_id": coordinate[2],
                "delta": wire,
            }
        )
        group_values.setdefault((coordinate[0], coordinate[1]), []).append(delta)
    groups = [
        {
            "opponent_id": opponent_id,
            "horizon": horizon,
            "mean_delta": _decimal_wire(_mean(values)),
            "cell_count": len(values),
        }
        for (opponent_id, horizon), values in sorted(group_values.items())
    ]
    if len(groups) != 27 or any(item["cell_count"] != 30 for item in groups):
        raise ValueError("paired exact-EV groups are not the approved 27 x 30 product")
    return {
        "cells": cells,
        "groups": groups,
        "macro_mean_delta": _decimal_wire(_mean([Decimal(item["mean_delta"]) for item in groups])),
        "micro_mean_delta": _decimal_wire(_mean([Decimal(item["delta"]) for item in cells])),
    }


def _verify_provider_calibration_invariance(
    provider: Mapping[str, object],
    primary: Mapping[str, object],
    provider_calibration: Mapping[str, object],
    primary_calibration: Mapping[str, object],
) -> None:
    provider_cells = provider_calibration["cells"]
    primary_cells = primary_calibration["cells"]
    if not isinstance(provider_cells, list) or not isinstance(primary_cells, list):
        raise ValueError("Rule provider calibration cells are invalid")

    def invariant_cell(value: object) -> dict[str, object]:
        if not isinstance(value, dict) or not isinstance(value.get("key"), list):
            raise ValueError("Rule provider calibration cell is invalid")
        return {**value, "key": value["key"][1:]}

    if len(provider_cells) != 810 or [invariant_cell(item) for item in provider_cells] != [
        invariant_cell(item) for item in primary_cells
    ]:
        raise ValueError("Rule provider changed a calibration cell")
    macro_keys = {
        "brier",
        "ece",
        "precision",
        "recall",
        "undefined_brier_groups",
        "undefined_ece_groups",
        "undefined_precision_groups",
        "undefined_recall_groups",
    }
    provider_macro = _closed_object(
        provider["macro"],
        macro_keys | {"mean_cell_efficiency", "undefined_efficiency_groups"},
        "provider macro",
    )
    primary_macro = _closed_object(
        primary["macro"],
        macro_keys | {"mean_cell_efficiency", "undefined_efficiency_groups"},
        "primary macro",
    )
    if {key: provider_macro[key] for key in macro_keys} != {
        key: primary_macro[key] for key in macro_keys
    }:
        raise ValueError("Rule provider changed a macro calibration metric")
    provider_micro = _closed_object(
        provider["micro"],
        {"calibration", "micro_mean_cell_efficiency"},
        "provider micro",
    )
    primary_micro = _closed_object(
        primary["micro"],
        {"calibration", "micro_mean_cell_efficiency"},
        "primary micro",
    )
    if provider_micro["calibration"] != primary_micro["calibration"]:
        raise ValueError("Rule provider changed a micro calibration metric")
    if provider["gto_fpr"] != primary["gto_fpr"]:
        raise ValueError("Rule provider changed GTO FPR")


def _confidence_value_from_backend(
    backend: P610BValidationExecutionBackend, key: ValidationSessionKey
) -> tuple[Decimal, bool]:
    evidence = backend.ablation_evidence(key)
    return (
        Decimal(evidence["score_exact_decimal"]),
        evidence["candidate_eligibility"]["emitted"],
    )


def _selected_source_records(
    snapshot: P610BSnapshot, artifact_name: str
) -> tuple[ValidationArtifactRecord, ...]:
    artifact = snapshot.p69.artifact_payloads[artifact_name]
    records = tuple(_artifact_record(item) for item in artifact["records"])
    selected_id = snapshot.p69.selected_candidate.candidate_id
    return tuple(record for record in records if record.candidate_id == selected_id)


def _selected_source_record(
    snapshot: P610BSnapshot, artifact_name: str
) -> ValidationArtifactRecord:
    records = _selected_source_records(snapshot, artifact_name)
    if len(records) != 1:
        raise ValueError(f"selected source {artifact_name} must contain exactly one record")
    return records[0]


def _selected_primary_series_id(snapshot: P610BSnapshot) -> str:
    value = _selected_source_record(snapshot, "validation_aggregate_metrics").payload["result"][
        "series_id"
    ]
    return _validate_sha256(value, "selected primary series ID")


def _source_snapshot(snapshot: P610BSnapshot) -> dict[str, object]:
    batch_path = _p6_10a_artifact_path(snapshot, "p6_10a_batch_manifest")
    report_path = _p6_10a_artifact_path(snapshot, "comparator_ablation_report")
    gap_path = _p6_10a_artifact_path(snapshot, "gate_b_readiness_gap_packet")
    return {
        "target_commit": P6_10B_BASELINE,
        "p6_10a_batch_manifest": _repo_reference(
            snapshot.repo_root, "p6_10a_batch_manifest", batch_path
        ),
        "p6_10a_run_manifest": _repo_reference(
            snapshot.repo_root, "p6_10a_run_manifest", snapshot.p6_10a_run_path
        ),
        "p6_10a_result_root": _repo_reference(
            snapshot.repo_root, "p6_10a_result_root", snapshot.p6_10a_result_path
        ),
        "comparator_ablation_report": _repo_reference(
            snapshot.repo_root, "comparator_ablation_report", report_path
        ),
        "gate_b_readiness_gap_packet": _repo_reference(
            snapshot.repo_root, "gate_b_readiness_gap_packet", gap_path
        ),
    }


def _p6_10a_artifact_path(snapshot: P610BSnapshot, name: str) -> Path:
    for ref in snapshot.p6_10a_result["artifacts"]:
        if ref["name"] == name:
            return _safe_child(snapshot.p6_10a_result_path.parent, ref["path"], name)
    raise ValueError(f"P6-10A result root lacks {name}")


def _ablation_projection(plan: P610BAblationPlan) -> dict[str, object]:
    return {
        "ablation_id": plan.ablation_id,
        "config": plan.config,
        "config_sha256": plan.config_sha256,
        "candidate_id": plan.candidate.candidate_id,
        "series_id": plan.series_id,
        "intervention": plan.config["intervention"],
    }


def _batch_from_payload(payload: dict[str, Any], raw: bytes) -> P610BBatchPlan:
    plans = []
    for entry in payload["ablation_configs"]:
        config = entry["config"]
        config_hash = sha256_bytes(canonical_json_bytes(config))
        if config_hash != entry["config_sha256"]:
            raise ValueError("P6-10B config hash does not reconstruct")
        retained = config["retained_primary_config"]
        candidate = PrimaryCandidate(
            entry["candidate_id"],
            retained["epsilon"],
            retained["sample_floor"],
            retained["detector_confidence"],
            retained["provider_confidence"],
            retained["safety_alpha"],
            retained["sampling_contract_sha256"],
        )
        plans.append(
            P610BAblationPlan(
                entry["ablation_id"], config, config_hash, candidate, entry["series_id"]
            )
        )
    sessions = tuple(
        ValidationSessionKey(
            item["candidate_id"],
            item["opponent_id"],
            item["horizon"],
            item["repetition_id"],
        )
        for item in payload["sessions"]
    )
    return P610BBatchPlan(payload, raw, sha256_bytes(raw), tuple(plans), sessions)


def _artifact_record(value: object) -> ValidationArtifactRecord:
    fields = {
        "candidate_id",
        "payload_sha256",
        "payload",
        "opponent_id",
        "horizon",
        "repetition_id",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("P6-10B embedded record is not closed-world")
    record = ValidationArtifactRecord(
        value["candidate_id"],
        value["payload_sha256"],
        value["payload"],
        value["opponent_id"],
        value["horizon"],
        value["repetition_id"],
    )
    if record.payload_sha256 != sha256_bytes(canonical_json_bytes(record.payload)):
        raise ValueError("P6-10B embedded record payload hash mismatch")
    return record


def _nested(value: object, path: Sequence[str]) -> object:
    current = value
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError(f"metric path {'.'.join(path)} is missing")
        current = current[key]
    return current


def _decimal_difference(left: object, right: object) -> str | None:
    if left is None or right is None:
        return None
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        difference = Decimal(str(left)) - Decimal(str(right))
    return _decimal_wire(difference)


def _mean(values: Sequence[Decimal]) -> Decimal:
    if not values:
        raise ValueError("mean requires values")
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        return sum(values, Decimal(0)) / Decimal(len(values))


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("decimal wire must be finite")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"-0", ""} else text


def _verify_binary64_evidence(value: object, label: str) -> None:
    data = _closed_object(value, {"binary64_hex", "exact_decimal"}, label)
    number = float.fromhex(data["binary64_hex"])
    if not number == number or number in {float("inf"), float("-inf")}:
        raise ValueError(f"{label} must be finite")
    if Decimal.from_float(number) != Decimal(data["exact_decimal"]):
        raise ValueError(f"{label} hex and exact decimal differ")


def _interpretation_limits(ablation_id: str) -> list[str]:
    common = [
        "fixed-nine-opponent-validation-snapshot-only",
        "no-test-generalization",
        "no-primary-selection-change",
    ]
    if ablation_id == ABL_CONFIDENCE_MVP_ID:
        return [
            "bounded-legacy-score-not-posterior-probability",
            "estimator-method-only-not-threshold-alpha-epsilon-or-floor",
            *common,
        ]
    return ["provider-only-not-detector-threshold-alpha-or-epsilon", *common]


def _write_payloads_exclusive(root: Path, payloads: Mapping[str, bytes]) -> list[dict[str, object]]:
    refs = []
    for name, raw in payloads.items():
        path = root / f"{name}.json"
        _write_exclusive(path, raw)
        refs.append(_reference(name, path.name, raw))
    return refs


def _reference(name: str, relative_path: str, raw: bytes) -> dict[str, object]:
    return {
        "name": name,
        "path": relative_path,
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _repo_reference(root: Path, name: str, path: Path) -> dict[str, object]:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("source artifact escapes the repository") from exc
    raw = resolved.read_bytes()
    return _reference(name, relative, raw)


def _absolute_reference(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"path": str(path), "sha256": sha256_bytes(raw), "size_bytes": len(raw)}


def _relative_reference(root: Path, path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "path": path.resolve().relative_to(root.resolve()).as_posix(),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _verify_absolute_reference(reference: object, path: Path, label: str) -> None:
    ref = _closed_object(reference, {"path", "sha256", "size_bytes"}, label)
    raw = path.read_bytes()
    if ref != {"path": str(path), "sha256": sha256_bytes(raw), "size_bytes": len(raw)}:
        raise ValueError(f"{label} reference differs from its bytes")


def _verify_relative_reference(root: Path, path: Path, reference: object, label: str) -> None:
    ref = _closed_object(reference, {"path", "sha256", "size_bytes"}, label)
    raw = path.read_bytes()
    expected = {
        "path": path.resolve().relative_to(root.resolve()).as_posix(),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }
    if ref != expected:
        raise ValueError(f"{label} reference differs from its bytes")


def _safe_repo_relative(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("repository-relative path must be POSIX")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("repository-relative path escapes the repository")
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ValueError("repository-relative path escapes the repository")
    return path


def _safe_child(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError(f"{label} path must be relative POSIX")
    relative = Path(value)
    if relative.is_absolute() or relative.as_posix() != value or ".." in relative.parts:
        raise ValueError(f"{label} path escapes its root")
    path = (root / relative).resolve()
    if root.resolve() not in path.parents:
        raise ValueError(f"{label} path escapes its root")
    return path


def _closed_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} is not closed-world")
    return value


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not canonical JSON")
    return payload


def _run_pinned_p6_10a_verifier(
    run_manifest_path: Path, *, repo_root: Path
) -> tuple[dict[str, Any], P69Snapshot]:
    """Run the unchanged P6-10A verifier against its historical Git state.

    P6-10A correctly rejects later repository commits.  P6-10B therefore
    adapts only the read-only repository-state observation to the SHA-pinned
    P6-10A target while retaining every source, runtime, artifact, schema,
    cardinality, and deterministic reconstruction check.
    """
    from . import p6_10 as p6_10_module
    from . import p6_10_freeze as p6_10_freeze_module
    from . import validation_freeze as validation_freeze_module
    from .validation_freeze import ValidationRepositoryState

    raw = run_manifest_path.read_bytes()
    if sha256_bytes(raw) != P6_10A_RUN_SHA256:
        raise ValueError("P6-10A run manifest hash differs from the approved snapshot")
    payload = _strict_object(raw, "P6-10A run manifest")
    git = payload.get("git")
    expected_git = {
        "branch": "main",
        "head_commit": P6_10B_BASELINE,
        "local_main_commit": P6_10B_BASELINE,
        "cached_origin_main_commit": P6_10B_BASELINE,
        "dirty": False,
        "live_remote_queried": False,
        "expected_target_commit": P6_10B_BASELINE,
    }
    if git != expected_git:
        raise ValueError("P6-10A run is not bound to the approved historical target")
    historical = ValidationRepositoryState(
        "main",
        P6_10B_BASELINE,
        P6_10B_BASELINE,
        P6_10B_BASELINE,
        False,
    )
    original_p6_10a_reader = p6_10_freeze_module._read_repository_state
    original_validation_reader = validation_freeze_module._read_repository_state
    original_snapshot_loader = p6_10_module.load_p6_9_snapshot
    captured: list[P69Snapshot] = []

    def capture_snapshot(*args: object, **kwargs: object) -> P69Snapshot:
        value = original_snapshot_loader(*args, **kwargs)
        captured.append(value)
        return value

    try:
        p6_10_freeze_module._read_repository_state = lambda _root: historical
        validation_freeze_module._read_repository_state = lambda _root: historical
        p6_10_module.load_p6_9_snapshot = capture_snapshot
        verified = verify_p6_10a_run_manifest(run_manifest_path, repo_root=repo_root)
    finally:
        p6_10_freeze_module._read_repository_state = original_p6_10a_reader
        validation_freeze_module._read_repository_state = original_validation_reader
        p6_10_module.load_p6_9_snapshot = original_snapshot_loader
    if verified != payload:
        raise ValueError("P6-10A pinned verifier returned different manifest bytes")
    if not captured or any(item != captured[0] for item in captured[1:]):
        raise ValueError("P6-10A verifier did not return one stable P6-9 snapshot")
    return verified, captured[0]


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _SHA256_CHARS for char in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("UTC timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("UTC timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("UTC timestamp must be timezone-aware")
    return parsed


def _parse_args(raw_argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-manifest", required=True, type=Path)
    parser.add_argument("--freeze-hash-sidecar", required=True, type=Path)
    return parser.parse_args(list(raw_argv))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[2]
    run_path = run_p6_10b_from_freeze(
        args.freeze_manifest,
        args.freeze_hash_sidecar,
        repo_root=repo_root,
    )
    print(f"P6-10B completed and verified: {run_path}")
    print("P6-10 complete and Gate B ready remain false; human approval is required")
    return 0


__all__ = [
    "P6_10B_ATTEMPT_ID",
    "P6_10B_BATCH_MANIFEST",
    "P6_10B_CLI_VERSION",
    "P6_10B_ENTRYPOINT",
    "P6_10B_FAILURE_RECORD",
    "P6_10B_RESULT_ROOT",
    "P6_10B_RUN_MANIFEST",
    "P610BAblationPlan",
    "P610BBatchPlan",
    "P610BResultBundle",
    "P610BSnapshot",
    "build_p6_10b_batch",
    "execute_p6_10b",
    "load_p6_10a_snapshot",
    "main",
    "run_p6_10b_independent_verifier",
    "run_p6_10b_from_freeze",
    "verify_p6_10b_batch",
    "verify_p6_10b_result_root",
    "verify_p6_10b_run_manifest",
]
