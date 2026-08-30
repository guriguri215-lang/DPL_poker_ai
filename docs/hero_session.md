# Normal Hero session tutorial

[Back to the documentation index](README.md).

This command runs a deterministic, simulated Hero river session. It uses no
network input and writes a validated local bundle.

## Identify the command

Show the version without starting a session or creating files:

```text
poker-xai-run-session --version
```

For a source checkout, the historical wrapper goes through the same
`poker_ai.run_session_cli` module:

```text
python cli/run_session.py --version
```

The output identifies the invoked entry point and the authoritative
project/distribution version. If that version cannot be resolved under the
[no-guessing provenance contract](dpl_and_run_manifest.md#version-and-git-provenance),
the version is `unknown`. It is never inferred from the current directory or an
unrelated installation.

Inspect all current options without running a session:

```text
poker-xai-run-session --help
```

## Run a minimal offline session

Use one hand and one CFR+ iteration for a quick smoke run:

```text
poker-xai-run-session --seed 7 --hands 1 --solver-iterations 1 --out-dir experiments_output/tutorial
```

The compatibility command accepts the same arguments:

```text
python cli/run_session.py --seed 7 --hands 1 --solver-iterations 1 --out-dir experiments_output/tutorial
```

The bundle contains:

- `S00000007.dpl.jsonl`, with one validated DPL v3 object per line;
- `S00000007.manifest.json`, the RunManifest sidecar;
- `provenance/leak_confidence_estimator.json`;
- `provenance/action_baseline_table.json`;
- `provenance/action_stats_terminal_snapshots.json`.

The writer validates the provenance files before writing the DPL and manifest.
The manifest records the actual entry point, the full argument vector, the
resolved-or-`unknown` package/Git provenance, the master seed, and hashed solver
and configuration references.

## Opt in to in-repository-checked explanations

Add one flag to the same command; no separate top-level command is introduced:

```text
poker-xai-run-session --seed 7 --hands 1 --solver-iterations 1 --explanations --out-dir experiments_output/tutorial
```

The flag adds these existing-format files:

- `S00000007.explanations.jsonl`, with one `ExplanationDocument` per DPL line;
- `S00000007.verifier_summary.json`, with all-item verification counts and any
  failures (a successful published bundle has none);
- `S00000007.post_session_evaluation.json`, a canonical versioned Phase 8
  evaluation plus the proposed next-session settings.

The DPL and explanations preserve count and order, and every explanation's
`dpl_ref` is `session_id:hand_id` for the corresponding DPL. Generation uses the
deterministic template generator with no LLM, network input, or additional
dependency. The separate in-repository verifier checks every explanation against
its DPL, ontology paths, source references, numeric claims, and rendered template
before the writer creates or changes the run bundle; if any item fails, no
artifact from that attempted run is written. These checks do not certify solver
convergence, strategy safety or optimality, GTO status, external validation, or
independent third-party reproducibility. On success, the existing RunManifest
schema references the DPL, explanations, summary, terminal provenance snapshot,
and post-session evaluation with relative paths and SHA-256 hashes.

The answer key remains environment-only throughout every decision and is
revealed only after `run_session` has returned all validated DPLs. The initial
MVP makes the following deterministic assumptions because the specification
does not prescribe formulas or numeric update steps:

- detection accuracy is `(TP + TN) / (TP + FP + FN + TN)` over reached,
  structurally eligible, non-boundary terminal candidates;
- estimation error is the unweighted mean absolute observed-rate error over
  reached terminal candidates;
- EV gain is the per-decision mean of exact `final_ev - base_ev`;
- over-adjustment means exact `final_ev < base_ev`, while under-adjustment means
  exact `exploit_ev > final_ev`;
- explanation validity requires both the existing explanation verifier and
  truth-positive cited LEAK reasons.

A false positive, negative mean EV gain, or over-adjustment keeps the existing
detector estimator but sets its three existing confidence gates to `1.0`, safety
alpha to `0.0`, and epsilon to `0.0`. Otherwise every current value is retained.
In particular, false negatives and under-adjustment do not lower a threshold or
raise alpha/epsilon in this slice.

## Read a saved evaluation after complete bundle verification

Use the saved RunManifest and opt in to the additional display:

```text
poker-xai-verify-explanation-bundle --manifest experiments_output/tutorial/S00000007.manifest.json --show-evaluation
```

The command first performs the ordinary saved-bundle checks without changing
the bundle. Only after every manifest reference and hash, DPL/explanation pair,
checker-summary value, post-session field and session/opponent binding, and
next-session setting has passed does it print the six existing evaluation
metrics and the existing detector, safety-alpha, and epsilon settings in fixed
`key=value` order. The displayed `evaluation.exploit_ev_gain_vs_base` is the
saved mean exact `final_ev - base_ev` metric described above; it is not rounded
by the display. Hashes, filesystem paths, the answer key, diagnostic notes, and
session/opponent identities are omitted.

Without `--show-evaluation`, the verifier retains its existing two-line output
and older explanation bundles without this artifact remain verifiable. With the
flag, a missing or invalid post-session artifact fails before any success line
is emitted. The display reads the already saved, hash-bound result; it does not
rerun the evaluator or solver, independently reproduce the metric, recommend
that the next settings be used, or establish convergence, GTO play,
strategy-safety, profitability, or real-world performance.

## Run the solver-backed no-facing fixtures

### R007 check-back fixture

Use the existing session entry point and explicitly select R007:

```text
poker-xai-run-session --seed 20260704 --hands 5 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R007 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r007
```

This fixture forces the simulated Hero to the existing river tree's OOP `start`
node. The only legal actions are `CHECK` and the tree's fixed 0.33-pot bet,
recorded with the existing public label `BET_33`. Raises and other sizes are not
available on this path. Bare `--leaky-fixture`, without the selector, keeps the
historical R008 jam-all facing-an-all-in fixture.

The check-back opponent can respond only after Hero actually selects `CHECK`.
That public response is recorded after the current DPL decision and can inform
only later hands. A terminal situation with no reached check opportunity is
saved with zero observations rather than a fabricated action. The explicit
epsilon value above uses the existing recorded execution sampler so this fixed
five-hand smoke reaches the observation needed for an R007 HARD node-lock solve;
the normal and R008 epsilon default remains `0.0`.

When the solver candidate strictly improves exact current-decision EV, the DPL
records `exploit_source="nodelock_solver"` and a non-empty `solver_result_id`.
The corresponding `ExplanationDocument` contains the same ID, and the saved
bundle command verifies all five explanations. This is still a bounded,
finite-iteration simulation, not a convergence or GTO certificate.

### R003 small-bet overfold fixture

Select R003 explicitly to observe and exploit overfolding after the same fixed
0.33-pot bet used by R007:

```text
poker-xai-run-session --seed 20260004 --hands 20 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R003 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r003
```

Hero starts OOP with only `CHECK` and `BET_33`; no other bet size or raise is
available. R003 is a content-hashed, in-memory noncatalog fixture. Its baseline
is the reach-weighted IP `FOLD` rate at `vs_bet` in one pinned 40-iteration CFR+
0.33-pot profile, and its environment response rate is exactly 0.16 higher. The
inline opponent `ConfigRef` pins the reference scenario, solver inputs,
baseline and locked-profile hashes, lock modes, and response sampler. The
profile is a finite-iteration reference, not a convergence, exact-equilibrium,
or GTO certificate.

The environment samples `FOLD` or `CALL` only after Hero actually selects
`BET_33`. Detection for that hand has already completed, so the response is
recorded for later hands only; a Hero `CHECK` creates no response observation.
With sufficient prior public evidence, the existing node-lock provider applies
opponent/IP/`vs_bet`/`FOLD` with `baseline_scaled`, `HARD`, and
`fix_to_baseline`. It accepts a changed policy only when exact current-node
`CHECK`/`BET_33` EV strictly improves under the existing provider threshold.
DPL, SafetyMixer, template explanations, post-session evaluation,
and explicit settings handoff use their existing contracts.

Both `--leaky-fixture` and `--leaky-fixture-reason LEAK_R003` are required. The
general synthetic-opponent config and Phase 6 catalogs do not accept R003, and
there is no implicit fixture selection.

### R004 small-bet overcall fixture

Select R004 explicitly for the CALL-side experiment at the same 0.33-pot node:

```text
poker-xai-run-session --seed 20260004 --hands 160 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R004 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r004
```

R004 uses R003's exact reference scenario, 40-iteration finite-CFR profile,
0.33-pot size, and OOP `CHECK`/`BET_33` adapter. Its reach-weighted IP
`vs_bet/CALL` baseline is `0.7328227049493046`; adding the existing `0.16`
fixture delta gives a target of `0.8928227049493046`, which remains strictly
between zero and one. The environment applies that target with the existing
`baseline_scaled`, `HARD`, `fix_to_baseline` node lock. The content-hashed inline
identity includes R004, CALL, the solver settings, and both profile digests; it
does not add a profile artifact or make an equilibrium or GTO claim.

Hero detection completes before any response is generated. Only an actual
`BET_33` lets the environment sample and record `FOLD` or `CALL`; a `CHECK`
records no response, and the sample is available only to later hands. Eligible
provider results use exact current-node `CHECK`/`BET_33` EV and the existing
`1e-12 bb` overcall improvement tolerance. Outside the fixed BET_33 scope the
provider uses its existing rule fallback, which is an identity policy here.

Both fixture flags are required. R004 remains unsupported by generic synthetic
opponent configuration and every Phase 6 catalog. A later R004 session must
repeat both flags even when `--previous-session-manifest` is supplied: the
verified handoff restores only detector defaults, safety alpha, and epsilon.

### R001 overfold fixture

Select R001 explicitly; the normal, bare-fixture, R002, R003, R004, R007, and R008
defaults do not select this path:

```text
poker-xai-run-session --seed 20260000 --hands 20 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R001 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r001
```

Hero starts OOP with only `CHECK` and `BET_75`. `BET_75` is the existing frozen
`river-large-bet-equilibrium-v1` size, exactly 0.75 pot; there is no size argument
or multi-size tree. The fixture reuses pinned versioned training opponent
`nl-train-r001-d016-s102`. Its detector baseline is the frozen equilibrium's
IP `FOLD` rate at `vs_bet`, and its environment response is synthesized from the
same existing R001 mapping.

The environment samples and records `FOLD` or `CALL` only after Hero actually
selects `BET_75`. A Hero `CHECK` records no response and preserves a known
zero-opportunity situation. Detection for the current decision occurs before
the response, so that response can inform only later hands. After the configured
confidence gate is reached, an improving candidate may record the existing
opponent/IP/`vs_bet`/`FOLD` HARD `fix_to_baseline` node-lock provenance. Base,
exploit, and final policies keep the `CHECK`/`BET_75` keys, while DPL EV remains
the exact current-node `solver_exact` value.

With `--explanations`, the output directory contains:

- `S20260000.dpl.jsonl` and `S20260000.manifest.json`;
- `S20260000.explanations.jsonl` and `S20260000.verifier_summary.json`;
- `S20260000.post_session_evaluation.json`;
- the existing action-baseline, confidence-estimator, and terminal-snapshot
  files below `provenance/`.

The saved explanation bundle can be checked later with the existing
`poker-xai-verify-explanation-bundle` command. This fixture does not add a raise,
arbitrary size, automatic session loop, or any live-play integration, and its
outputs are not a convergence, GTO, strategy-safety, profitability, or real-play
performance claim.

### R002 overcall fixture

Select R002 to test the opposite action-rate leak at the same fixed node:

```text
poker-xai-run-session --seed 20260000 --hands 40 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R002 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r002
```

R002 deliberately reuses R001's frozen `river-large-bet-equilibrium-v1`, 0.75-pot
size, OOP `CHECK`/`BET_75` Hero decision, and IP `vs_bet` node. The difference is
the canonical opponent action: R001 raises `FOLD` above baseline, while R002
raises `CALL` above baseline. Both deltas are `0.16`. R002 is a content-hashed
in-memory fixture, not a new member of the nine-opponent Phase 6 catalog; its
canonical generation config is pinned as an inline `ConfigRef` in the existing
RunManifest contract.

The detector's R002 baseline and the environment's true CALL rate are both
derived through the existing ground-truth extractor. A `FOLD` or `CALL` is
sampled only after Hero actually selects `BET_75`, after that hand's decision
has been recorded. With sufficient prior public evidence, the node-lock provider
locks opponent/IP/`vs_bet`/`CALL` using `baseline_scaled`, `HARD`, and
`fix_to_baseline`. The accepted policy retains exact `CHECK`/`BET_75` action-EV
keys and must improve locked exact EV by more than `1e-12 bb`. The existing
`min_decision_ev_delta` is a policy threshold; the `1e-12 bb` value is the
existing exact-EV numerical tolerance, not a newly configurable provider
tolerance.

“Exact” here is exact under the fixed model: the evaluator traverses the finite
river tree for the current combo and current node while later actions follow the
supplied profile. The CFR+ profile is still finite-iteration. Neither the R001
nor R002 output certifies convergence, an exact equilibrium, GTO play, safety,
or real-world profitability.

## Hand settings to the next session explicitly

Name the completed source RunManifest; the command never searches for one:

```text
poker-xai-run-session --seed 8 --hands 1 --solver-iterations 1 --previous-session-manifest experiments_output/tutorial/S00000007.manifest.json --out-dir experiments_output/tutorial-next
```

The source must be the complete `--explanations` bundle above, because that is
the existing opt-in that writes the post-session evaluation.

Before the first Hero decision, the loader reuses the saved explanation-bundle
verifier, validates every relative `ArtifactRef` path and SHA-256, and requires
one canonical post-session artifact with the supported schema/type and matching
source-session/opponent identities. It strictly reconstructs the existing
`LeakDetectorConfig`, safety alpha, and epsilon and rejects invalid ranges. A
failure creates no output for the attempted successor.

The restored values are defaults. Explicit `--safety-alpha` and
`--exploration-epsilon` flags take precedence, including an explicit `0.0`.
When `--leaky-fixture` is also present, the baseline selected by
`--leaky-fixture-reason` remains the only baseline. The restored detector config
is passed to both the detector and real solver-backed node-lock provider, except
that the explicit R001, R002, R003, and R004 fixtures always use fixed
`min_deviation=0.08`.
Its confidence gates and retained rule-based fallback otherwise use the restored
thresholds. The source's posterior/action history, baseline, opponent identity,
session mode, and answer key are not transferred. Re-select R007, R001, R002,
R003, or R004 on every intended matching successor. There is no implicit latest-file
search, session registry, or automatic loop; repeat the explicit handoff for
each intended successor.

Omitting `--explanations` retains the five-file bundle above and does not change
the session inputs, action, solver behavior, or invocation provenance.

To recheck a saved explanation bundle without rerunning the session, use the
manifest-first, read-only command described in [Saved Hero explanation bundle
verification](explanation_bundle_verification.md).

## Important options and limits

- `--seed` defaults to `20260704`; `--hands` defaults to `200`.
- `--solver-iterations` defaults to `40`; `--solver-average-delay` defaults to
  `0`.
- `--previous-session-manifest PATH` makes that verified session's detector,
  alpha, and epsilon the defaults for this run. If omitted, normal alpha and
  epsilon remain `0.0`.
- Explicit `--safety-alpha` and `--exploration-epsilon` values override restored
  defaults.
- `--leaky-fixture` is a public positive-path smoke fixture that connects the
  detected leak to the solver-backed node-lock exploit provider. It defaults to
  the historical R008 fixture; `--leaky-fixture-reason LEAK_R007` selects the
  OOP `CHECK`/`BET_33` check-back fixture; `LEAK_R003` selects small-bet overfold
  and `LEAK_R004` small-bet overcall at the same fixed `BET_33`; `LEAK_R001`
  selects the overfold and `LEAK_R002` the overcall variant of the OOP
  `CHECK`/`BET_75` fixture. R001, R002, R003, and R004 use fixed detector
  deviation threshold `0.08`. The
  existing solver iteration and average-delay values configure both the
  base-policy and node-lock solves. A mapping that does not
  apply to the fixed river tree, or a baseline-scaled lock with no reachable
  target, uses the retained rule-based fallback. Every candidate changes policy
  only when it strictly improves the existing exact action EV; otherwise the base
  policy remains in use. This is not a production opponent model.
- `--explanations` is an artifact-output opt-in; it does not affect policy or
  action selection.

The default adapter remains limited to facing an all-in and therefore chooses
only between `FOLD` and `CALL`; R007/R003/R004 are limited to OOP
`CHECK`/`BET_33`, and R001/R002 to OOP `CHECK`/fixed 0.75-pot `BET_75`. Other
sizes and raises remain unsupported.
The 40-iteration default is not a convergence guarantee.
See [Responsible use](responsible_use.md) before using or sharing results.
