# poker_ai

Hero-side pipeline: observation, finite-iteration CFR river base strategy,
action-only leak detection, SafetyMixer, ActionSelector and the session runner.
The original Phase 2 river MVP (ADR-0007) is connected to the combo-granular CFR
solver for bounded all-in decisions and explicit R007/R001 OOP no-facing fixtures.

## Task 3 vertical slice

Scenario → stub opponent public action → observation tracking → CFR `vs_bet` strategy
→ minimal action-only LeakDetector → optional exploit provider → SafetyMixer →
Decision Provenance Log (JSONL) → schema validation. Showdown-required leaks and
an LLM surface layer are outside the implemented normal-session path.

- `actions.py` — the river action vocabulary; the default path realises facing an
  all-in (`FOLD` / `CALL`), R007 realises only OOP `CHECK` / `BET_33`, and R001
  only OOP `CHECK` / `BET_75`. Every exposed decision uses exact fixed-tree
  action EV.
- `scenario.py` + no config file — the **frozen Q3** scenario schema
  (`SCENARIO_SCHEMA_VERSION = 0.1.0`, ADR-0014) and a deterministic seed-driven
  generator (M-5).
- `hand_bucket.py` + `hand_bucket.yaml` — the **frozen Q5** percentile bands
  (`bucket_def_version = 0.1.0`, ADR-0015) mapping a combo to one of the five frozen
  DPL classes (ADR-0005). A bucket is a strict-CDF / reach-percentile band within
  Hero's own range, not an absolute hand category, so upper bands can be empty for
  small/concentrated ranges (ADR-0015).
- `cfr_policy.py` — the normal base-policy providers. The historical provider maps
  the observed all-in to a combo- and position-specific `vs_bet` entry. The R007
  adapter maps the existing single 0.33-pot tree size to `BET_33`; the R001
  adapter maps the frozen equilibrium's 0.75-pot size to `BET_75`. Both return
  the OOP `start` entry and evaluate exact current-node action EV without adding
  a solver public API or multi-size tree.
- `base_policy.py` — the provider boundary and compatibility-only adapter for the
  hand-authored `0.0.1-stub` strategy.
- `baseline_strategy.py` + `baseline_strategy.yaml` — the retained **stub** fixture
  (`baseline_table_version` ends with `-stub`; not an equilibrium).
- `opponent.py` — fixed `jam_all`, R007 `check_back_all`, and pinned versioned
  R001 synthesis fixture identities. Hidden action behavior stays
  environment-side; only the public assumed range is available to Hero.
- `observation.py` — action-only public observation counts by situation key. It
  accepts public action labels, never opponent objects or hidden policies.
- `leak.py` — MVP action-rate LeakDetector for `LEAK_R001`, `LEAK_R007`, and
  `LEAK_R008`, producing DPL `DetectedLeak` records from public observations only.
  R001 derives its baseline from the frozen equilibrium; the normal CLI baseline
  remains unchanged.
- `exploit.py` — solver-backed node-lock and retained rule-based exploit
  providers. The node-lock provider handles eligible `LEAK_R001`, `LEAK_R007`,
  and `LEAK_R008` records with the existing HARD/fix-to-baseline solver, uses the rule provider
  when the fixed river tree cannot apply a lock, and changes policy only when
  exact per-action EV strictly improves over the base policy.
- `mixer.py` — the SafetyMixer (`final = (1-alpha)*base + alpha*exploit`, the DPL
  convex-mixing contract) and the seeded ActionSelector. This formula produces a
  valid mixture; it is not a strategy-safety proof.
- `decision.py` — Hero's decision on the public `Observation`, with the exact
  `incremental_ev_from_current_node` EV (`solver_exact`, ADR-0008).
- `session.py` — the runner that records public opponent actions, assembles validated
  DPLs and a `RunManifest`, and writes JSONL + manifest under a gitignored output
  directory.
- `explanation_artifacts.py` — one-to-one orchestration for deterministic template
  explanations and a separate in-repository verifier. It checks DPL/ontology
  paths, source references, numeric claims, and rendered templates before any
  bundle write; it does not certify convergence, safety, optimality, GTO status,
  external validation, or independent third-party reproducibility.
- `post_session_evaluation.py` - the deterministic Phase 8 answer-key evaluator.
  It runs only after all Hero decisions, reuses terminal posterior candidates,
  exact DPL EV and existing verifier results, and proposes conservative
  next-session settings using only the existing detector thresholds, safety
  alpha and epsilon. A later normal Hero session uses those verified settings as
  defaults only when you explicitly pass the completed source RunManifest with
  `--previous-session-manifest`; it does not discover a manifest or start another
  session automatically, or carry forward the source baseline, observation
  history or answer key.
- `explanation_bundle_cli.py` — the thin, offline, read-only manifest-first CLI
  for rechecking saved normal Hero explanation bundles. It reuses the writer's
  pairing, checker-result, and summary decisions and never runs a session.

Run the distributed CLI with
`poker-xai-run-session --seed 20260704 --hands 200` (CFR+ defaults:
`--solver-iterations 40 --solver-average-delay 0`). The compatible source-tree
wrapper remains `python cli/run_session.py --seed 20260704 --hands 200`.
To exercise a positive convex mixer blend:
`poker-xai-run-session --leaky-fixture --safety-alpha 0.5`.
To exercise R007 with the fixed five-hand causal smoke:

```text
poker-xai-run-session --seed 20260704 --hands 5 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R007 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r007
```

To exercise R001 with the fixed 0.75-pot branch and saved-bundle verification:

```text
poker-xai-run-session --seed 20260000 --hands 20 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R001 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r001
```

Both paths use the packaged `poker_ai.run_session_cli` implementation and record
their actual entrypoint, raw arguments, package version, and anchored-or-unknown
Git provenance in the RunManifest.

The default adapter is limited to heads-up river decisions facing an all-in. R007
is limited to OOP `CHECK`/`BET_33`; it records a check-back only after Hero checks.
R001 is limited to OOP `CHECK`/fixed `BET_75`; it records `FOLD`/`CALL` only after
Hero bets. Neither response is carried into the same decision. Arbitrary or
additional no-facing sizes, raises, and an automatic session loop remain
unsupported.
The 40-iteration default is a bounded experiment setting, not a convergence,
exact-equilibrium, or GTO certificate.

## Frozen at 0.1.0 (Q3 / Q4 / Q5)

`scenario.py` (Q3, ADR-0014), `state_cluster.yaml` (Q4, ADR-0016), and
`hand_bucket.yaml` (Q5, ADR-0015) are frozen at `0.1.0`. They are not among the
Phase-0 frozen contracts (ADR-0006), but changing their fields, invariants,
precedence, or thresholds now requires a new ADR and a version bump.
