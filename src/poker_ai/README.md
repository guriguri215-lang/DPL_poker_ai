# poker_ai

Hero-side pipeline: observation, finite-iteration CFR river base strategy,
action-only leak detection, SafetyMixer, ActionSelector and the session runner.
The original Phase 2 river MVP (ADR-0007) is connected to the combo-granular CFR
solver for bounded all-in decisions.

## Task 3 vertical slice

Scenario → stub opponent public action → observation tracking → CFR `vs_bet` strategy
→ minimal action-only LeakDetector → optional exploit provider → SafetyMixer →
Decision Provenance Log (JSONL) → schema validation. Showdown-required leaks and
an LLM surface layer are outside the implemented normal-session path.

- `actions.py` — the river action vocabulary; task 3 realises only facing an all-in
  (`FOLD` / `CALL`), whose terminals are showdown-determined so every EV is exact.
- `scenario.py` + no config file — the **frozen Q3** scenario schema
  (`SCENARIO_SCHEMA_VERSION = 0.1.0`, ADR-0014) and a deterministic seed-driven
  generator (M-5).
- `hand_bucket.py` + `hand_bucket.yaml` — the **frozen Q5** percentile bands
  (`bucket_def_version = 0.1.0`, ADR-0015) mapping a combo to one of the five frozen
  DPL classes (ADR-0005). A bucket is a strict-CDF / reach-percentile band within
  Hero's own range, not an absolute hand category, so upper bands can be empty for
  small/concentrated ranges (ADR-0015).
- `cfr_policy.py` — the normal base-policy provider. It maps the observed all-in bet
  to the river solver bet size and returns Hero's finite-iteration combo- and
  position-specific `vs_bet` `StrategyTable` entry under an explicit
  iterations/average-delay config.
- `base_policy.py` — the provider boundary and compatibility-only adapter for the
  hand-authored `0.0.1-stub` strategy.
- `baseline_strategy.py` + `baseline_strategy.yaml` — the retained **stub** fixture
  (`baseline_table_version` ends with `-stub`; not an equilibrium).
- `opponent.py` — the single fixed `jam_all` stub opponent. Its hidden action
  strategy is behind a tripwire: reading `hidden_strategy` raises (AI Spec 6.3); only
  the public assumed range is available to Hero.
- `observation.py` — action-only public observation counts by situation key. It
  accepts public action labels, never opponent objects or hidden policies.
- `leak.py` — MVP action-rate LeakDetector for `LEAK_R007` / `LEAK_R008`, producing
  DPL `DetectedLeak` records from public observations only. Its action baseline
  matches the stub opponent, so the normal CLI run has no detected leaks.
- `exploit.py` — rule-based exploit provider. The MVP reacts to actionable
  `LEAK_R008` records by shifting fold mass into calls only when exact per-action EV
  improves over the base policy.
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
- `explanation_bundle_cli.py` — the thin, offline, read-only manifest-first CLI
  for rechecking saved normal Hero explanation bundles. It reuses the writer's
  pairing, checker-result, and summary decisions and never runs a session.

Run the distributed CLI with
`poker-xai-run-session --seed 20260704 --hands 200` (CFR+ defaults:
`--solver-iterations 40 --solver-average-delay 0`). The compatible source-tree
wrapper remains `python cli/run_session.py --seed 20260704 --hands 200`.
To exercise a positive convex mixer blend:
`poker-xai-run-session --safety-alpha 0.5`.
Both paths use the packaged `poker_ai.run_session_cli` implementation and record
their actual entrypoint, raw arguments, package version, and anchored-or-unknown
Git provenance in the RunManifest.

The normal adapter is limited to heads-up river decisions facing an all-in. Its
40-iteration default is a bounded experiment setting, not a convergence,
exact-equilibrium, or GTO certificate.

## Frozen at 0.1.0 (Q3 / Q4 / Q5)

`scenario.py` (Q3, ADR-0014), `state_cluster.yaml` (Q4, ADR-0016), and
`hand_bucket.yaml` (Q5, ADR-0015) are frozen at `0.1.0`. They are not among the
Phase-0 frozen contracts (ADR-0006), but changing their fields, invariants,
precedence, or thresholds now requires a new ADR and a version bump.
