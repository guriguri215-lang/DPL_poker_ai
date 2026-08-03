# poker_ai

Hero-side pipeline: observation, lookup strategy, action-only leak detection,
SafetyMixer, ActionSelector and the session runner. Phase 2 implemented the river MVP
(ADR-0007): one river decision wired end to end before the CFR solver was added.
The packaged quickstart still uses the original stub baseline; solver-produced
strategies are available separately in `poker_solver` and are not automatically
wired into `cli/run_session.py`.

## Task 3 vertical slice

Scenario → stub opponent public action → observation tracking → lookup strategy
(with `hand_bucket`) → minimal action-only LeakDetector → rule exploit provider →
SafetyMixer → Decision Provenance Log (JSONL) → schema validation. This historical
vertical slice does not automatically use the later node-lock and CFR packages.
Showdown-required leak detection and an LLM layer remain absent.

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
- `baseline_strategy.py` + `baseline_strategy.yaml` — a **stub** base strategy
  (`baseline_table_version` ends with `-stub`; not an equilibrium) keyed by situation
  then `hand_bucket`, plus a builder for the canonical per-combo `StrategyTable`.
- `opponent.py` — the single fixed `jam_all` stub opponent. Its hidden action
  strategy is behind a tripwire: reading `hidden_strategy` raises (AI Spec 6.3); only
  the public assumed range is available to Hero.
- `observation.py` — action-only public observation counts by situation key. It
  accepts public action labels, never opponent objects or hidden policies.
- `leak.py` — MVP action-rate LeakDetector for `LEAK_R007` / `LEAK_R008`, producing
  frozen DPL `DetectedLeak` records from public observations only. The default stub
  baseline matches the stub opponent, so the normal CLI run has no detected leaks.
- `exploit.py` — rule-based exploit provider. The MVP reacts to actionable
  `LEAK_R008` records by shifting fold mass into calls only when exact per-action EV
  improves over the base policy.
- `mixer.py` — the SafetyMixer (`final = (1-alpha)*base + alpha*exploit`, the DPL
  mixing contract) and the seeded ActionSelector.
- `decision.py` — Hero's decision on the public `Observation`, with the exact
  `incremental_ev_from_current_node` EV (`solver_exact`, ADR-0008).
- `session.py` — the runner that records public opponent actions, assembles validated
  DPLs and a `RunManifest`, and writes JSONL + manifest under a gitignored output
  directory.

Run it: `python cli/run_session.py --seed 20260704 --hands 200`.
To exercise a positive safety mix: `python cli/run_session.py --safety-alpha 0.5`.

## Frozen at 0.1.0 (Q3 / Q4 / Q5)

`scenario.py` (Q3, ADR-0014), `state_cluster.yaml` (Q4, ADR-0016), and
`hand_bucket.yaml` (Q5, ADR-0015) are frozen at `0.1.0`. They are not among the
Phase-0 frozen contracts (ADR-0006), but changing their fields, invariants,
precedence, or thresholds now requires a new ADR and a version bump.
