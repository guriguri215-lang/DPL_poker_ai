# poker_ai

Hero-side pipeline: observation, lookup strategy, SafetyMixer, ActionSelector and
the session runner. Phase 2 (task 3) implements the **vertical slice** (ADR-0007):
one river decision, wired end to end, before the CFR solver exists.

## Task 3 vertical slice

Scenario → single decision → lookup strategy (with `hand_bucket`) → stub opponent →
SafetyMixer (`alpha = 0`) → Decision Provenance Log (JSONL) → schema validation.
Leak detection, exploitation (`alpha > 0`), CFR and the LLM layer are later phases.

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
- `mixer.py` — the SafetyMixer (`final = (1-alpha)*base + alpha*exploit`, the DPL
  mixing contract) and the seeded ActionSelector.
- `decision.py` — Hero's decision on the public `Observation`, with the exact
  `incremental_ev_from_current_node` EV (`solver_exact`, ADR-0008).
- `session.py` — the runner that assembles validated DPLs and a `RunManifest`, and
  writes JSONL + manifest under a gitignored output directory.

Run it: `python cli/run_session.py --seed 20260704 --hands 200`.

## Frozen at 0.1.0 (Q3 / Q5)

`scenario.py` (Q3, ADR-0014) and `hand_bucket.yaml` (Q5, ADR-0015) are frozen at
`0.1.0` (human-approved 2026-07-04). They are not among the Phase-0 frozen contracts
(ADR-0006), but changing their fields, invariants or thresholds now requires a new ADR
and a version bump. The Q4 `state_cluster` definition remains `0.1.0-draft`.
