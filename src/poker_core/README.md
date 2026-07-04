# poker_core

Shared contracts and primitives for the whole project, so that `poker_ai` and
`poker_solver` use one implementation and cannot drift (REV-20260702 H-2/H-9).

## Frozen contracts (Phase 0, ADR-0006)

- `dpl_schema.py` — Decision Provenance Log (DPL) schema v1, the core contract.
- `reason_ontology.yaml` + `reason_ontology.py` — the three-layer reason
  namespaces `LEAK_` / `TRG_` / `MIX_` (ADR-0001) and their loader.
- `strategy_table.py` — per-combo StrategyTable contract (ADR-0005, M-3).
- `run_manifest.py` — the reproducibility manifest for a run.
- `schema_export.py` — build/write JSON Schemas for the contracts above.

## River primitives and evaluators (Phase 1, task 2)

- `card.py` — the shared `Card` model (rank + suit, deck index / bit mask).
- `combo.py` — the two-card `Combo` with a canonical string form.
- `range_model.py` — the weighted `Range` with blocker / conflict exclusion and
  normalisation.
- `hand_evaluator.py` — best five-of-seven evaluation into a comparable strength
  (all categories, kickers, ties).
- `showdown_ev.py` — exact range-vs-range showdown equity and Hero EV with
  blocker removal (Solver spec Phase S0), plus a seeded Monte Carlo estimator.
- `state_cluster.py` + `state_cluster.yaml` — the single board-texture
  classifier driven by a declarative, versioned rule set (H-9). The taxonomy is
  a **draft** (`cluster_def_version` ends with `-draft`, Q4) and must be frozen
  via an ADR before any persisted table is keyed on it.
