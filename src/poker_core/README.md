# poker_core

Shared contracts and primitives for the whole project. Phase 0 freezes the
contracts here (ADR-0006):

- `dpl_schema.py` — Decision Provenance Log (DPL) schema v1, the core contract.
- `reason_ontology.yaml` + `reason_ontology.py` — the three-layer reason
  namespaces `LEAK_` / `TRG_` / `MIX_` (ADR-0001) and their loader.
- `run_manifest.py` — the reproducibility manifest for a run.
- `schema_export.py` — build/write JSON Schemas for the contracts above.

Later phases add cards, hand evaluation, ranges, the state-cluster definition
and the strategy table here so that `poker_ai` and `poker_solver` share a single
implementation and cannot drift.
