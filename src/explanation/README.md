# explanation

Structured explanations generated from validated DPL records.

Phase 5 keeps generation deterministic and LLM-free:

- `contract.py` defines the Explanation object: five ordered stages
  (observation, hypothesis, validation, adjustment, residual risk), a separate
  counterfactual block, policy reasons (`LEAK_` / `TRG_`) split from sampling
  reasons (`MIX_`), and numeric claims with explicit source paths.
- `template.py` renders the contract from a `DecisionProvenanceLog`. It obtains
  EV values only through `dpl.ev_for_explanation()`, so non-`solver_exact` EVs do
  not reach the explanation. Optional solver diagnostics are stored separately
  from the decision-level EV delta.

The independent Explanation Verifier and any future LLM surface layer are later
Phase 5/8 tasks.
