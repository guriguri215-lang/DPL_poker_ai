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
- `verifier.py` independently audits an `ExplanationDocument` against the DPL
  and optional solver diagnostics. It does not import the generator; it resolves
  source paths, allowed derivations, reason citations, rendered text and the
  closed set of allowed numeric claim names with separate logic. Surface numbers
  are checked against verifier-side display rounding for percentages and EV
  units. Detected leak numeric claims are limited to whitelisted leak reasons,
  and solver diagnostics input requires matching explanation-side claims.

Any future LLM surface layer remains a later Phase 8 task.
