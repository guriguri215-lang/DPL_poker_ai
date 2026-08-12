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
- `verifier.py` is a separate in-repository checker for an
  `ExplanationDocument`, its source DPL, and optional solver diagnostics. It does
  not import the generator; it resolves source paths, allowed derivations, reason
  citations, rendered text and the closed set of allowed numeric claim names
  with separate logic. Surface numbers are checked against verifier-side display
  rounding for percentages and EV units. Detected leak numeric claims are limited
  to whitelisted leak reasons, and solver diagnostics input requires matching
  explanation-side claims. These checks do not certify solver convergence,
  strategy safety or optimality, GTO status, external validation, or independent
  third-party reproducibility.

The normal Hero `--explanations` path and the historical P5-4 artifact CLI share
the minimal orchestration in `poker_ai.explanation_artifacts`. That layer keeps
the generator and verifier separate, preserves DPL order, verifies every pair
before writing, and reuses the existing explanations JSONL and verifier-summary
formats. It changes neither explanation schema nor generator/verifier logic.
The manifest-first saved-bundle consumer reuses the same pairing, checker-result,
and verifier-summary decisions; see the public [verification guide](../../docs/explanation_bundle_verification.md).

Any future LLM surface layer remains a later Phase 8 task.
