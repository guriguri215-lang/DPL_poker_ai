# poker-xai

**A research framework for explainable, verifiable safe opponent exploitation in
poker. It is not a real-time playing bot.** It studies whether an AI's decision
to deviate from a baseline strategy in order to exploit an opponent can be
disclosed *faithfully* — and how to measure that faithfulness against ground
truth.

The framework deliberately contains **no** real-time input, screen scraping,
site APIs or automation. That capability is absent by design, not disabled.

## What this is

Poker is a rare setting where the opponent's true strategy can be revealed after
the fact, which gives explanation faithfulness a ground truth. Around this we
build:

- A **Decision Provenance Log (DPL)**: a structured, auditable record of *why*
  the policy was adjusted on each decision (observed leak → trigger → exploit →
  safety mixing → realised action), with an explicit reason ontology and EV
  provenance.
- A **node-lock opponent synthesis** so leaks are constructively known.
- An **answer-key protocol** and faithfulness metrics (Reason Validity,
  numerical consistency, counterfactual consistency, calibration).

The central research claim is a *faithfulness evaluation framework* for
explainable safe exploitation, not EV performance.

## Can / cannot do

- **Can**: define and validate the DPL / Reason Ontology / RunManifest
  contracts, and (in later phases) solve River spots exactly, synthesise
  opponents with known leaks, generate template explanations, and evaluate their
  faithfulness.
- **Cannot / will not**: play against live opponents, read screens, connect to
  poker sites, or automate real-money play.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python cli/export_schemas.py --out-dir docs/schemas
```

## Status

Early development. Phase 0 (frozen contracts) lives in `src/poker_core`:
the DPL schema, the Reason Ontology and the RunManifest. Other packages are
placeholders filled in over later phases.

## Citation

A paper is in preparation ("Verifiable Safe Exploitation"). Citation details
will be added on release.

## Responsible use

This is a simulation-only research artefact. Do not use it to gain an unfair
advantage in real-money play or in violation of any poker platform's terms. See
`docs/responsible_use.md` (added with the docs phase).

## License

Apache-2.0. See [LICENSE](LICENSE).
