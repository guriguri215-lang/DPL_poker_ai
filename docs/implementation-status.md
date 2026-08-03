# Implementation status

This document separates implemented behavior from research goals and records the
evidence used for the public README. The snapshot was reviewed on 2026-08-03 from
base commit `b6e21a7` on branch `gate-b-v2-cli-wip-freeze`, one commit ahead of local
`main` (`e5e71ce`).

## Project classification

- Primary type: **Research prototype**
- Secondary types: Python library, CLI collection, mathematical/optimization tool
- Maturity: **Functional prototype**
- Intended users: researchers and developers studying poker AI, imperfect-
  information games, opponent modeling, decision provenance, and explanation
  faithfulness

## Claim-to-evidence matrix

| Public claim or surface | Evidence | Assessment | Qualification |
| --- | --- | --- | --- |
| DPL, Reason Ontology, StrategyTable, and RunManifest contracts exist | `src/poker_core/dpl_schema.py`, `reason_ontology.py`, `strategy_table.py`, `run_manifest.py`; `tests/poker_core/` | Implemented | Pydantic validators, not formal verification |
| Schema export is runnable | `cli/export_schemas.py`; `tests/test_export_schemas.py`; reviewed command wrote five schemas | Implemented | JSON Schema omits some cross-field semantics |
| River hand/range EV is available | `card.py`, `combo.py`, `range_model.py`, `hand_evaluator.py`, `showdown_ev.py`; corresponding tests | Implemented | Exact enumeration and seeded Monte Carlo; not a full betting-game solver |
| The documented DPL session is reproducible | `cli/run_session.py`, `poker_ai/session.py`; reviewed five-hand run | Implemented for the documented fixture | Uses a stub baseline/opponent; environment and Git state still matter |
| Public-only leak detection is enforced | `observation.py`, `opponent.py`, `leak.py`; hidden-strategy tripwire tests | Implemented in the simulation | Does not establish privacy/security for arbitrary external data |
| CFR and CFR+ solve poker games | `poker_solver/cfr.py`, `cfr_plus.py`, analytic AKQ/Kuhn/toy tests | Partially implemented | Deterministic full-tree approximate solving for finite games only |
| River solving is supported | `river_tree.py`, `river_solve.py`, `test_river_*` | Implemented for a restricted abstraction | Heads-up, two-player zero-sum, single-bet river tree; not full NLHE GTO |
| Best response/exploitability is independently evaluated | `best_response.py`, `evaluate.py`, `reach.py`; analytic tests | Implemented for finite repository games | Independent of CFR internals, not independently validated by an external project |
| Node-locked opponents can be synthesized | `poker_solver/nodelock.py`, `opponents/synthesis.py`, `opponents/ground_truth.py` | Implemented for HARD locks | SOFT locks raise `NotImplementedError` |
| Explanations are verified | `explanation/template.py`, `explanation/verifier.py`; explanation tests | Implemented internal verification | Deterministic template only; no human study, LLM, or external verifier |
| Training and Validation are automated | `phase6/training_*`, `validation_*`, `production_inputs.py`; Phase 6 tests | Experimental | Closed repository fixtures and large deterministic plans; not a service or general benchmark |
| Gate B provides a production-ready trust boundary | `phase6/gate_b_*`; Gate B tests | Not verified | Fail-closed design is implemented, but current CI/tests/lint are not clean and v2 is WIP |
| No live poker integration exists | repository-wide search plus CLI/package inventory | Implemented boundary | No screen scraping, site API, live table input, or real-money automation found |
| No model/API provider is required | `pyproject.toml`, imports, CLI inventory | Implemented for documented paths | Only Pydantic and PyYAML are runtime dependencies |
| Supported OS is cross-platform | CI workflow and platform-specific Gate B code/tests | Partially verified | Ubuntu CI plus Windows review; macOS unverified; Gate B v2 command is Windows-specific |

## Interfaces and data formats

| Surface | Input | Output | Stability |
| --- | --- | --- | --- |
| `cli/run_session.py` | CLI flags for seed, hand count, mixing, fixture, and output directory | DPL JSONL plus RunManifest JSON | Demonstration CLI; functional |
| `cli/export_schemas.py` / `poker-xai-export-schemas` | Output directory | Five JSON Schema files | Functional |
| `poker_solver` Python API | In-memory finite games, river scenarios, ranges, profiles, node-lock configs | Strategy profiles, EV, exploitability, metrics, artifacts | Experimental internal API |
| `opponents` Python API | Canonical config and frozen equilibrium reference | Deterministic synthesized strategy and leak provenance | Repository-fixture API |
| Phase 6 wrapper scripts | Frozen manifests, catalogs, paths, and execution contracts | Canonical JSON artifacts and manifests | Experimental; advanced, resource-intensive |
| Gate B v2 closed CLI | `execute-once-v2` plus a pinned Windows spec reference | Canonical receipt or closed JSON error | WIP; intentionally has no `--help` path |

## Validation snapshot

| Check | Result | Evidence |
| --- | --- | --- |
| Test discovery | 1,624 tests collected | `python -m pytest --collect-only` |
| Clean install | Passed in a new Python 3.12 venv | `python -m pip install -e ".[dev]"` |
| Minimal DPL run | Passed in the clean venv: 5 decisions, 5 leaks, 5 mixed decisions | `python cli/run_session.py --seed 20260704 --hands 5 --leaky-fixture ...` |
| Schema export | Passed in the clean venv: five schema files written | `python cli/export_schemas.py --out-dir ...` |
| Core non-Phase-6 suites | 538 passed | `tests/poker_core`, `poker_ai`, `poker_solver`, `opponent_models`, `explanation`, and schema-export tests |
| Ruff lint | Failed with 8 findings | Includes unused/unsorted imports, a shadowed `field`, and undefined `_strict_canonical_object` in Gate B v2 WIP |
| Ruff format | Failed | Four files would be reformatted |
| Latest `main` CI | Failed on 2026-08-01 | 1,513 passed, 20 skipped, 34 failed; Linux rejected Windows-root golden fixtures |
| Full local WIP suite | 1,611 passed, 10 skipped, 3 failed in the combined-dependency review environment | Two failures were caused by duplicate installed-distribution inventory; one failed Windows stream enumeration |
| Clean rerun of the 3 failures | 2 passed, 1 failed | The remaining Gate B v2 lifecycle test fails closed when enumerating streams on its volume-GUID child path |

The latest successful `main` CI run was commit `d031dcb` on 2026-07-31. The
following `main` commit `e5e71ce` failed. Passing unit tests or exact values for
small games must not be generalized into real-world poker strength, security, or
scientific validity.

## Known implementation boundaries

- `poker_ai`'s quickstart baseline is `0.0.1-stub`, not solver output.
- `cli/run_session.py` supplies the Git commit but not the worktree-dirty flag;
  `RunManifest.code.git_dirty` therefore remains its default `false` even when
  local changes exist.
- SOFT node-lock modes are declared but rejected.
- `src/experiments/` remains a placeholder; implemented Phase 6 work lives in
  `src/phase6/`.
- The Test opponent split is intentionally unavailable through normal catalog
  access and is handled only by controlled Gate B surfaces.
- Gate B relies on filesystem identity and anti-substitution behavior that differs
  between Windows and POSIX.
- The repository has no releases, published benchmark, coverage claim, security
  audit, external validation, stable API guarantee, or documented deployment.
- Generated experiment artifacts and schemas are gitignored and must be recreated.

## Evidence interpretation

“Exact” in this repository refers to enumeration or deterministic evaluation
within a declared finite game, range, policy, or artifact contract. It does not
mean that full no-limit hold'em is solved. “Verifier” refers to an independently
coded repository component, not a third-party audit. “Production” appears in
internal class/version names for concrete backends; it is not a public
production-readiness claim.
