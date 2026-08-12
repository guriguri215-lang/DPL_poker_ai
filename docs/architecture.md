# Architecture

[Back to the documentation index](README.md).

`poker-xai` is a simulation and evaluation framework, not a real-time poker bot.
The repository has no screen reader, poker-site API, real-time input adapter, or
live-play automation.

## Component boundaries

- [`poker_core`](../src/poker_core/README.md) owns shared cards, ranges, strategy
  tables, the Reason Ontology, the versioned Decision Provenance Log (DPL), and
  the RunManifest contract.
- [`poker_solver`](../src/poker_solver/README.md) owns the game-tree, CFR/CFR+,
  best-response, node-lock, evaluation, and frozen river-scenario solving code.
- [`poker_ai`](../src/poker_ai/README.md) connects public observations to a Hero
  base policy, leak detection, optional exploitation, SafetyMixer, action
  selection, DPL validation, and session output. Its small explanation-artifact
  orchestration layer connects completed sessions to the existing generator and
  verifier without moving either implementation across component boundaries.
- [`opponents`](../src/opponents/README.md) owns versioned synthetic opponent
  models used by the research and evaluation paths.
- [`explanation`](../src/explanation/README.md) renders and verifies explanations
  from validated records. It does not change the policy or solver result.
- [`phase6`](../src/phase6) contains the separate evaluation and Gate B contracts;
  the normal Hero session does not redefine them.

## Normal Hero session flow

The normal session implemented by
[`poker_ai.session`](../src/poker_ai/session.py) follows this sequence:

1. A seed deterministically produces simulated river scenarios.
2. The environment lets the stub opponent act, then gives Hero only the public
   observation and assumed public range. Hero is not given the opponent's hidden
   strategy.
3. The CFR+ river adapter solves Hero's exact combo- and position-specific
   `vs_bet` base policy for the observed all-in size.
4. Public opponent actions update the action-only observation tracker. The leak
   detector may produce recorded leak hypotheses, and an optional exploit
   provider may propose a policy.
5. SafetyMixer forms `final_policy`; the optional epsilon sampler affects only
   execution and is recorded separately.
6. Each decision is validated as a current DPL v3 record. The session also builds
   a RunManifest containing invocation, version, seed, and hashed configuration
   references.
7. Without explanation opt-in, the existing writer validates the posterior
   provenance bundle, then writes DPL JSONL, the RunManifest sidecar, and the
   supporting `provenance/` JSON files exactly as before.
8. With `--explanations`, one deterministic `ExplanationDocument` is generated
   for each validated DPL in input order. The independent verifier checks all
   pairs, including their session/hand reference, before the output directory is
   changed. Only a fully verified set is written using the existing explanations
   JSONL and verifier-summary formats. The unchanged RunManifest schema uses its
   existing hashed `ArtifactRef` outputs for DPL, explanations, summary, and the
   terminal posterior-provenance snapshot.

The [DPL and RunManifest page](dpl_and_run_manifest.md) describes the two public
contracts. The [session tutorial](hero_session.md) shows the supported command.

## Current boundary

The normal river adapter supports only a Hero decision while facing an all-in,
so the legal actions are `FOLD` and `CALL`. It does not expand the other action
branches. The default CFR+ budget is 40 iterations with average delay 0 and no
checkpoints. Forty iterations is an alpha default, not a convergence guarantee.
