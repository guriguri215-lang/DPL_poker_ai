# Responsible use

[Back to the documentation index](README.md).

`DPL_poker_ai` is the repository name; the Python distribution and CLI use
`poker-xai`. It is an early-alpha, simulation-only research framework for
studying explainable and auditable poker decisions, not a real-time playing bot.

Use it for reproducible simulations, contract validation, solver research, and
faithfulness evaluation. Do not use or adapt it to gain an unfair advantage in
real-money play, to violate a poker platform's rules, or to automate play against
live opponents. The repository intentionally contains no screen scraping,
poker-site API integration, real-time input, or live-play automation.

DPL and RunManifest records and the separate in-repository explanation verifier
improve auditability. They do not prove strategy safety, fairness or optimality,
solver convergence, exact equilibrium, GTO status, EV superiority, external
validation, or independent third-party reproducibility. SafetyMixer implements
the convex formula `(1-alpha)*base + alpha*exploit`; neither its name nor that
formula is a safety proof. The normal Hero adapter is limited to facing an
all-in, and its 40-iteration CFR+ default produces a finite-iteration combo- and
position-specific policy with no convergence, exact-equilibrium, or GTO
certificate. Keep those limitations with any result, demonstration, or
downstream explanation.

Gate B v2 is an implemented, Windows-only, one-shot validation route for approved
local artifacts. “Production” is an internal route label, not a
production-readiness or independent-security-certification claim.

Use only synthetic or otherwise authorized inputs, review generated artifacts
before sharing them, and follow applicable law, platform terms, and research
ethics. Report project defects through the repository's
[GitHub Issues](https://github.com/guriguri215-lang/DPL_poker_ai/issues).
