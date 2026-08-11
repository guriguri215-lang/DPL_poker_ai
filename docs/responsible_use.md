# Responsible use

[Back to the documentation index](README.md).

`poker-xai` is an early-alpha, simulation-only research framework for studying
explainable and auditable poker decisions. It is not a real-time playing bot.

Use it for reproducible simulations, contract validation, solver research, and
faithfulness evaluation. Do not use or adapt it to gain an unfair advantage in
real-money play, to violate a poker platform's rules, or to automate play against
live opponents. The repository intentionally contains no screen scraping,
poker-site API integration, real-time input, or live-play automation.

DPL and RunManifest records improve auditability; they do not prove that a
strategy is safe, fair, optimal, or converged. The normal Hero adapter is limited
to facing an all-in, and its 40-iteration CFR+ default is not a convergence
guarantee. Keep those limitations with any result, demonstration, or downstream
explanation.

Use only synthetic or otherwise authorized inputs, review generated artifacts
before sharing them, and follow applicable law, platform terms, and research
ethics. Report project defects through the repository's
[GitHub Issues](https://github.com/guriguri215-lang/DPL_poker_ai/issues).
