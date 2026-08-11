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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and verification.
Use [GitHub Issues](https://github.com/guriguri215-lang/DPL_poker_ai/issues) to
report or discuss work, and submit changes through
[Pull requests](https://github.com/guriguri215-lang/DPL_poker_ai/pulls).
Please keep pull requests small and focused so they are easy to review and verify.

## Documentation

See the public [documentation index](docs/README.md) for the current
[architecture](docs/architecture.md), [DPL and RunManifest
contracts](docs/dpl_and_run_manifest.md), [normal Hero session
tutorial](docs/hero_session.md), and [responsible-use guidance](docs/responsible_use.md).

## Normal Hero session CLI

The distributed command runs the normal simulated Hero session and writes DPL
v3 JSONL plus its RunManifest sidecar:

```bash
poker-xai-run-session --seed 20260704 --hands 5 --out-dir experiments_output/quickstart
```

The historical source-checkout command is a compatibility wrapper around the
same packaged module:

```bash
python cli/run_session.py --seed 20260704 --hands 5 --out-dir experiments_output/quickstart
```

Identify either command without starting a session or creating output files:

```bash
poker-xai-run-session --version
python cli/run_session.py --version
```

Both forms reuse the same project/distribution version resolver as the
RunManifest. If authoritative metadata for the executing module is unavailable,
the displayed version is `unknown`.

RunManifest provenance follows an explicit no-guessing contract. When the
executing module is the exact `src/poker_ai` tree, the package version comes
from that project's `pyproject.toml`; its Git commit and dirty state are read
only when Git confirms the same project root. An installed or unpacked wheel
uses only distribution metadata that locates the executing module. An unpacked
sdist likewise uses its own `pyproject.toml`. If version metadata is unavailable,
`package_version` is `unknown`; outside a confirmed Git source checkout,
`git_commit` is `unknown` and `git_dirty` is `null`. The current working
directory and unrelated installations are never used as substitutes.

The manifest records `poker-xai-run-session` or `cli/run_session.py` as the
actual entrypoint and preserves the complete argument vector after the
entrypoint, before argument parsing. The normal river adapter is limited to
facing an all-in. CFR+ defaults to 40 iterations, which is not a convergence
guarantee.

## Gate B v2 one-shot CLI

The Windows-only Gate B v2 production route is started by the repository
launcher. It accepts one pinned bootstrap manifest on a fixed local volume and
stops after the initial attempt is durably `SEALED`:

```powershell
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'
$env:PYTHONSAFEPATH = '1'
$env:PYTHONPYCACHEPREFIX = $python
$env:PYTHONPATH = (Resolve-Path .\src).Path
& $python -S -B -P -s -X "pycache_prefix=$python" -m gate_b_v2_launcher execute-once-v2 `
  --spec-parent 'D:\gate-b\approved' `
  --spec-parent-identity-scheme windows-volume-file-id-v1 `
  --spec-parent-serialization-profile windows-volume8-file16-lowerhex-v1 `
  --spec-parent-volume-id-hex 00000001 `
  --spec-parent-file-id-hex 0000000000000001 `
  --spec-name gate-b-v2-bootstrap.json `
  --expected-spec-sha256 <64-lowercase-hex-sha256> `
  --expected-spec-size-bytes <positive-size>
```

The five interpreter variables and the exact `-S -B -P -s -X pycache_prefix=<exact-python.exe>`
flags above are part of the v2 authorization
boundary. Run the command from the approved checkout root with a copied virtual
environment: `PYTHONPATH` must
contain exactly that checkout's resolved `src` directory and no other entry.
`-S` prevents `site`, every venv `.pth` file, `sitecustomize`, and
`usercustomize` from running during process startup. The stdlib-only launcher
checks that closed startup before it appends exactly the running venv's resolved
`site-packages` path; it never calls `site` to process startup hooks.
`PYTHONPYCACHEPREFIX` must resolve to the exact running `python.exe`, which is a
regular copied file rather than a cache directory. Together with disabled
bytecode writes, safe-path mode, and disabled user-site discovery, this makes
every repository `__pycache__` (including an ignored timestamp-valid cache)
unaddressable from process startup. A process started without this source-only
boundary is rejected before the first v2 artifact read or reservation; it is
never re-executed implicitly.

UNC paths, device paths, alternate data streams, nested volume mounts, and
non-fixed target volumes are rejected before artifact open. Storage checks use
the mount that actually contains each target, not only its drive-letter root.
The parent volume/file identity, exact bootstrap bytes, two approved Git
commits, and the complete runtime source inventory must all match.

The `poker-xai-gate-b-v2` console metadata may be packaged in a wheel, but a
console script cannot retroactively prevent Python startup hooks and is not a
production invocation. It fails preflight unless its process already has the
exact closed startup above. Production preflight is deliberately
repository-source-only: every executed Gate B module (including
the executor's calibration, exact-EV, sampling, and production-input helpers)
must originate from the approved checkout and match its declared Git commit.
A wheel or `site-packages` module origin therefore fails closed. Use an
editable/repository-source installation when invoking the packaged command.

A prepared route is single-consume; replay and either public reserve entry
point without its one-shot authorization fail closed. Replace the placeholders
only with independently approved evidence, and do not use this example against
production data.

## Status

Early alpha, simulation-only development. The frozen core contracts now use DPL
v3 with read-only DPL v1/v2 loading compatibility, alongside the Reason Ontology
and RunManifest. Normal Hero sessions use CFR+ to produce exact combo- and
position-specific `vs_bet` policies for facing-all-in river decisions; the
default is 40 iterations, average delay 0, and no checkpoints, with the observed
all-in bet matched to the solver bet size. Leak detection, SafetyMixer,
opponent-synthesis/node-lock, template explanation, and Phase 6 evaluation and
Gate B v2 contracts are implemented. The river adapter remains limited to
facing an all-in, has a higher computation cost than the retained stub, and 40
iterations is not a convergence guarantee.

## Responsible use

This is a simulation-only research artefact. Do not use it to gain an unfair
advantage in real-money play or in violation of any poker platform's terms. See
[Responsible use](docs/responsible_use.md).

## Distribution

Release artifacts are distributed only through GitHub Releases. This project
does not publish to PyPI or other package indexes. Starting with `0.1.0a4`, each
release attaches only the wheel, sdist, `artifact-manifest.json`, and
`SHA256SUMS` taken unchanged from the same verified release-workflow bundle.

## License

Apache-2.0. See [LICENSE](LICENSE).
