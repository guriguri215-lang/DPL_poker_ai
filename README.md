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

## Gate B v2 one-shot CLI

The packaged Windows-only Gate B v2 route is exposed as
`poker-xai-gate-b-v2`. It accepts one pinned bootstrap manifest on a fixed
local volume and stops after the initial attempt is durably `SEALED`:

```powershell
$python = (Get-Command python.exe).Source
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'
$env:PYTHONSAFEPATH = '1'
$env:PYTHONPYCACHEPREFIX = $python
$env:PYTHONPATH = (Resolve-Path .\src).Path
poker-xai-gate-b-v2 execute-once-v2 `
  --spec-parent 'D:\gate-b\approved' `
  --spec-parent-identity-scheme windows-volume-file-id-v1 `
  --spec-parent-serialization-profile windows-volume8-file16-lowerhex-v1 `
  --spec-parent-volume-id-hex 00000001 `
  --spec-parent-file-id-hex 0000000000000001 `
  --spec-name gate-b-v2-bootstrap.json `
  --expected-spec-sha256 <64-lowercase-hex-sha256> `
  --expected-spec-size-bytes <positive-size>
```

The five interpreter variables above are part of the v2 authorization
boundary. Run this command from the approved checkout root: `PYTHONPATH` must
contain exactly that checkout's resolved `src` directory and no other entry.
`PYTHONPYCACHEPREFIX` must resolve to the exact running `python.exe`,
which is a regular file rather than a cache directory. Together with disabled
bytecode writes, safe-path mode, and disabled user-site discovery, this makes
every repository `__pycache__` (including an ignored timestamp-valid cache)
unaddressable from process startup. The same boundary can be expressed for a
module launch as `python -B -P -s -X pycache_prefix=<exact-python.exe> -m
phase6.gate_b_v2_cli ...`. A process started without this source-only boundary
is rejected before the first v2 artifact read or reservation; it is never
re-executed implicitly.

UNC paths, device paths, alternate data streams, nested volume mounts, and
non-fixed target volumes are rejected before artifact open. Storage checks use
the mount that actually contains each target, not only its drive-letter root.
The parent volume/file identity, exact bootstrap bytes, two approved Git
commits, and the complete runtime source inventory must all match.

The console metadata may be packaged in a wheel, but production preflight is
deliberately repository-source-only: every executed Gate B module (including
the executor's calibration, exact-EV, sampling, and production-input helpers)
must originate from the approved checkout and match its declared Git commit.
A wheel or `site-packages` module origin therefore fails closed. Use an
editable/repository-source installation when invoking the packaged command.

A prepared route is single-consume; replay and either public reserve entry
point without its one-shot authorization fail closed. Replace the placeholders
only with independently approved evidence, and do not use this example against
production data.

## Status

Early development. Phase 0 (frozen contracts) lives in `src/poker_core`:
the DPL schema, the Reason Ontology and the RunManifest. Other packages are
placeholders filled in over later phases.

## Responsible use

This is a simulation-only research artefact. Do not use it to gain an unfair
advantage in real-money play or in violation of any poker platform's terms. See
`docs/responsible_use.md` (added with the docs phase).

## License

Apache-2.0. See [LICENSE](LICENSE).
