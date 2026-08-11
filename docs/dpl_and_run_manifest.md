# DPL and RunManifest contracts

[Back to the documentation index](README.md).

## Decision Provenance Log

The Decision Provenance Log (DPL) is one validated JSON object per Hero decision.
The canonical models are in
[`poker_core.dpl_schema`](../src/poker_core/dpl_schema.py).

- DPL v1 (`1.0.0`) and v2 (`2.0.0`) are retained for historical, read-only
  loading. `load_dpl` and `load_dpl_json` dispatch on `schema_version`; they do
  not upgrade, convert, or relabel historical records.
- New session output uses DPL v3 (`3.0.0`). V3 adds required
  `base_strategy_provenance`, including the strategy table version, its source,
  and the SHA-256 of the solver configuration.
- Missing and unsupported schema versions are rejected.

The canonical validator enforces more than JSON shape. It checks policy
distributions, the SafetyMixer equation, LEAK/TRG/MIX reason namespaces, the
closed-world explanation allowlist, execution-sampling consistency, and EV
provenance. Exported JSON Schema describes structure and field constraints, but
does not replace those cross-field checks.

## RunManifest

The [`RunManifest`](../src/poker_core/run_manifest.py) is the audit and
reproducibility sidecar for a session. Schema version `1.0.0` records:

- code identity and invocation: Git commit/dirty state when available, package
  and Python versions, entry point, and the argument vector;
- DPL, ontology, cluster, strategy-table, and baseline-table versions;
- the required master seed;
- configuration references with roles and SHA-256 hashes;
- opponent identity/split and output references.

Structural loading is deliberately separate from compatibility checking. An old
manifest can remain structurally readable even when its recorded ontology is not
the current one; `ontology_matches_current()` reports that compatibility
separately. A JSON serialize/validate round trip preserves the manifest model.

## Version and Git provenance

The implementation in
[`poker_ai.runtime_provenance`](../src/poker_ai/runtime_provenance.py) does not
guess from the current directory or another installation:

- In the exact source or unpacked-sdist `src/poker_ai` layout, the package version
  comes only from that project's matching `pyproject.toml`.
- For an unpacked wheel, the version comes only from distribution metadata that
  locates the module that is actually executing.
- If authoritative package metadata cannot be resolved, the package version is
  `unknown`.
- Git commit and dirty state are used only when Git confirms the exact source
  project root. Otherwise they are `unknown` and `null`.

The CLI's `--version` output and the RunManifest package version reuse this same
project/distribution resolution contract.
