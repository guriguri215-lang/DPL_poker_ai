# Verify a saved Hero explanation bundle

[Back to the documentation index](README.md).

`poker-xai-verify-explanation-bundle` rechecks an already saved, normal Hero
explanation bundle from its RunManifest. It is offline and read-only: it does not
run a session or solver, contact a network service, install anything, or create,
replace, or repair bundle files.

```text
poker-xai-verify-explanation-bundle --manifest experiments_output/quickstart/S20260704.manifest.json
```

The command accepts the normal and public leaky-fixture bundles written by
`poker-xai-run-session --explanations`, including saved `0.1.0a8`-format
bundles. The manifest's directory is the bundle root. Verification fails closed
unless every existing RunManifest `ArtifactRef` has a normalized relative POSIX
path inside that root, a SHA-256 digest, and a readable file with exactly that
digest. The DPL JSONL, explanations JSONL, verifier-summary JSON, and manifest
are required. Current normal Hero bundles also carry the hashed post-session
evaluation artifact; saved older bundles without it remain supported.

After artifact integrity passes, the command uses the existing version-aware DPL
loader and existing explanation checker. It requires the DPLs and
`ExplanationDocument` objects to have equal counts and the same order, with one
matching session ID and hand ID at each position. Every available pair is
checked. Finally, the saved verifier summary must agree with the shared session
counts, checker totals, pass/fail result, pass rate, and artifact paths used by
the writer. When a post-session evaluation is present, the verifier applies the
same captured-bytes validation as the successor-session consumer: exactly one
reference, canonical JSON, supported schema and artifact type, the complete
evaluation and next-settings shapes, matching session and opponent identities,
finite metrics, valid counts and notes, and existing configuration ranges.

A successful command reports only these two result classes:

```text
artifact_integrity=passed references=5
explanation_checker=passed total=3 summary=consistent
```

An older four-reference bundle reports `references=4` instead.

## Read the verified evaluation and next-session settings

The default command above keeps its existing two-line output. Add the explicit
display opt-in only when you want to read the current bundle's saved
post-session result:

```text
poker-xai-verify-explanation-bundle --manifest experiments_output/quickstart/S20260704.manifest.json --show-evaluation
```

After the same two verification lines, the command emits a fixed sequence of
`key=value` lines for these existing fields:

- `evaluation.leak_detection_accuracy`;
- `evaluation.average_estimation_error`;
- `evaluation.exploit_ev_gain_vs_base`;
- `evaluation.over_adjustment_count` and
  `evaluation.under_adjustment_count`;
- `evaluation.explanation_validity_score`;
- every field in the existing
  `next_session.leak_detector_config`, followed by
  `next_session.safety_alpha` and `next_session.epsilon`.

Numeric values are not rounded for display. String values use JSON quoting so a
stored string cannot create a misleading extra output line. Hashes, local
paths, answer-key data, internal diagnostic notes, and session/opponent
identities are not printed.

Nothing is printed until the manifest, every referenced artifact and digest,
the DPL/explanation pairing and checker result, the saved verifier summary, the
post-session schema and session/opponent binding, and all next-session settings
have succeeded. The command obtains the displayed values from the same captured
artifact bytes used by those checks; it does not verify one filesystem state
and then reread another. A missing, duplicated, changed, malformed, or
mismatched post-session artifact therefore returns nonzero with no partial
success output and leaves the bundle unchanged.

Saved older bundles without a post-session artifact remain valid with no flag.
They cannot provide this display: `--show-evaluation` fails clearly rather than
printing only part of the result.

This opt-in confirms that the displayed values are the supported, hash-bound
values saved with the verified bundle. It does not reveal the answer key, rerun
the session or solver, independently recompute the evaluation from raw events,
validate the evaluation methodology against external evidence, or certify that
the proposed settings are profitable or safe.

On failure, the command emits no partial success result and returns nonzero. It
reports a category and target filename without writing output or changing the
target bundle.

The same read-only operation is available as a Python API:

```python
from poker_ai import verify_saved_explanation_bundle

result = verify_saved_explanation_bundle(
    "experiments_output/quickstart/S20260704.manifest.json"
)
```

This verifies artifact integrity, saved-artifact semantics, and the
in-repository explanation checker only. It does not certify solver convergence,
strategy safety or optimality, GTO status, external or third-party validation,
or reproduction of a research result. The source session remains limited to a
Hero decision while facing an all-in. Its default 40 CFR+ iterations are a fixed
early-alpha computation budget, not a convergence guarantee.
