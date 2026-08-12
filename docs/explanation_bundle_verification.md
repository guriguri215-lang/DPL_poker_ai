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
are required.

After artifact integrity passes, the command uses the existing version-aware DPL
loader and existing explanation checker. It requires the DPLs and
`ExplanationDocument` objects to have equal counts and the same order, with one
matching session ID and hand ID at each position. Every available pair is
checked. Finally, the saved verifier summary must agree with the shared session
counts, checker totals, pass/fail result, pass rate, and artifact paths used by
the writer.

A successful command reports only these two result classes:

```text
artifact_integrity=passed references=4
explanation_checker=passed total=3 summary=consistent
```

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

This verifies artifact integrity and the in-repository explanation checker only.
It does not certify solver convergence, strategy safety or optimality, GTO
status, external or third-party validation, or reproduction of a research
result. The source session remains limited to a Hero decision while facing an
all-in. Its default 40 CFR+ iterations are a fixed early-alpha computation
budget, not a convergence guarantee.
