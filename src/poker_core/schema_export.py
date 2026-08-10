"""Build and write JSON Schemas for the frozen Phase-0 contracts.

Kept importable (separate from the thin ``cli/export_schemas.py`` wrapper) so
tests can build the schemas in-process and validate example instances against
them.

The exported schemas are **structural**: they capture field structure, enums,
numeric ranges and the reason-id namespace patterns, but not the cross-field
semantics (policy sums, alpha-mixing consistency, closed-world
``allowed_reason_ids``, ``leak_type`` <-> ontology label, git-SHA format). The
canonical validator is the pydantic models in :mod:`poker_core`. Each exported
schema carries this note in its ``$comment``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dpl_schema import DecisionProvenanceLog, DecisionProvenanceLogV1, DecisionProvenanceLogV2
from .reason_ontology import ReasonOntology
from .run_manifest import RunManifest
from .strategy_table import StrategyTable

#: Contract name -> pydantic model exported as JSON Schema.
SCHEMA_MODELS: dict[str, type] = {
    "decision_provenance_log": DecisionProvenanceLog,
    "decision_provenance_log_v1": DecisionProvenanceLogV1,
    "decision_provenance_log_v2": DecisionProvenanceLogV2,
    "run_manifest": RunManifest,
    "reason_ontology": ReasonOntology,
    "strategy_table": StrategyTable,
}

#: Note embedded in every exported schema and printed by the CLI.
STRUCTURAL_SCHEMA_NOTE = (
    "Structural schema exported from a pydantic contract in poker_core. It "
    "captures structure, enums, ranges and reason-id namespace patterns, but NOT "
    "cross-field semantics (policy sums, alpha-mixing consistency, closed-world "
    "allowed_reason_ids, leak_type<->ontology label). The pydantic model is the "
    "canonical validator."
)


def build_schemas() -> dict[str, dict]:
    """Return a mapping of contract name -> JSON Schema (draft 2020-12)."""
    schemas: dict[str, dict] = {}
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema()
        schema["$comment"] = STRUCTURAL_SCHEMA_NOTE
        schemas[name] = schema
    return schemas


def write_schemas(out_dir: Path | str) -> list[Path]:
    """Write each contract's JSON Schema to ``out_dir`` and return the paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in build_schemas().items():
        path = out / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    """Write every contract's JSON Schema to ``--out-dir`` (default docs/schemas)."""
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("docs/schemas"),
        help="directory to write *.schema.json files into (default: docs/schemas)",
    )
    args = parser.parse_args(argv)
    for path in write_schemas(args.out_dir):
        print(f"wrote {path}")
    print(f"note: {STRUCTURAL_SCHEMA_NOTE}")
    return 0
