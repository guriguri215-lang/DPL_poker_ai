"""Build and write JSON Schemas for the frozen Phase-0 contracts.

Kept importable (separate from the thin ``cli/export_schemas.py`` wrapper) so
tests can build the schemas in-process and validate example instances against
them.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dpl_schema import DecisionProvenanceLog
from .reason_ontology import ReasonOntology
from .run_manifest import RunManifest

#: Contract name -> pydantic model exported as JSON Schema.
SCHEMA_MODELS: dict[str, type] = {
    "decision_provenance_log": DecisionProvenanceLog,
    "run_manifest": RunManifest,
    "reason_ontology": ReasonOntology,
}


def build_schemas() -> dict[str, dict]:
    """Return a mapping of contract name -> JSON Schema (draft 2020-12)."""
    return {name: model.model_json_schema() for name, model in SCHEMA_MODELS.items()}


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
    return 0
