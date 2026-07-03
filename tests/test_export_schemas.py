"""Tests for JSON Schema export (cli/export_schemas.py -> schema_export)."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaError

from poker_core.schema_export import SCHEMA_MODELS, build_schemas, main, write_schemas


def test_build_schemas_covers_all_contracts():
    schemas = build_schemas()
    assert set(schemas) == set(SCHEMA_MODELS)
    for schema in schemas.values():
        # each is a valid JSON Schema document with an object at the root
        Draft202012Validator.check_schema(schema)
        assert schema["type"] == "object"


def test_write_schemas_emits_files(tmp_path):
    written = write_schemas(tmp_path)
    assert {p.name for p in written} == {
        "decision_provenance_log.schema.json",
        "run_manifest.schema.json",
        "reason_ontology.schema.json",
    }
    for path in written:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(loaded)


def test_cli_main_writes_to_out_dir(tmp_path, capsys):
    rc = main(["--out-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "decision_provenance_log.schema.json" in out
    assert (tmp_path / "run_manifest.schema.json").exists()


def test_exported_dpl_schema_validates_example(valid_dpl):
    schema = build_schemas()["decision_provenance_log"]
    # valid instance passes structural validation against the exported schema
    Draft202012Validator(schema).validate(valid_dpl)


def test_exported_dpl_schema_rejects_bad_enum(valid_dpl):
    schema = build_schemas()["decision_provenance_log"]
    valid_dpl["ev_estimate"]["ev_source"] = "made_up_source"
    with pytest.raises(JsonSchemaError):
        Draft202012Validator(schema).validate(valid_dpl)


def test_exported_dpl_schema_rejects_extra_property(valid_dpl):
    # extra="forbid" -> additionalProperties: false in the exported schema
    schema = build_schemas()["decision_provenance_log"]
    valid_dpl["unexpected"] = 1
    with pytest.raises(JsonSchemaError):
        Draft202012Validator(schema).validate(valid_dpl)


def test_exported_manifest_schema_validates_example(valid_manifest):
    schema = build_schemas()["run_manifest"]
    Draft202012Validator(schema).validate(valid_manifest)
