"""Tests for the Reason Ontology loader (ADR-0001)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from poker_core.reason_ontology import (
    VALID_NAMESPACES,
    ReasonOntology,
    get_ontology,
    load_ontology,
    namespace_of,
)


def test_packaged_ontology_loads_and_is_cached():
    onto = get_ontology()
    assert onto is get_ontology()  # lru_cache returns the same instance
    assert onto.ontology_version == "1.1.0"


def test_namespace_counts_match_spec():
    onto = get_ontology()
    assert len(onto.ids_in("LEAK")) == 8  # AI Spec 6.6 R001..R008
    assert len(onto.ids_in("TRG")) == 3  # AI Spec 6.10 R007..R009
    assert len(onto.ids_in("MIX")) == 2  # AI Spec 6.10 R010 + ADR-0018
    assert len(onto.reasons) == 13
    assert "MIX_EPSILON" in onto.ids_in("MIX")


def test_every_id_prefix_matches_declared_namespace():
    onto = get_ontology()
    for entry in onto.reasons:
        assert namespace_of(entry.id) == entry.namespace
        assert entry.namespace in VALID_NAMESPACES


def test_is_valid_enforces_namespace():
    onto = get_ontology()
    assert onto.is_valid("LEAK_R001")
    assert onto.is_valid("LEAK_R001", namespace="LEAK")
    # right id, wrong namespace -> invalid
    assert not onto.is_valid("LEAK_R001", namespace="TRG")
    # unknown id -> invalid
    assert not onto.is_valid("LEAK_R999")
    assert not onto.has("LEAK_R999")


def test_get_and_labels_are_unique():
    onto = get_ontology()
    assert onto.get("LEAK_R007").label == "check_back_too_often"
    labels = [e.label for e in onto.reasons]
    assert len(labels) == len(set(labels))


def test_namespace_of_without_underscore():
    assert namespace_of("bogus") == ""


def test_duplicate_ids_rejected():
    entry = {
        "id": "LEAK_R001",
        "namespace": "LEAK",
        "label": "river_large_bet_overfold",
        "description": "x",
        "source_ref": "y",
    }
    with pytest.raises(ValidationError, match="duplicate reason id"):
        ReasonOntology.model_validate(
            {
                "schema_version": "1.0.0",
                "ontology_version": "1.0.0",
                "namespaces": {"LEAK": {"description": "d"}},
                "reasons": [entry, dict(entry)],
            }
        )


def test_prefix_must_match_namespace():
    with pytest.raises(ValidationError, match="namespace prefix"):
        ReasonOntology.model_validate(
            {
                "schema_version": "1.0.0",
                "ontology_version": "1.0.0",
                "namespaces": {"LEAK": {"description": "d"}},
                "reasons": [
                    {
                        "id": "TRG_R001",  # says LEAK namespace but TRG_ prefix
                        "namespace": "LEAK",
                        "label": "x",
                        "description": "y",
                        "source_ref": "z",
                    }
                ],
            }
        )


def test_undeclared_namespace_rejected():
    with pytest.raises(ValidationError):
        ReasonOntology.model_validate(
            {
                "schema_version": "1.0.0",
                "ontology_version": "1.0.0",
                "namespaces": {"BOGUS": {"description": "d"}},
                "reasons": [],
            }
        )


def test_reason_using_undeclared_namespace_rejected():
    # MIX_ prefix is valid, but MIX is not declared in `namespaces` here.
    with pytest.raises(ValidationError, match="not declared"):
        ReasonOntology.model_validate(
            {
                "schema_version": "1.0.0",
                "ontology_version": "1.0.0",
                "namespaces": {"LEAK": {"description": "d"}},
                "reasons": [
                    {
                        "id": "MIX_R001",
                        "namespace": "MIX",
                        "label": "x",
                        "description": "y",
                        "source_ref": "z",
                    }
                ],
            }
        )


def test_load_ontology_reloads_packaged_file():
    onto = load_ontology()
    assert isinstance(onto, ReasonOntology)
    # reloading the packaged file yields content identical to the cached copy
    assert onto == get_ontology()
