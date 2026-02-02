"""Tests for config-driven context building (Step 1)."""
import json
import pytest
from pathlib import Path
from typing import Any, Mapping

from dbl_gateway.context_builder import build_context, ContextArtifacts
from dbl_gateway.config import load_context_config, reset_config_cache, ContextConfig


@pytest.fixture
def sample_config(tmp_path: Path) -> ContextConfig:
    """Create a sample config for testing."""
    config = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
            "empty_refs_policy": "DENY",
            "expand_last_n": 10,
            "allow_execution_refs_for_prompt": True,
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
        "normalization": {
            "rules": ["FILTER_INTENT_ONLY", "SCOPE_BOUND", "SORT_CANONICAL"],
        },
    }
    path = tmp_path / "context.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return load_context_config(path)


@pytest.fixture
def valid_payload() -> Mapping[str, Any]:
    """Valid payload for context building."""
    return {
        "thread_id": "thread-1",
        "turn_id": "turn-1",
        "parent_turn_id": None,
        "message": "Hello, world!",
    }


def test_build_context_uses_config(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """build_context uses provided config."""
    artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    assert isinstance(artifacts, ContextArtifacts)
    assert artifacts.config_digest == sample_config.config_digest
    assert artifacts.config_digest.startswith("sha256:")


def test_normalization_record_materialized(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """NormalizationRecord is materialized in ContextSpec."""
    artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    normalization = artifacts.context_spec["retrieval"]["normalization"]
    
    assert normalization["applied_rules"] == ["FILTER_INTENT_ONLY", "SCOPE_BOUND", "SORT_CANONICAL"]
    assert normalization["boundary_version"] == "1"
    assert normalization["config_digest"] == sample_config.config_digest


def test_ordering_from_config(tmp_path: Path, valid_payload: Mapping[str, Any]) -> None:
    """assembly_rules.ordering comes from config.canonical_sort."""
    config = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
            "empty_refs_policy": "DENY",
            "canonical_sort": "event_index_desc",  # Different ordering
            "enforce_scope_bound": True,
        },
    }
    path = tmp_path / "context.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    cfg = load_context_config(path)
    
    artifacts = build_context(valid_payload, intent_type="chat.message", config=cfg)
    
    assert artifacts.context_spec["assembly_rules"]["ordering"] == "event_index_desc"


def test_context_digest_changes_with_config(tmp_path: Path, valid_payload: Mapping[str, Any]) -> None:
    """context_digest changes when config changes (via normalization record)."""
    cfg_a = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
            "empty_refs_policy": "DENY",
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
        "normalization": {"rules": ["A"]},
    }
    cfg_b = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
            "empty_refs_policy": "DENY",
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
        "normalization": {"rules": ["B"]},  # Different rule!
    }
    
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(cfg_a), encoding="utf-8")
    path_b.write_text(json.dumps(cfg_b), encoding="utf-8")
    
    config_a = load_context_config(path_a)
    config_b = load_context_config(path_b)
    
    artifacts_a = build_context(valid_payload, intent_type="chat.message", config=config_a)
    artifacts_b = build_context(valid_payload, intent_type="chat.message", config=config_b)
    
    # Context digest MUST differ because normalization.applied_rules are in the digest scope
    assert artifacts_a.context_digest != artifacts_b.context_digest
    
    # Config digests also differ
    assert artifacts_a.config_digest != artifacts_b.config_digest


def test_resolved_refs_empty_initially(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """resolved_refs is empty until Step 2 implements resolution."""
    artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    assert artifacts.context_spec["retrieval"]["resolved_refs"] == []
    assert artifacts.assembled_context["assembled_from"] == []


def test_normative_input_digests_empty_initially(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """normative_input_digests is empty until Step 2 implements resolution."""
    artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    assert artifacts.assembled_context["normative_input_digests"] == []


def test_context_digest_stable_same_inputs(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """Same inputs produce same context_digest (determinism)."""
    artifacts_1 = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    artifacts_2 = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    assert artifacts_1.context_digest == artifacts_2.context_digest
    assert artifacts_1.config_digest == artifacts_2.config_digest


def test_schema_version_updated(sample_config: ContextConfig, valid_payload: Mapping[str, Any]) -> None:
    """ContextSpec uses new schema version."""
    artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
    
    assert artifacts.context_spec["assembly_rules"]["schema_version"] == "ctxspec.2"
