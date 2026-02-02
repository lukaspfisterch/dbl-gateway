"""Tests for context configuration loading and digest computation."""
import json
import pytest
from pathlib import Path
from dbl_gateway.config import (
    load_context_config,
    get_context_config,
    reset_config_cache,
    ContextConfig,
    _compute_config_digest,
)


@pytest.fixture
def sample_config(tmp_path: Path) -> Path:
    """Create a valid sample config file."""
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
    return path


def test_load_valid_config(sample_config: Path) -> None:
    """Load a valid config and verify fields."""
    cfg = load_context_config(sample_config)
    
    assert isinstance(cfg, ContextConfig)
    assert cfg.max_refs == 50
    assert cfg.empty_refs_policy == "DENY"
    assert cfg.expand_last_n == 10
    assert cfg.allow_execution_refs_for_prompt is True
    assert cfg.canonical_sort == "event_index_asc"
    assert cfg.enforce_scope_bound is True
    assert cfg.schema_version == "1"
    assert cfg.normalization_rules == ("FILTER_INTENT_ONLY", "SCOPE_BOUND", "SORT_CANONICAL")


def test_config_digest_stability(sample_config: Path) -> None:
    """Config digest must be stable across loads."""
    cfg1 = load_context_config(sample_config)
    cfg2 = load_context_config(sample_config)
    
    assert cfg1.config_digest == cfg2.config_digest
    assert cfg1.config_digest.startswith("sha256:")


def test_config_digest_changes_on_content_change(tmp_path: Path) -> None:
    """Config digest must change when content changes."""
    config_a = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
            "empty_refs_policy": "DENY",
            "expand_last_n": 10,
            "allow_execution_refs_for_prompt": True,
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
    }
    config_b = {
        "schema_version": "1",
        "context": {
            "max_refs": 51,  # Changed!
            "empty_refs_policy": "DENY",
            "expand_last_n": 10,
            "allow_execution_refs_for_prompt": True,
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
    }
    
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(config_a), encoding="utf-8")
    path_b.write_text(json.dumps(config_b), encoding="utf-8")
    
    cfg_a = load_context_config(path_a)
    cfg_b = load_context_config(path_b)
    
    assert cfg_a.config_digest != cfg_b.config_digest


def test_config_not_found_raises(tmp_path: Path) -> None:
    """Missing config file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_context_config(tmp_path / "nonexistent.json")


def test_invalid_schema_version_raises(tmp_path: Path) -> None:
    """Invalid schema_version raises ValueError."""
    config = {
        "schema_version": "999",
        "context": {"max_refs": 50, "empty_refs_policy": "DENY", "enforce_scope_bound": True},
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    
    with pytest.raises(ValueError, match="Unsupported schema_version"):
        load_context_config(path)


def test_invalid_empty_refs_policy_raises(tmp_path: Path) -> None:
    """Invalid empty_refs_policy raises ValueError."""
    config = {
        "schema_version": "1",
        "context": {"max_refs": 50, "empty_refs_policy": "INVALID", "enforce_scope_bound": True},
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    
    with pytest.raises(ValueError, match="empty_refs_policy"):
        load_context_config(path)


def test_frozen_config(sample_config: Path) -> None:
    """Config is immutable (frozen dataclass)."""
    cfg = load_context_config(sample_config)
    
    with pytest.raises(AttributeError):
        cfg.max_refs = 100  # type: ignore


def test_cache_returns_same_instance(sample_config: Path, monkeypatch) -> None:
    """get_context_config returns cached instance."""
    reset_config_cache()
    monkeypatch.setenv("DBL_GATEWAY_CONTEXT_CONFIG", str(sample_config))
    
    cfg1 = get_context_config()
    cfg2 = get_context_config()
    
    assert cfg1 is cfg2
    
    reset_config_cache()
