"""Tests for context configuration loading and digest computation."""
import json
import pytest
from pathlib import Path
from dbl_gateway.config import (
    BoundaryConfig,
    allowed_tool_families_for_mode,
    load_context_config,
    load_boundary_config,
    get_context_config,
    get_boundary_config,
    reset_config_cache,
    ContextConfig,
    reset_boundary_config_cache,
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
    assert cfg.high_risk_context_admit_mode == "metadata_only"
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


@pytest.fixture
def sample_boundary_config(tmp_path: Path) -> Path:
    config = {
        "schema_version": "1",
        "boundary_version": "1",
        "exposure_mode": "operator",
        "admission": {
            "public": {
                "allow_artifact_handle": False,
                "allow_declared_refs": False,
                "max_declared_tools": 0,
                "max_budget": {
                    "max_tokens": 4096,
                    "max_duration_ms": 30000,
                },
            },
        },
        "tool_policy": {
            "families": {
                "exec_like": ["code.*"],
                "web_read": ["web.*"],
                "retrieval": ["search.*"],
            },
            "matrix": {
                "public": {
                    "anonymous": ["web_read"],
                    "user": ["web_read", "retrieval"],
                    "operator": ["web_read", "retrieval"],
                    "internal": ["web_read", "retrieval"],
                },
                "operator": {
                    "anonymous": [],
                    "user": ["web_read", "retrieval"],
                    "operator": ["web_read", "retrieval"],
                    "internal": ["web_read", "retrieval"],
                },
                "demo": {
                    "*": ["*"],
                },
            },
        },
        "surface_rules": {
            "healthz": "public",
            "capabilities": "public",
            "surfaces": "operator",
            "ui_root": "demo",
        },
    }
    path = tmp_path / "boundary.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_load_valid_boundary_config(sample_boundary_config: Path) -> None:
    cfg = load_boundary_config(sample_boundary_config)

    assert isinstance(cfg, BoundaryConfig)
    assert cfg.boundary_version == "1"
    assert cfg.exposure_mode == "operator"
    assert cfg.surface_rules["surfaces"] == "operator"
    assert cfg.admission.public_allow_artifact_handle is False
    assert cfg.admission.public_max_declared_tools == 0
    assert cfg.tool_policy.families["exec_like"] == ("code.*",)
    assert allowed_tool_families_for_mode(cfg, trust_class="internal") == ("web_read", "retrieval")
    assert allowed_tool_families_for_mode(cfg, mode="public", trust_class="anonymous") == ("web_read",)
    assert cfg.config_digest.startswith("sha256:")


def test_boundary_config_digest_changes_on_content_change(tmp_path: Path) -> None:
    config_a = {
        "schema_version": "1",
        "boundary_version": "1",
        "exposure_mode": "public",
        "admission": {
            "public": {
                "allow_artifact_handle": False,
                "allow_declared_refs": False,
                "max_declared_tools": 0,
                "max_budget": {"max_tokens": 4096, "max_duration_ms": 30000},
            },
        },
        "tool_policy": {
            "families": {"web_read": ["web.*"]},
            "matrix": {
                "public": {
                    "anonymous": ["web_read"],
                    "user": ["web_read"],
                    "operator": ["web_read"],
                    "internal": ["web_read"],
                },
                "operator": {
                    "anonymous": [],
                    "user": ["web_read"],
                    "operator": ["web_read"],
                    "internal": ["web_read"],
                },
                "demo": {"*": ["*"]},
            },
        },
        "surface_rules": {"healthz": "public"},
    }
    config_b = {
        "schema_version": "1",
        "boundary_version": "1",
        "exposure_mode": "demo",
        "admission": {
            "public": {
                "allow_artifact_handle": False,
                "allow_declared_refs": False,
                "max_declared_tools": 0,
                "max_budget": {"max_tokens": 4096, "max_duration_ms": 30000},
            },
        },
        "tool_policy": {
            "families": {"web_read": ["web.*"]},
            "matrix": {
                "public": {
                    "anonymous": ["web_read"],
                    "user": ["web_read"],
                    "operator": ["web_read"],
                    "internal": ["web_read"],
                },
                "operator": {
                    "anonymous": [],
                    "user": ["web_read"],
                    "operator": ["web_read"],
                    "internal": ["web_read"],
                },
                "demo": {"*": ["*"]},
            },
        },
        "surface_rules": {"healthz": "public"},
    }
    path_a = tmp_path / "boundary-a.json"
    path_b = tmp_path / "boundary-b.json"
    path_a.write_text(json.dumps(config_a), encoding="utf-8")
    path_b.write_text(json.dumps(config_b), encoding="utf-8")

    cfg_a = load_boundary_config(path_a)
    cfg_b = load_boundary_config(path_b)

    assert cfg_a.config_digest != cfg_b.config_digest


def test_boundary_config_cache_returns_same_instance(
    sample_boundary_config: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_boundary_config_cache()
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", str(sample_boundary_config))

    cfg1 = get_boundary_config()
    cfg2 = get_boundary_config()

    assert cfg1 is cfg2

    reset_boundary_config_cache()
