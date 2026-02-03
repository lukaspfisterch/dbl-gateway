"""
Context configuration loader for DBL Gateway.

Loads context.json, validates against schema, computes config_digest.
Config is loaded once at startup and immutable during runtime.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Mapping

from dbl_core.events.canonical import canonicalize_value, json_dumps
from hashlib import sha256


__all__ = [
    "ContextConfig",
    "JobRuntimeConfig",
    "load_context_config",
    "get_context_config",
    "load_job_runtime_config",
    "get_job_runtime_config",
]

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "context.json"


@dataclass(frozen=True)
class ContextConfig:
    """Immutable context configuration."""
    
    # Core settings
    max_refs: int
    empty_refs_policy: Literal["DENY", "EXPAND_LAST_N", "ALLOW_EMPTY"]
    expand_last_n: int
    allow_execution_refs_for_prompt: bool
    canonical_sort: Literal["event_index_asc", "event_index_desc", "none"]
    enforce_scope_bound: bool
    
    # Normalization rules
    normalization_rules: tuple[str, ...]

    # Conditional rules
    expand_thread_history_enabled: bool
    
    # Schema version
    schema_version: str
    
    # Computed digest (for audit/replay)
    config_digest: str
    
    # Raw config for serialization
    _raw: Mapping[str, Any]


def load_context_config(path: Path | None = None) -> ContextConfig:
    """
    Load context configuration from JSON file.
    
    Args:
        path: Path to context.json. Defaults to config/context.json.
        
    Returns:
        Immutable ContextConfig with computed digest.
        
    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config is invalid.
    """
    config_path = path or _resolve_config_path()
    
    if not config_path.exists():
        raise FileNotFoundError(f"Context config not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    
    return _parse_config(raw)


def _resolve_config_path() -> Path:
    """Resolve config path from ENV or default."""
    env_path = os.environ.get("DBL_GATEWAY_CONTEXT_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def _parse_config(raw: Mapping[str, Any]) -> ContextConfig:
    """Parse and validate raw config dict."""
    schema_version = raw.get("schema_version")
    if schema_version != "1":
        raise ValueError(f"Unsupported schema_version: {schema_version}")
    
    context = raw.get("context")
    if not isinstance(context, Mapping):
        raise ValueError("context must be an object")
    
    # Required fields
    max_refs = context.get("max_refs")
    if not isinstance(max_refs, int) or max_refs < 1:
        raise ValueError("max_refs must be a positive integer")
    
    empty_refs_policy = context.get("empty_refs_policy")
    if empty_refs_policy not in ("DENY", "EXPAND_LAST_N", "ALLOW_EMPTY"):
        raise ValueError("empty_refs_policy must be DENY, EXPAND_LAST_N, or ALLOW_EMPTY")
    
    expand_last_n = context.get("expand_last_n", 10)
    if not isinstance(expand_last_n, int) or expand_last_n < 1:
        raise ValueError("expand_last_n must be a positive integer")
    
    allow_execution = context.get("allow_execution_refs_for_prompt", True)
    if not isinstance(allow_execution, bool):
        raise ValueError("allow_execution_refs_for_prompt must be boolean")
    
    canonical_sort = context.get("canonical_sort", "event_index_asc")
    if canonical_sort not in ("event_index_asc", "event_index_desc", "none"):
        raise ValueError("canonical_sort must be event_index_asc, event_index_desc, or none")
    
    enforce_scope = context.get("enforce_scope_bound", True)
    if not isinstance(enforce_scope, bool):
        raise ValueError("enforce_scope_bound must be boolean")
    
    # Normalization rules
    normalization = raw.get("normalization", {})
    rules = normalization.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("normalization.rules must be a list")

    conditional_rules = normalization.get("conditional_rules", {})
    if not isinstance(conditional_rules, Mapping):
        conditional_rules = {}
    expand_rule = conditional_rules.get("EXPAND_THREAD_HISTORY", {})
    if not isinstance(expand_rule, Mapping):
        expand_rule = {}
    expand_enabled = bool(expand_rule.get("enabled", False))
    
    # Compute config_digest
    config_digest = _compute_config_digest(raw)
    
    return ContextConfig(
        max_refs=max_refs,
        empty_refs_policy=empty_refs_policy,
        expand_last_n=expand_last_n,
        allow_execution_refs_for_prompt=allow_execution,
        canonical_sort=canonical_sort,
        enforce_scope_bound=enforce_scope,
        normalization_rules=tuple(rules),
        expand_thread_history_enabled=expand_enabled,
        schema_version=str(schema_version),
        config_digest=config_digest,
        _raw=raw,
    )


def _compute_config_digest(raw: Mapping[str, Any]) -> str:
    """
    Compute canonical digest of config.
    
    Uses dbl-core canonicalization for determinism.
    """
    canonical = canonicalize_value(raw)
    canonical_bytes = json_dumps(canonical).encode("utf-8")
    hex_digest = sha256(canonical_bytes).hexdigest()
    return f"sha256:{hex_digest}"


@lru_cache(maxsize=1)
def get_context_config() -> ContextConfig:
    """
    Get cached context configuration.
    
    Loads once at first call, immutable thereafter.
    """
    return load_context_config()


def reset_config_cache() -> None:
    """Reset config cache. Only for testing."""
    get_context_config.cache_clear()


@dataclass(frozen=True)
class JobRuntimeConfig:
    queue_max: int
    concurrency_ingest: int
    concurrency_embed: int
    concurrency_index: int
    concurrency_llm: int
    llm_wall_clock_s: int


def _read_int_env(names: list[str], *, default: int, minimum: int = 1) -> int:
    for name in names:
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        return max(minimum, value)
    return max(minimum, default)


def load_job_runtime_config() -> JobRuntimeConfig:
    queue_max = _read_int_env(
        ["DBL_JOB_QUEUE_MAX", "DBL_GATEWAY_WORK_QUEUE_MAX"],
        default=100,
        minimum=1,
    )
    return JobRuntimeConfig(
        queue_max=queue_max,
        concurrency_ingest=_read_int_env(["DBL_JOB_CONCURRENCY_INGEST"], default=2, minimum=1),
        concurrency_embed=_read_int_env(["DBL_JOB_CONCURRENCY_EMBED"], default=1, minimum=1),
        concurrency_index=_read_int_env(["DBL_JOB_CONCURRENCY_INDEX"], default=1, minimum=1),
        concurrency_llm=_read_int_env(["DBL_JOB_CONCURRENCY_LLM"], default=1, minimum=1),
        llm_wall_clock_s=_read_int_env(["DBL_LLM_WALL_CLOCK_S"], default=60, minimum=1),
    )


@lru_cache(maxsize=1)
def get_job_runtime_config() -> JobRuntimeConfig:
    return load_job_runtime_config()
