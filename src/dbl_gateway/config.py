"""
Context configuration loader for DBL Gateway.

Loads context.json, validates against schema, computes config_digest.
Config is loaded once at startup and immutable during runtime.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse
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

    # Handle content fetch (Workbench resolver)
    allow_handle_content_fetch: bool
    workbench_resolver_url: str | None
    workbench_auth_bearer_token: str | None
    workbench_fetch_timeout_ms: int
    workbench_max_bytes: int
    workbench_admit_kinds: tuple[str, ...]
    
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

    handle_cfg = context.get("handle_content_fetch", {})
    if not isinstance(handle_cfg, Mapping):
        handle_cfg = {}
    allow_handle_fetch = handle_cfg.get("allow_handle_content_fetch", False)
    if not isinstance(allow_handle_fetch, bool):
        raise ValueError("handle_content_fetch.allow_handle_content_fetch must be boolean")
    resolver_url = handle_cfg.get("workbench_resolver_url")
    if resolver_url is not None and not isinstance(resolver_url, str):
        raise ValueError("handle_content_fetch.workbench_resolver_url must be string when provided")
    auth_token = handle_cfg.get("workbench_auth_bearer_token")
    if auth_token is not None and not isinstance(auth_token, str):
        raise ValueError("handle_content_fetch.workbench_auth_bearer_token must be string when provided")
    fetch_timeout_ms = handle_cfg.get("workbench_fetch_timeout_ms", 1500)
    if not isinstance(fetch_timeout_ms, int) or fetch_timeout_ms < 100:
        raise ValueError("handle_content_fetch.workbench_fetch_timeout_ms must be int >= 100")
    max_bytes = handle_cfg.get("workbench_max_bytes", 512000)
    if not isinstance(max_bytes, int) or max_bytes < 1024:
        raise ValueError("handle_content_fetch.workbench_max_bytes must be int >= 1024")
    admit_kinds = handle_cfg.get("workbench_admit_kinds", ["extracted_text", "summary"])
    if not isinstance(admit_kinds, list) or not all(isinstance(k, str) for k in admit_kinds):
        raise ValueError("handle_content_fetch.workbench_admit_kinds must be list[str]")

    # Env overrides (explicit)
    def _env_bool(name: str) -> bool | None:
        raw_val = os.getenv(name)
        if raw_val is None:
            return None
        val = raw_val.strip().lower()
        if val in ("1", "true", "yes", "on"):
            return True
        if val in ("0", "false", "no", "off"):
            return False
        return None

    def _env_int(name: str) -> int | None:
        raw_val = os.getenv(name)
        if raw_val is None:
            return None
        try:
            return int(raw_val.strip())
        except ValueError:
            return None

    env_allow = _env_bool("ALLOW_HANDLE_CONTENT_FETCH")
    if env_allow is not None:
        allow_handle_fetch = env_allow
    env_url = os.getenv("WORKBENCH_RESOLVER_URL")
    if env_url is not None and env_url.strip():
        resolver_url = env_url.strip()
    env_token = os.getenv("WORKBENCH_AUTH_BEARER_TOKEN")
    if env_token is not None:
        auth_token = env_token.strip()
    env_timeout = _env_int("WORKBENCH_FETCH_TIMEOUT_MS")
    if env_timeout is not None and env_timeout >= 100:
        fetch_timeout_ms = env_timeout
    env_max = _env_int("WORKBENCH_MAX_BYTES")
    if env_max is not None and env_max >= 1024:
        max_bytes = env_max
    env_kinds = os.getenv("WORKBENCH_ADMIT_KINDS")
    if env_kinds is not None:
        items = [k.strip() for k in env_kinds.split(",") if k.strip()]
        if items:
            admit_kinds = items
    
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
    
    # Basic scheme guard for resolver URL (trusted operator config)
    if isinstance(resolver_url, str) and resolver_url.strip():
        parsed = urlparse(resolver_url.strip())
        if parsed.scheme not in ("http", "https"):
            raise ValueError("handle_content_fetch.workbench_resolver_url must be http(s)")

    return ContextConfig(
        max_refs=max_refs,
        empty_refs_policy=empty_refs_policy,
        expand_last_n=expand_last_n,
        allow_execution_refs_for_prompt=allow_execution,
        canonical_sort=canonical_sort,
        enforce_scope_bound=enforce_scope,
        allow_handle_content_fetch=allow_handle_fetch,
        workbench_resolver_url=resolver_url.strip() if isinstance(resolver_url, str) and resolver_url.strip() else None,
        workbench_auth_bearer_token=auth_token.strip() if isinstance(auth_token, str) and auth_token.strip() else None,
        workbench_fetch_timeout_ms=fetch_timeout_ms,
        workbench_max_bytes=max_bytes,
        workbench_admit_kinds=tuple(admit_kinds),
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
