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

from .auth import TRUST_CLASSES


__all__ = [
    "BoundaryAdmissionConfig",
    "BoundaryBudgetLimitConfig",
    "BoundaryConfig",
    "BoundaryEconomicPolicyConfig",
    "BoundaryEconomicPolicyRule",
    "BoundaryRequestPolicyConfig",
    "BoundaryRequestPolicyRule",
    "BoundaryToolPolicyConfig",
    "ContextConfig",
    "JobRuntimeConfig",
    "allowed_tool_families_for_mode",
    "economic_policy_rule_for_mode",
    "context_resolution_enabled",
    "exposure_mode_allows",
    "get_boundary_config",
    "load_context_config",
    "load_boundary_config",
    "get_context_config",
    "load_job_runtime_config",
    "get_job_runtime_config",
    "request_policy_rule_for_mode",
    "reset_boundary_config_cache",
]


def context_resolution_enabled() -> bool:
    """Check GATEWAY_ENABLE_CONTEXT_RESOLUTION env var. Default: OFF."""
    return os.environ.get("GATEWAY_ENABLE_CONTEXT_RESOLUTION", "").lower() in ("true", "1", "yes")

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "context.json"
DEFAULT_BOUNDARY_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "boundary.json"

_EXPOSURE_RANKS: dict[str, int] = {
    "public": 0,
    "operator": 1,
    "demo": 2,
}


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
    high_risk_context_admit_mode: Literal["disabled", "metadata_only", "model_context"]
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


@dataclass(frozen=True)
class BoundaryAdmissionConfig:
    """Immutable admission policy derived from boundary config."""

    public_allow_artifact_handle: bool
    public_allow_declared_refs: bool
    public_max_declared_tools: int
    public_max_budget_tokens: int
    public_max_budget_duration_ms: int


@dataclass(frozen=True)
class BoundaryToolPolicyConfig:
    """Immutable tool-family policy derived from boundary config."""

    families: Mapping[str, tuple[str, ...]]
    matrix: Mapping[str, Mapping[str, tuple[str, ...]]]


@dataclass(frozen=True)
class BoundaryBudgetLimitConfig:
    """Immutable budget ceiling used by boundary request policy."""

    max_tokens: int
    max_duration_ms: int


@dataclass(frozen=True)
class BoundaryRequestPolicyRule:
    """Immutable rule for one exposure/trust/request-class combination."""

    decision: Literal["allow", "deny"]
    reason_code: str | None
    max_budget: BoundaryBudgetLimitConfig | None


@dataclass(frozen=True)
class BoundaryRequestPolicyConfig:
    """Immutable request classification and budget policy."""

    request_classes: tuple[str, ...]
    light_budget: BoundaryBudgetLimitConfig
    matrix: Mapping[str, Mapping[str, Mapping[str, BoundaryRequestPolicyRule]]]


@dataclass(frozen=True)
class BoundaryEconomicPolicyRule:
    """Immutable economic shaping rule for one exposure/trust/request-class tuple."""

    slot_class: Literal["none", "shared", "reserved"]
    cost_class: Literal["low", "bounded", "capped"]
    reservation_required: bool
    reason_code: str | None


@dataclass(frozen=True)
class BoundaryEconomicPolicyConfig:
    """Immutable economic policy derived from boundary config."""

    slot_classes: tuple[str, ...]
    cost_classes: tuple[str, ...]
    matrix: Mapping[str, Mapping[str, Mapping[str, BoundaryEconomicPolicyRule]]]


@dataclass(frozen=True)
class BoundaryConfig:
    """Immutable boundary configuration for surface exposure."""

    schema_version: str
    boundary_version: str
    exposure_mode: Literal["public", "operator", "demo"]
    surface_rules: Mapping[str, Literal["public", "operator", "demo"]]
    admission: BoundaryAdmissionConfig
    tool_policy: BoundaryToolPolicyConfig
    request_policy: BoundaryRequestPolicyConfig
    economic_policy: BoundaryEconomicPolicyConfig
    config_digest: str
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


def exposure_mode_allows(
    current_mode: Literal["public", "operator", "demo"],
    required_mode: Literal["public", "operator", "demo"],
) -> bool:
    """Return True when the current exposure mode may access the required mode."""
    return _EXPOSURE_RANKS[current_mode] >= _EXPOSURE_RANKS[required_mode]


def allowed_tool_families_for_mode(
    boundary_config: BoundaryConfig,
    *,
    mode: Literal["public", "operator", "demo"] | None = None,
    trust_class: str = "anonymous",
) -> tuple[str, ...]:
    selected_mode = mode or boundary_config.exposure_mode
    mode_matrix = boundary_config.tool_policy.matrix.get(selected_mode, {})
    if "*" in mode_matrix:
        return mode_matrix["*"]
    selected_trust = trust_class if trust_class in TRUST_CLASSES else "anonymous"
    return mode_matrix.get(selected_trust, ())


def request_policy_rule_for_mode(
    boundary_config: BoundaryConfig,
    *,
    request_class: str,
    mode: Literal["public", "operator", "demo"] | None = None,
    trust_class: str = "anonymous",
) -> BoundaryRequestPolicyRule:
    selected_mode = mode or boundary_config.exposure_mode
    mode_matrix = boundary_config.request_policy.matrix.get(selected_mode, {})
    selected_trust = trust_class if trust_class in TRUST_CLASSES else "anonymous"
    trust_rules = mode_matrix.get(selected_trust)
    if trust_rules is None:
        trust_rules = mode_matrix.get("*", {})
    rule = trust_rules.get(request_class)
    if rule is None:
        raise ValueError(
            f"request_policy.matrix.{selected_mode}.{selected_trust}.{request_class} is missing",
        )
    return rule


def economic_policy_rule_for_mode(
    boundary_config: BoundaryConfig,
    *,
    request_class: str,
    mode: Literal["public", "operator", "demo"] | None = None,
    trust_class: str = "anonymous",
) -> BoundaryEconomicPolicyRule:
    selected_mode = mode or boundary_config.exposure_mode
    mode_matrix = boundary_config.economic_policy.matrix.get(selected_mode, {})
    selected_trust = trust_class if trust_class in TRUST_CLASSES else "anonymous"
    trust_rules = mode_matrix.get(selected_trust)
    if trust_rules is None:
        trust_rules = mode_matrix.get("*", {})
    rule = trust_rules.get(request_class)
    if rule is None:
        raise ValueError(
            f"economic_policy.matrix.{selected_mode}.{selected_trust}.{request_class} is missing",
        )
    return rule


def load_boundary_config(path: Path | None = None) -> BoundaryConfig:
    """Load boundary exposure configuration from JSON file."""
    config_path = path or _resolve_boundary_config_path()

    if not config_path.exists():
        raise FileNotFoundError(f"Boundary config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    return _parse_boundary_config(raw)


def _resolve_boundary_config_path() -> Path:
    env_path = os.environ.get("DBL_GATEWAY_BOUNDARY_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_BOUNDARY_CONFIG_PATH


def _parse_boundary_config(raw: Mapping[str, Any]) -> BoundaryConfig:
    schema_version = raw.get("schema_version")
    if schema_version != "1":
        raise ValueError(f"Unsupported boundary schema_version: {schema_version}")

    boundary_version = raw.get("boundary_version")
    if not isinstance(boundary_version, str) or not boundary_version.strip():
        raise ValueError("boundary_version must be a non-empty string")

    exposure = raw.get("exposure_mode")
    if exposure not in _EXPOSURE_RANKS:
        raise ValueError("exposure_mode must be one of: public, operator, demo")

    raw_rules = raw.get("surface_rules")
    if not isinstance(raw_rules, Mapping):
        raise ValueError("surface_rules must be an object")

    surface_rules: dict[str, Literal["public", "operator", "demo"]] = {}
    for surface_id, required_mode in raw_rules.items():
        if not isinstance(surface_id, str) or not surface_id.strip():
            raise ValueError("surface_rules keys must be non-empty strings")
        if required_mode not in _EXPOSURE_RANKS:
            raise ValueError(
                f"surface_rules[{surface_id!r}] must be one of: public, operator, demo",
            )
        surface_rules[surface_id.strip()] = required_mode

    raw_admission = raw.get("admission")
    if not isinstance(raw_admission, Mapping):
        raise ValueError("admission must be an object")
    public_rules = raw_admission.get("public")
    if not isinstance(public_rules, Mapping):
        raise ValueError("admission.public must be an object")

    allow_artifact_handle = public_rules.get("allow_artifact_handle", False)
    if not isinstance(allow_artifact_handle, bool):
        raise ValueError("admission.public.allow_artifact_handle must be boolean")
    allow_declared_refs = public_rules.get("allow_declared_refs", False)
    if not isinstance(allow_declared_refs, bool):
        raise ValueError("admission.public.allow_declared_refs must be boolean")
    max_declared_tools = public_rules.get("max_declared_tools", 0)
    if not isinstance(max_declared_tools, int) or max_declared_tools < 0:
        raise ValueError("admission.public.max_declared_tools must be int >= 0")

    max_budget = public_rules.get("max_budget", {})
    if not isinstance(max_budget, Mapping):
        raise ValueError("admission.public.max_budget must be an object")
    max_budget_tokens = max_budget.get("max_tokens", 4096)
    if not isinstance(max_budget_tokens, int) or max_budget_tokens < 1:
        raise ValueError("admission.public.max_budget.max_tokens must be int >= 1")
    max_budget_duration_ms = max_budget.get("max_duration_ms", 30000)
    if not isinstance(max_budget_duration_ms, int) or max_budget_duration_ms < 1000:
        raise ValueError("admission.public.max_budget.max_duration_ms must be int >= 1000")

    raw_tool_policy = raw.get("tool_policy")
    if not isinstance(raw_tool_policy, Mapping):
        raise ValueError("tool_policy must be an object")

    raw_families = raw_tool_policy.get("families")
    if not isinstance(raw_families, Mapping) or not raw_families:
        raise ValueError("tool_policy.families must be a non-empty object")

    families: dict[str, tuple[str, ...]] = {}
    for family_name, patterns in raw_families.items():
        if not isinstance(family_name, str) or not family_name.strip():
            raise ValueError("tool_policy.families keys must be non-empty strings")
        if not isinstance(patterns, list) or not patterns:
            raise ValueError(f"tool_policy.families.{family_name} must be a non-empty list[str]")
        parsed_patterns: list[str] = []
        for item in patterns:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"tool_policy.families.{family_name} entries must be non-empty strings"
                )
            parsed_patterns.append(item.strip())
        families[family_name.strip()] = tuple(parsed_patterns)

    raw_matrix = raw_tool_policy.get("matrix")
    if not isinstance(raw_matrix, Mapping):
        raise ValueError("tool_policy.matrix must be an object")

    matrix: dict[str, dict[str, tuple[str, ...]]] = {}
    for exposure_name in _EXPOSURE_RANKS:
        raw_mode = raw_matrix.get(exposure_name)
        if not isinstance(raw_mode, Mapping):
            raise ValueError(f"tool_policy.matrix.{exposure_name} must be an object")
        parsed_mode: dict[str, tuple[str, ...]] = {}
        for trust_name, allowed in raw_mode.items():
            if trust_name != "*" and trust_name not in TRUST_CLASSES:
                raise ValueError(
                    f"tool_policy.matrix.{exposure_name} keys must be trust classes or '*'"
                )
            if not isinstance(allowed, list):
                raise ValueError(
                    f"tool_policy.matrix.{exposure_name}.{trust_name} must be list[str]"
                )
            parsed_allowed: list[str] = []
            for item in allowed:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        f"tool_policy.matrix.{exposure_name}.{trust_name} entries must be non-empty strings"
                    )
                family_name = item.strip()
                if family_name != "*" and family_name not in families:
                    raise ValueError(
                        f"tool_policy.matrix.{exposure_name}.{trust_name} references unknown family {family_name!r}"
                    )
                parsed_allowed.append(family_name)
            parsed_mode[str(trust_name)] = tuple(parsed_allowed)
        matrix[exposure_name] = parsed_mode

    raw_request_policy = raw.get("request_policy")
    if not isinstance(raw_request_policy, Mapping):
        raise ValueError("request_policy must be an object")
    raw_classification = raw_request_policy.get("classification")
    if not isinstance(raw_classification, Mapping):
        raise ValueError("request_policy.classification must be an object")
    raw_light_budget = raw_classification.get("light_budget")
    if not isinstance(raw_light_budget, Mapping):
        raise ValueError("request_policy.classification.light_budget must be an object")
    light_budget_tokens = raw_light_budget.get("max_tokens", 2048)
    if not isinstance(light_budget_tokens, int) or light_budget_tokens < 1:
        raise ValueError("request_policy.classification.light_budget.max_tokens must be int >= 1")
    light_budget_duration_ms = raw_light_budget.get("max_duration_ms", 15000)
    if not isinstance(light_budget_duration_ms, int) or light_budget_duration_ms < 1000:
        raise ValueError(
            "request_policy.classification.light_budget.max_duration_ms must be int >= 1000"
        )

    request_classes = ("probe", "intent", "execution_light", "execution_heavy")
    raw_request_matrix = raw_request_policy.get("matrix")
    if not isinstance(raw_request_matrix, Mapping):
        raise ValueError("request_policy.matrix must be an object")
    request_matrix: dict[str, dict[str, dict[str, BoundaryRequestPolicyRule]]] = {}
    for exposure_name in _EXPOSURE_RANKS:
        raw_mode = raw_request_matrix.get(exposure_name)
        if not isinstance(raw_mode, Mapping):
            raise ValueError(f"request_policy.matrix.{exposure_name} must be an object")
        parsed_mode: dict[str, dict[str, BoundaryRequestPolicyRule]] = {}
        for trust_name, raw_rules in raw_mode.items():
            if trust_name != "*" and trust_name not in TRUST_CLASSES:
                raise ValueError(
                    f"request_policy.matrix.{exposure_name} keys must be trust classes or '*'"
                )
            if not isinstance(raw_rules, Mapping):
                raise ValueError(
                    f"request_policy.matrix.{exposure_name}.{trust_name} must be an object"
                )
            parsed_rules: dict[str, BoundaryRequestPolicyRule] = {}
            for request_class in request_classes:
                raw_rule = raw_rules.get(request_class)
                if not isinstance(raw_rule, Mapping):
                    raise ValueError(
                        f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class} must be an object"
                    )
                decision = raw_rule.get("decision")
                if decision not in {"allow", "deny"}:
                    raise ValueError(
                        f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class}.decision "
                        "must be allow or deny"
                    )
                reason_code = raw_rule.get("reason_code")
                if reason_code is not None and (
                    not isinstance(reason_code, str) or not reason_code.strip()
                ):
                    raise ValueError(
                        f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class}.reason_code "
                        "must be a non-empty string when provided"
                    )
                raw_rule_budget = raw_rule.get("max_budget")
                parsed_budget: BoundaryBudgetLimitConfig | None = None
                if raw_rule_budget is not None:
                    if not isinstance(raw_rule_budget, Mapping):
                        raise ValueError(
                            f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class}.max_budget "
                            "must be an object"
                        )
                    rule_tokens = raw_rule_budget.get("max_tokens")
                    rule_duration_ms = raw_rule_budget.get("max_duration_ms")
                    if not isinstance(rule_tokens, int) or rule_tokens < 1:
                        raise ValueError(
                            f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class}.max_budget.max_tokens "
                            "must be int >= 1"
                        )
                    if not isinstance(rule_duration_ms, int) or rule_duration_ms < 1000:
                        raise ValueError(
                            f"request_policy.matrix.{exposure_name}.{trust_name}.{request_class}.max_budget.max_duration_ms "
                            "must be int >= 1000"
                        )
                    parsed_budget = BoundaryBudgetLimitConfig(
                        max_tokens=rule_tokens,
                        max_duration_ms=rule_duration_ms,
                    )
                parsed_rules[request_class] = BoundaryRequestPolicyRule(
                    decision=decision,
                    reason_code=reason_code.strip() if isinstance(reason_code, str) else None,
                    max_budget=parsed_budget,
                )
            parsed_mode[str(trust_name)] = parsed_rules
        request_matrix[exposure_name] = parsed_mode

    raw_economic_policy = raw.get("economic_policy")
    if not isinstance(raw_economic_policy, Mapping):
        raise ValueError("economic_policy must be an object")
    slot_classes = ("none", "shared", "reserved")
    cost_classes = ("low", "bounded", "capped")
    raw_economic_matrix = raw_economic_policy.get("matrix")
    if not isinstance(raw_economic_matrix, Mapping):
        raise ValueError("economic_policy.matrix must be an object")
    economic_matrix: dict[str, dict[str, dict[str, BoundaryEconomicPolicyRule]]] = {}
    for exposure_name in _EXPOSURE_RANKS:
        raw_mode = raw_economic_matrix.get(exposure_name)
        if not isinstance(raw_mode, Mapping):
            raise ValueError(f"economic_policy.matrix.{exposure_name} must be an object")
        parsed_mode: dict[str, dict[str, BoundaryEconomicPolicyRule]] = {}
        for trust_name, raw_rules in raw_mode.items():
            if trust_name != "*" and trust_name not in TRUST_CLASSES:
                raise ValueError(
                    f"economic_policy.matrix.{exposure_name} keys must be trust classes or '*'"
                )
            if not isinstance(raw_rules, Mapping):
                raise ValueError(
                    f"economic_policy.matrix.{exposure_name}.{trust_name} must be an object"
                )
            parsed_rules: dict[str, BoundaryEconomicPolicyRule] = {}
            for request_class in request_classes:
                raw_rule = raw_rules.get(request_class)
                if not isinstance(raw_rule, Mapping):
                    raise ValueError(
                        f"economic_policy.matrix.{exposure_name}.{trust_name}.{request_class} must be an object"
                    )
                slot_class = raw_rule.get("slot_class")
                if slot_class not in slot_classes:
                    raise ValueError(
                        f"economic_policy.matrix.{exposure_name}.{trust_name}.{request_class}.slot_class "
                        "must be none, shared, or reserved"
                    )
                cost_class = raw_rule.get("cost_class")
                if cost_class not in cost_classes:
                    raise ValueError(
                        f"economic_policy.matrix.{exposure_name}.{trust_name}.{request_class}.cost_class "
                        "must be low, bounded, or capped"
                    )
                reservation_required = raw_rule.get("reservation_required", False)
                if not isinstance(reservation_required, bool):
                    raise ValueError(
                        f"economic_policy.matrix.{exposure_name}.{trust_name}.{request_class}.reservation_required "
                        "must be boolean"
                    )
                reason_code = raw_rule.get("reason_code")
                if reason_code is not None and (
                    not isinstance(reason_code, str) or not reason_code.strip()
                ):
                    raise ValueError(
                        f"economic_policy.matrix.{exposure_name}.{trust_name}.{request_class}.reason_code "
                        "must be a non-empty string when provided"
                    )
                parsed_rules[request_class] = BoundaryEconomicPolicyRule(
                    slot_class=slot_class,
                    cost_class=cost_class,
                    reservation_required=reservation_required,
                    reason_code=reason_code.strip() if isinstance(reason_code, str) else None,
                )
            parsed_mode[str(trust_name)] = parsed_rules
        economic_matrix[exposure_name] = parsed_mode

    config_digest = _compute_config_digest(raw)

    return BoundaryConfig(
        schema_version=str(schema_version),
        boundary_version=boundary_version.strip(),
        exposure_mode=exposure,
        surface_rules=surface_rules,
        admission=BoundaryAdmissionConfig(
            public_allow_artifact_handle=allow_artifact_handle,
            public_allow_declared_refs=allow_declared_refs,
            public_max_declared_tools=max_declared_tools,
            public_max_budget_tokens=max_budget_tokens,
            public_max_budget_duration_ms=max_budget_duration_ms,
        ),
        tool_policy=BoundaryToolPolicyConfig(
            families=families,
            matrix=matrix,
        ),
        request_policy=BoundaryRequestPolicyConfig(
            request_classes=request_classes,
            light_budget=BoundaryBudgetLimitConfig(
                max_tokens=light_budget_tokens,
                max_duration_ms=light_budget_duration_ms,
            ),
            matrix=request_matrix,
        ),
        economic_policy=BoundaryEconomicPolicyConfig(
            slot_classes=slot_classes,
            cost_classes=cost_classes,
            matrix=economic_matrix,
        ),
        config_digest=config_digest,
        _raw=raw,
    )


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
    high_risk_context_admit_mode = handle_cfg.get("high_risk_context_admit_mode", "metadata_only")
    if high_risk_context_admit_mode not in ("disabled", "metadata_only", "model_context"):
        raise ValueError(
            "handle_content_fetch.high_risk_context_admit_mode must be disabled, metadata_only, or model_context"
        )
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

    env_allow = _env_bool("DBL_HANDLE_CONTENT_FETCH_ENABLED")
    if env_allow is None:
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
    env_kinds = os.getenv("DBL_HANDLE_CONTENT_FETCH_ALLOWED_KINDS")
    if env_kinds is None:
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
        high_risk_context_admit_mode=high_risk_context_admit_mode,
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


@lru_cache(maxsize=1)
def get_boundary_config() -> BoundaryConfig:
    """Get cached boundary configuration."""
    return load_boundary_config()


def reset_boundary_config_cache() -> None:
    """Reset boundary config cache. Only for testing."""
    get_boundary_config.cache_clear()


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
