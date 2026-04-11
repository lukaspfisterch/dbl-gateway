from __future__ import annotations

import hashlib
import importlib.metadata
from datetime import datetime, timezone
import os
import time
from typing import Any, Mapping
import httpx
import logging

_LOGGER = logging.getLogger(__name__)

from pydantic import BaseModel, model_serializer

from .config import (
    allowed_tool_families_for_mode,
    BoundaryConfig,
    context_resolution_enabled,
    economic_policy_rule_for_mode,
    exposure_mode_allows,
    get_boundary_config,
    get_context_config,
    request_policy_rule_for_mode,
)
from .auth import TRUST_CLASSES, load_auth_config_with_identity_policy
from .providers import get_provider_capabilities
from .providers.contract import ProviderCapabilities
from .wire_contract import (
    BUDGET_LIMITS,
    CAPABILITIES_INTENT_TYPES,
    INTERFACE_VERSION,
    MAX_DECLARED_TOOLS,
    SUPPORTED_TOOL_SCOPE,
    TOOL_NAME_PATTERN,
)

CAPABILITIES_SCHEMA_VERSION = "gateway.capabilities.v1"


def _gateway_version() -> str:
    try:
        return importlib.metadata.version("dbl-gateway")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"

# Global TTL cache for capabilities
# Structure: {"value": dict, "expires_at": float}
_CAPS_CACHE: dict[str, Any] = {}
_CAPS_TTL_SECONDS = 60.0

class CapabilitiesHealth(BaseModel):
    status: str
    checked_at: str


class CapabilitiesLimits(BaseModel):
    max_output_tokens: int


class CapabilitiesFeatures(BaseModel):
    streaming: bool
    tools: bool
    json_mode: bool


class CapabilitiesModel(BaseModel):
    id: str
    display_name: str
    features: CapabilitiesFeatures
    limits: CapabilitiesLimits
    health: CapabilitiesHealth


class CapabilitiesProvider(BaseModel):
    id: str
    models: list[CapabilitiesModel]


class CapabilitiesSurfaces(BaseModel):
    tail: bool
    snapshot: bool
    events: bool
    ingress_intent: bool


class CapabilitiesBoundary(BaseModel):
    boundary_version: str
    boundary_config_digest: str
    exposure_mode: str


class CapabilitiesAuth(BaseModel):
    mode: str
    current_trust_class: str
    trust_classes: list[str]
    identity_sources: list[str]
    issuers_allowed: list[str]
    audiences_allowed: list[str]
    claim_mapping: dict[str, Any] | None = None
    role_mapping_summary: dict[str, Any] | None = None

    @model_serializer(mode="wrap")
    def _omit_none_fields(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        if data.get("claim_mapping") is None:
            data.pop("claim_mapping", None)
        if data.get("role_mapping_summary") is None:
            data.pop("role_mapping_summary", None)
        return data


class SurfaceDescriptor(BaseModel):
    id: str
    path: str
    methods: list[str]
    auth: str
    plane: str
    description: str


class CapabilitiesIntents(BaseModel):
    supported: list[str]
    catalog: dict[str, dict[str, Any]]


class CapabilitiesDeclaredTools(BaseModel):
    max_items: int
    name_pattern: str


class CapabilitiesToolScope(BaseModel):
    supported: list[str]
    default_when_declared_tools_present: str


class CapabilitiesToolSurface(BaseModel):
    declared_tools: CapabilitiesDeclaredTools
    tool_scope: CapabilitiesToolScope
    semantic_families: dict[str, list[str]]
    trust_class_current: str
    allowed_families_current: list[str]
    allowed_families_by_exposure: dict[str, dict[str, list[str]]]
    no_mix_rules: list[dict[str, Any]]


class CapabilitiesBudgetField(BaseModel):
    type: str
    min: int
    max: int


class CapabilitiesBudget(BaseModel):
    fields: dict[str, CapabilitiesBudgetField]
    request_classes: list[str]
    visible_request_classes_current: list[str]
    light_budget_classification: dict[str, int]
    current_request_policy: dict[str, dict[str, Any]]
    request_policy_by_exposure: dict[str, dict[str, dict[str, dict[str, Any]]]]


class CapabilitiesEconomic(BaseModel):
    slot_classes: list[str]
    cost_classes: list[str]
    current_policy: dict[str, dict[str, Any]]
    policy_by_exposure: dict[str, dict[str, dict[str, dict[str, Any]]]]


class CapabilitiesResponse(BaseModel):
    schema_version: str
    gateway_version: str
    interface_version: int
    auth: CapabilitiesAuth
    boundary: CapabilitiesBoundary
    intents: CapabilitiesIntents
    tool_surface: CapabilitiesToolSurface
    budget: CapabilitiesBudget
    economic: CapabilitiesEconomic
    providers: list[CapabilitiesProvider]
    surfaces: CapabilitiesSurfaces
    surface_catalog: list[SurfaceDescriptor]

_SURFACE_REGISTRY: tuple[dict[str, object], ...] = (
    {
        "id": "healthz",
        "path": "/healthz",
        "methods": ["GET"],
        "auth": "required",
        "plane": "runtime",
        "description": "Health check for the gateway process.",
        "min_exposure": "public",
    },
    {
        "id": "capabilities",
        "path": "/capabilities",
        "methods": ["GET"],
        "auth": "required",
        "plane": "discovery",
        "description": "Self-description of the runtime contract, providers, and surfaces.",
        "min_exposure": "public",
    },
    {
        "id": "surfaces",
        "path": "/surfaces",
        "methods": ["GET"],
        "auth": "required",
        "plane": "discovery",
        "description": "Explicit catalog of callable gateway and observer surfaces.",
        "min_exposure": "operator",
    },
    {
        "id": "intent_template",
        "path": "/intent-template",
        "methods": ["GET"],
        "auth": "required",
        "plane": "discovery",
        "description": "Self-teaching intent template and example envelopes.",
        "min_exposure": "operator",
    },
    {
        "id": "ingress_intent",
        "path": "/ingress/intent",
        "methods": ["POST"],
        "auth": "required",
        "plane": "intent",
        "description": "Intent ingress surface for declared envelopes.",
        "min_exposure": "public",
    },
    {
        "id": "snapshot",
        "path": "/snapshot",
        "methods": ["GET"],
        "auth": "required",
        "plane": "observation",
        "description": "Snapshot of persisted events and rolling v_digest.",
        "min_exposure": "operator",
    },
    {
        "id": "tail",
        "path": "/tail",
        "methods": ["GET"],
        "auth": "required",
        "plane": "observation",
        "description": "Authenticated SSE stream of event envelopes.",
        "min_exposure": "operator",
    },
    {
        "id": "thread_timeline",
        "path": "/threads/{thread_id}/timeline",
        "methods": ["GET"],
        "auth": "required",
        "plane": "observation",
        "description": "Turn-grouped thread timeline for replay and inspection.",
        "min_exposure": "operator",
    },
    {
        "id": "status",
        "path": "/status",
        "methods": ["GET"],
        "auth": "required",
        "plane": "observation",
        "description": "Projected runner state derived from events.",
        "min_exposure": "operator",
    },
    {
        "id": "execution_event",
        "path": "/execution/event",
        "methods": ["POST"],
        "auth": "required",
        "plane": "execution",
        "description": "External execution submission surface when enabled.",
        "min_exposure": "operator",
    },
    {
        "id": "ui_root",
        "path": "/ui/",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Built-in observer UI.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_tail",
        "path": "/ui/tail",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Auth-free SSE feed for the built-in observer.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_capabilities",
        "path": "/ui/capabilities",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer proxy for capabilities.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_snapshot",
        "path": "/ui/snapshot",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer proxy for latest snapshot state.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_policy_structure",
        "path": "/ui/policy-structure",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer proxy for the current policy inspector payload.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_intent",
        "path": "/ui/intent",
        "methods": ["POST"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer-side manual intent submission.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_verify_chain",
        "path": "/ui/verify-chain",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer-triggered full-chain verification.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_replay",
        "path": "/ui/replay",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Observer-triggered decision replay for a turn.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_demo_status",
        "path": "/ui/demo/status",
        "methods": ["GET"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Status surface for the integrated demo controller.",
        "min_exposure": "demo",
    },
    {
        "id": "ui_demo_start",
        "path": "/ui/demo/start",
        "methods": ["POST"],
        "auth": "none",
        "plane": "observer_ui",
        "description": "Start surface for the integrated demo controller.",
        "min_exposure": "demo",
    },
)

_SURFACES_BY_ID: dict[str, dict[str, object]] = {
    str(item["id"]): dict(item) for item in _SURFACE_REGISTRY
}


def _identity_sources_for_mode(mode: str) -> list[str]:
    if mode == "dev":
        return ["dev_headers"]
    if mode == "oidc":
        return ["oidc_jwt"]
    return []


def _identity_claim_mapping(cfg: BoundaryConfig) -> dict[str, Any]:
    return {
        "actor_id": list(cfg.identity_policy.actor_id_claims),
        "issuer": cfg.identity_policy.issuer_claim,
        "roles": list(cfg.identity_policy.role_claims),
    }


def _identity_role_mapping_summary(cfg: BoundaryConfig) -> dict[str, Any]:
    operator_targets = {"gateway.operator", "gateway.admin"}
    internal_targets = {"gateway.internal"}
    operator_sources = 0
    internal_sources = 0
    for mapped_roles in cfg.identity_policy.role_map.values():
        mapped_set = set(mapped_roles)
        if mapped_set & operator_targets:
            operator_sources += 1
        if mapped_set & internal_targets:
            internal_sources += 1
    return {
        "mapped_sources": len(cfg.identity_policy.role_map),
        "operator_sources": operator_sources,
        "internal_sources": internal_sources,
        "user_fallback": True,
    }


def get_capabilities_cached(
    boundary_config: BoundaryConfig | None = None,
    *,
    trust_class: str = "anonymous",
) -> dict[str, object]:
    """
    Cached version of get_capabilities with TTL.
    This should be called via run_in_threadpool if used in async context
    to avoid blocking the event loop on cache misses.
    """
    cfg = boundary_config or get_boundary_config()
    cache_key = _capabilities_cache_key(cfg, trust_class)
    now = time.time()
    cached = _CAPS_CACHE.get(cache_key)
    expires = _CAPS_CACHE.get(f"{cache_key}:expires_at", 0)

    if cached is not None and now < expires:
        return cached

    caps = get_capabilities(cfg, trust_class=trust_class)
    _CAPS_CACHE[cache_key] = caps
    _CAPS_CACHE[f"{cache_key}:expires_at"] = now + _CAPS_TTL_SECONDS
    return caps


def get_capabilities(
    boundary_config: BoundaryConfig | None = None,
    *,
    trust_class: str = "anonymous",
) -> dict[str, object]:
    cfg = boundary_config or get_boundary_config()
    auth_cfg = load_auth_config_with_identity_policy(identity_policy=cfg.identity_policy._raw)
    checked_at = datetime.now(timezone.utc).isoformat()
    providers: list[dict[str, Any]] = []
    intent_catalog = get_intent_catalog(cfg)

    if _get_openai_key():
        caps = get_provider_capabilities("openai")
        models = [_model_entry_from_provider(model_id, caps, checked_at) for model_id in _openai_models_all()]
        if models:
            providers.append({"id": "openai", "models": models})

    if _get_anthropic_key():
        caps = get_provider_capabilities("anthropic")
        models = [_model_entry_from_provider(model_id, caps, checked_at) for model_id in _anthropic_models_all()]
        if models:
            providers.append({"id": "anthropic", "models": models})

    ollama_info = _discover_ollama(checked_at)
    if ollama_info:
        providers.append(ollama_info)

    if _is_demo_mode():
        caps = get_provider_capabilities("stub")
        models = [
            _model_entry_from_provider(mid, caps, checked_at)
            for mid in _stub_models()
        ]
        if models:
            providers.append({"id": "stub", "models": models})

    def serialize_request_policy(mode: str, trust: str) -> dict[str, dict[str, Any]]:
        policy_map: dict[str, dict[str, Any]] = {}
        for request_class in cfg.request_policy.request_classes:
            rule = request_policy_rule_for_mode(
                cfg,
                mode=mode, trust_class=trust, request_class=request_class,
            )
            policy_map[request_class] = {
                "decision": rule.decision,
                "reason_code": rule.reason_code,
                "max_budget": (
                    {
                        "max_tokens": rule.max_budget.max_tokens,
                        "max_duration_ms": rule.max_budget.max_duration_ms,
                    }
                    if rule.max_budget is not None
                    else None
                ),
            }
        return policy_map

    def serialize_economic_policy(mode: str, trust: str) -> dict[str, dict[str, Any]]:
        policy_map: dict[str, dict[str, Any]] = {}
        for request_class in cfg.request_policy.request_classes:
            rule = economic_policy_rule_for_mode(
                cfg,
                mode=mode,
                trust_class=trust,
                request_class=request_class,
            )
            policy_map[request_class] = {
                "slot_class": rule.slot_class,
                "cost_class": rule.cost_class,
                "reservation_required": rule.reservation_required,
                "reason_code": rule.reason_code,
            }
        return policy_map

    current_request_policy = serialize_request_policy(cfg.exposure_mode, trust_class)
    if cfg.exposure_mode == "public":
        current_request_policy = {
            request_class: rule
            for request_class, rule in current_request_policy.items()
            if rule.get("decision") == "allow"
        }
    visible_request_classes_current = list(current_request_policy.keys())
    current_economic_policy = {
        request_class: rule
        for request_class, rule in serialize_economic_policy(cfg.exposure_mode, trust_class).items()
        if request_class in visible_request_classes_current
    }
    auth_payload: dict[str, Any] = {
        "mode": auth_cfg.mode,
        "current_trust_class": trust_class,
        "trust_classes": list(TRUST_CLASSES),
        "identity_sources": _identity_sources_for_mode(auth_cfg.mode),
        "issuers_allowed": list(auth_cfg.issuers_allowed),
        "audiences_allowed": list(auth_cfg.audiences_allowed),
    }
    if cfg.exposure_mode != "public":
        auth_payload["claim_mapping"] = _identity_claim_mapping(cfg)
        auth_payload["role_mapping_summary"] = _identity_role_mapping_summary(cfg)

    return {
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "gateway_version": _gateway_version(),
        "interface_version": INTERFACE_VERSION,
        "auth": auth_payload,
        "boundary": {
            "boundary_version": cfg.boundary_version,
            "boundary_config_digest": cfg.config_digest,
            "exposure_mode": cfg.exposure_mode,
        },
        "intents": {
            "supported": [intent_id for intent_id, meta in intent_catalog.items() if bool(meta.get("admitted"))],
            "catalog": intent_catalog,
        },
        "tool_surface": {
            "declared_tools": {
                "max_items": MAX_DECLARED_TOOLS,
                "name_pattern": TOOL_NAME_PATTERN,
            },
            "tool_scope": {
                "supported": list(SUPPORTED_TOOL_SCOPE),
                "default_when_declared_tools_present": "strict",
            },
            "semantic_families": {
                name: list(patterns)
                for name, patterns in cfg.tool_policy.families.items()
            },
            "trust_class_current": trust_class,
            "allowed_families_current": list(
                allowed_tool_families_for_mode(cfg, trust_class=trust_class)
            ),
            "allowed_families_by_exposure": {
                mode: {
                    trust: list(allowed_tool_families_for_mode(cfg, mode=mode, trust_class=trust))
                    for trust in cfg.tool_policy.matrix.get(mode, {})
                }
                for mode in ("public", "operator", "demo")
            },
            "no_mix_rules": [
                {
                    "rule_id": "tool.no_mix.exec_like",
                    "description": "exec-like tools are denied when mixed with any other tool family",
                },
            ],
        },
        "budget": {
            "fields": {
                name: {
                    "type": "integer",
                    "min": limits["min"],
                    "max": limits["max"],
                }
                for name, limits in BUDGET_LIMITS.items()
            },
            "request_classes": list(cfg.request_policy.request_classes),
            "visible_request_classes_current": visible_request_classes_current,
            "light_budget_classification": {
                "max_tokens": cfg.request_policy.light_budget.max_tokens,
                "max_duration_ms": cfg.request_policy.light_budget.max_duration_ms,
            },
            "current_request_policy": current_request_policy,
            "request_policy_by_exposure": {
                mode: {
                    trust: serialize_request_policy(mode, trust)
                    for trust in cfg.request_policy.matrix.get(mode, {})
                }
                for mode in ("public", "operator", "demo")
            },
        },
        "economic": {
            "slot_classes": list(cfg.economic_policy.slot_classes),
            "cost_classes": list(cfg.economic_policy.cost_classes),
            "current_policy": current_economic_policy,
            "policy_by_exposure": {
                mode: {
                    trust: serialize_economic_policy(mode, trust)
                    for trust in cfg.economic_policy.matrix.get(mode, {})
                }
                for mode in ("public", "operator", "demo")
            },
        },
        "providers": providers,
        "surfaces": {
            "tail": surface_enabled("tail", cfg),
            "snapshot": surface_enabled("snapshot", cfg),
            "events": False,
            "ingress_intent": surface_enabled("ingress_intent", cfg),
        },
        "surface_catalog": get_surface_catalog(cfg),
    }


def get_intent_catalog(boundary_config: BoundaryConfig | None = None) -> dict[str, dict[str, Any]]:
    cfg = boundary_config or get_boundary_config()
    context_enabled = context_resolution_enabled()
    context_cfg = get_context_config()

    catalog: dict[str, dict[str, Any]] = {
        "chat.message": {
            "risk_class": "standard",
            "admitted": True,
            "requires_context_resolution": False,
            "available_in_exposure_modes": ["public", "operator", "demo"],
        },
    }

    artifact_exposures = ["operator", "demo"]
    if cfg.admission.public_allow_artifact_handle:
        artifact_exposures = ["public", *artifact_exposures]

    artifact_visible = any(
        exposure_mode_allows(cfg.exposure_mode, required_mode)
        for required_mode in artifact_exposures
    )
    if artifact_visible:
        catalog["artifact.handle"] = {
            "risk_class": "high_risk_context",
            "admitted": context_enabled and (
                cfg.exposure_mode != "public" or cfg.admission.public_allow_artifact_handle
            ),
            "requires_context_resolution": True,
            "model_context_admit_mode": (
                context_cfg.high_risk_context_admit_mode if context_enabled else "disabled"
            ),
            "available_in_exposure_modes": artifact_exposures,
        }

    return catalog


def get_surface_catalog(boundary_config: BoundaryConfig | None = None) -> list[dict[str, object]]:
    cfg = boundary_config or get_boundary_config()
    visible: list[dict[str, object]] = []
    for item in _SURFACE_REGISTRY:
        surface_id = str(item["id"])
        if not surface_enabled(surface_id, cfg):
            continue
        visible.append({
            "id": surface_id,
            "path": str(item["path"]),
            "methods": list(item["methods"]),
            "auth": str(item["auth"]),
            "plane": str(item["plane"]),
            "description": str(item["description"]),
        })
    return visible


def surface_enabled(surface_id: str, boundary_config: BoundaryConfig | None = None) -> bool:
    cfg = boundary_config or get_boundary_config()
    item = _SURFACES_BY_ID.get(surface_id)
    if item is None:
        return False
    required_mode = cfg.surface_rules.get(surface_id)
    if required_mode is None:
        required_mode = str(item.get("min_exposure", "demo"))
    return exposure_mode_allows(cfg.exposure_mode, required_mode)


def resolve_surface_id(path: str) -> str | None:
    if path == "/":
        return "ui_root"
    if path in {"/ui", "/ui/"}:
        return "ui_root"
    if path.startswith("/threads/") and path.endswith("/timeline"):
        return "thread_timeline"
    for item in _SURFACE_REGISTRY:
        if path == item["path"]:
            return str(item["id"])
    return None


def surface_access_payload(
    path: str,
    *,
    boundary_config: BoundaryConfig | None = None,
) -> Mapping[str, object] | None:
    surface_id = resolve_surface_id(path)
    if surface_id is None:
        return None
    cfg = boundary_config or get_boundary_config()
    if surface_enabled(surface_id, cfg):
        return None
    required_mode = cfg.surface_rules.get(surface_id)
    if required_mode is None:
        required_mode = str(_SURFACES_BY_ID[surface_id].get("min_exposure", "demo"))
    return {
        "surface_id": surface_id,
        "exposure_mode": cfg.exposure_mode,
        "required_exposure_mode": required_mode,
        "status_code": 404 if str(surface_id).startswith("ui_") else 403,
        "detail": "surface unavailable in current exposure mode",
    }


def _capabilities_cache_key(cfg: BoundaryConfig, trust_class: str) -> str:
    runtime_fingerprint = {
        "boundary": cfg.config_digest,
        "trust_class": trust_class,
        "demo_mode": _is_demo_mode(),
        "stub_mode": os.getenv("STUB_MODE", "").strip(),
        "openai_key": bool(_get_openai_key()),
        "openai_chat_models": tuple(_openai_models_all()),
        "anthropic_key": bool(_get_anthropic_key()),
        "anthropic_models": tuple(_anthropic_models_all()),
        "ollama_base": os.getenv("OLLAMA_BASE_URL", "").strip(),
        "ollama_host": os.getenv("OLLAMA_HOST", "").strip(),
        "ollama_models": tuple(_parse_csv("OLLAMA_MODEL_IDS")),
    }
    return hashlib.sha256(repr(runtime_fingerprint).encode("utf-8")).hexdigest()


def resolve_model(requested_model_id: str | None) -> tuple[str | None, str | None]:
    requested = (requested_model_id or "").strip()
    allowed = _allowed_model_ids()
    if requested:
        if requested in allowed:
            return requested, None
        provider, reason = resolve_provider(requested)
        return None, reason or "model.unavailable"

    default_model_id = _default_model_id(allowed)
    if default_model_id:
        return default_model_id, None

    if _has_models_without_credentials():
        return None, "provider.missing_credentials"
    return None, "model.unavailable"


def resolve_provider(model_id: str) -> tuple[str | None, str | None]:
    if model_id in _openai_models_all():
        if not _get_openai_key():
            return None, "provider.missing_credentials"
        return "openai", None
    if model_id in _anthropic_models_all():
        if not _get_anthropic_key():
            return None, "provider.missing_credentials"
        return "anthropic", None
    if model_id in _ollama_models_all():
        return "ollama", None
    if _is_demo_mode() and model_id in _stub_models():
        return "stub", None
    return None, "model.unavailable"


def _model_entry_from_provider(
    model_id: str, caps: ProviderCapabilities, checked_at: str,
) -> dict[str, object]:
    return {
        "id": model_id,
        "display_name": model_id.replace("-", " ").upper(),
        "features": caps.features.model_dump(),
        "limits": {
            "max_output_tokens": caps.limits.max_output_tokens,
        },
        "health": {
            "status": "ok",
            "checked_at": checked_at,
        },
    }


def _allowed_model_ids() -> list[str]:
    models: list[str] = []
    if _get_openai_key():
        models.extend(_openai_models_all())
    if _get_anthropic_key():
        models.extend(_anthropic_models_all())
    models.extend(_ollama_models_all())
    if _is_demo_mode():
        models.extend(_stub_models())
    return _dedupe(models)


def _openai_models_all() -> list[str]:
    chat_models = _parse_csv("OPENAI_CHAT_MODEL_IDS")
    if not chat_models:
        chat_models = _parse_csv("OPENAI_MODEL_IDS")
    if not chat_models:
        chat_models = ["gpt-4o-mini"]
    response_models = _parse_csv("OPENAI_RESPONSES_MODEL_IDS") or []
    return _dedupe(chat_models + response_models)


def _anthropic_models_all() -> list[str]:
    models = _parse_csv("ANTHROPIC_MODEL_IDS")
    return models or ["claude-3-haiku-20240307"]


def _ollama_models_all() -> list[str]:
    # Check manual overrides first
    models = _parse_csv("OLLAMA_MODEL_IDS")
    if models:
        return models
    
    # Try dynamic discovery
    base = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST")
    if not base:
        return []
        
    try:
        with httpx.Client(timeout=2.0) as c:
            r = c.get(base.rstrip("/") + "/api/tags")
            if r.status_code >= 400:
                return []
            tags = r.json().get("models", [])
            return [str(t.get("name")) for t in tags if t.get("name")]
    except Exception:
        return []


def _discover_ollama(checked_at: str) -> dict[str, Any] | None:
    base = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST")
    if not base:
        return None
    if not base.startswith(("http://", "https://")):
        base = f"http://{base}"
    _LOGGER.info("ollama discovery base_url=%s", base)
    try:
        caps = get_provider_capabilities("ollama")
        with httpx.Client(timeout=2.0) as c:
            r = c.get(base.rstrip("/") + "/api/tags")
            _LOGGER.info("ollama tags status=%s", r.status_code)
            if r.status_code >= 400:
                return None
            tags = r.json().get("models", [])
            models = []
            for t in tags:
                name = str(t.get("name") or "")
                if name:
                    entry = _model_entry_from_provider(name, caps, checked_at)
                    entry["display_name"] = name  # ollama uses raw name
                    models.append(entry)
            if not models:
                return None
            return {"id": "ollama", "models": models}
    except Exception as exc:
        _LOGGER.warning("ollama discovery failed: %s", exc)
        return None


def _default_model_id(allowed: list[str]) -> str | None:
    if not allowed:
        return None
    return allowed[0]


def _has_models_without_credentials() -> bool:
    if _openai_models_all() and not _get_openai_key():
        return True
    if _anthropic_models_all() and not _get_anthropic_key():
        return True
    return False


def _get_openai_key() -> str:
    return os.getenv("OPENAI_API_KEY", "").strip()


def _get_anthropic_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _parse_csv(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _is_demo_mode() -> bool:
    return os.getenv("GATEWAY_DEMO_MODE", "").strip() in ("1", "true", "yes")


def _stub_models() -> list[str]:
    from .providers.stub import STUB_MODEL_IDS

    return list(STUB_MODEL_IDS)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
