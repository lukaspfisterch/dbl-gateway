from __future__ import annotations

import importlib.metadata
from datetime import datetime, timezone
import os
import time
from typing import Any
import httpx
import logging

_LOGGER = logging.getLogger(__name__)

from pydantic import BaseModel

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


class CapabilitiesIntents(BaseModel):
    supported: list[str]


class CapabilitiesDeclaredTools(BaseModel):
    max_items: int
    name_pattern: str


class CapabilitiesToolScope(BaseModel):
    supported: list[str]
    default_when_declared_tools_present: str


class CapabilitiesToolSurface(BaseModel):
    declared_tools: CapabilitiesDeclaredTools
    tool_scope: CapabilitiesToolScope


class CapabilitiesBudgetField(BaseModel):
    type: str
    min: int
    max: int


class CapabilitiesBudget(BaseModel):
    fields: dict[str, CapabilitiesBudgetField]


class CapabilitiesResponse(BaseModel):
    schema_version: str
    gateway_version: str
    interface_version: int
    intents: CapabilitiesIntents
    tool_surface: CapabilitiesToolSurface
    budget: CapabilitiesBudget
    providers: list[CapabilitiesProvider]
    surfaces: CapabilitiesSurfaces


def get_capabilities_cached() -> dict[str, object]:
    """
    Cached version of get_capabilities with TTL.
    This should be called via run_in_threadpool if used in async context
    to avoid blocking the event loop on cache misses.
    """
    now = time.time()
    cached = _CAPS_CACHE.get("value")
    expires = _CAPS_CACHE.get("expires_at", 0)

    if cached is not None and now < expires:
        return cached

    caps = get_capabilities()
    _CAPS_CACHE["value"] = caps
    _CAPS_CACHE["expires_at"] = now + _CAPS_TTL_SECONDS
    return caps


def get_capabilities() -> dict[str, object]:
    checked_at = datetime.now(timezone.utc).isoformat()
    providers: list[dict[str, Any]] = []

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

    return {
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "gateway_version": _gateway_version(),
        "interface_version": INTERFACE_VERSION,
        "intents": {
            "supported": list(CAPABILITIES_INTENT_TYPES),
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
        },
        "providers": providers,
        "surfaces": {
            "tail": True,
            "snapshot": True,
            "events": False,
            "ingress_intent": True,
        },
    }


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


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
