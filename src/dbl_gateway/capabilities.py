from __future__ import annotations

import os


def get_capabilities() -> dict[str, object]:
    models = _available_models()
    allowed_model_ids = [model["model_id"] for model in models]
    default_model_id = _default_model_id(allowed_model_ids)
    return {
        "allowed_model_ids": allowed_model_ids,
        "default_model_id": default_model_id,
    }


def _available_models() -> list[dict[str, str]]:
    models: list[dict[str, str]] = []
    if _get_openai_key():
        for model_id in _openai_models():
            models.append({"provider": "openai", "model_id": model_id})
    if _get_anthropic_key():
        for model_id in _anthropic_models():
            models.append({"provider": "anthropic", "model_id": model_id})
    return models


def resolve_provider(model_id: str) -> tuple[str | None, str | None]:
    if model_id in _openai_models():
        if not _get_openai_key():
            return None, "provider.missing_credentials"
        return "openai", None
    if model_id in _anthropic_models():
        if not _get_anthropic_key():
            return None, "provider.missing_credentials"
        return "anthropic", None
    return None, "model.unavailable"


def _openai_models() -> list[str]:
    chat_models = _parse_csv("OPENAI_CHAT_MODEL_IDS")
    if not chat_models:
        chat_models = _parse_csv("OPENAI_MODEL_IDS")
    if not chat_models:
        chat_models = ["gpt-4o-mini"]
    response_models = _parse_csv("OPENAI_RESPONSES_MODEL_IDS") or []
    combined: list[str] = []
    seen: set[str] = set()
    for model_id in chat_models + response_models:
        if model_id in seen:
            continue
        seen.add(model_id)
        combined.append(model_id)
    return combined


def _anthropic_models() -> list[str]:
    models = _parse_csv("ANTHROPIC_MODEL_IDS")
    return models or ["claude-3-haiku-20240307"]


def _default_model_id(allowed: list[str]) -> str | None:
    if not allowed:
        return None
    return allowed[0]


def _get_openai_key() -> str:
    return os.getenv("OPENAI_API_KEY", "").strip()


def _get_anthropic_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _parse_csv(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
