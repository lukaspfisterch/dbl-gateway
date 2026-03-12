from __future__ import annotations

from types import ModuleType

from . import anthropic, ollama, openai
from .contract import ProviderCapabilities

__all__ = ["openai", "anthropic", "ollama", "errors"]

PROVIDER_MODULES: dict[str, ModuleType] = {
    "openai": openai,
    "anthropic": anthropic,
    "ollama": ollama,
}


def get_provider_capabilities(name: str) -> ProviderCapabilities:
    mod = PROVIDER_MODULES.get(name)
    if mod is None:
        raise ValueError(f"unknown provider: {name}")
    return mod.get_capabilities()
