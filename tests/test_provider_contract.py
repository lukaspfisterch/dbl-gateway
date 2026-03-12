"""Verify every registered provider conforms to the provider contract."""
from __future__ import annotations

import pytest

from dbl_gateway.providers import PROVIDER_MODULES, get_provider_capabilities
from dbl_gateway.providers.contract import ProviderCapabilities


PROVIDER_NAMES = sorted(PROVIDER_MODULES.keys())


@pytest.mark.parametrize("name", PROVIDER_NAMES)
def test_provider_has_get_capabilities(name: str) -> None:
    mod = PROVIDER_MODULES[name]
    assert hasattr(mod, "get_capabilities"), f"{name} missing get_capabilities()"
    assert callable(mod.get_capabilities)


@pytest.mark.parametrize("name", PROVIDER_NAMES)
def test_provider_capabilities_valid(name: str) -> None:
    caps = get_provider_capabilities(name)
    assert isinstance(caps, ProviderCapabilities)
    assert caps.provider_id == name
    assert caps.limits.max_output_tokens > 0
    assert caps.limits.default_max_tokens > 0
    assert caps.limits.timeout_seconds > 0
    assert caps.execution_mode in {"http", "local", "rpc"}


@pytest.mark.parametrize("name", PROVIDER_NAMES)
def test_provider_has_execute(name: str) -> None:
    mod = PROVIDER_MODULES[name]
    assert hasattr(mod, "execute"), f"{name} missing execute()"
    assert callable(mod.execute)


def test_unknown_provider_raises() -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        get_provider_capabilities("nonexistent")
