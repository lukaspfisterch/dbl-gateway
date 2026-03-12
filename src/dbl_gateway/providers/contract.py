from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel

from ..ports.execution_port import NormalizedResponse


class ProviderFeatures(BaseModel):
    streaming: bool
    tools: bool
    json_mode: bool


class ProviderLimits(BaseModel):
    max_output_tokens: int
    default_max_tokens: int
    timeout_seconds: float


class ProviderCapabilities(BaseModel):
    provider_id: str
    features: ProviderFeatures
    limits: ProviderLimits
    requires_api_key: bool
    execution_mode: Literal["http", "local", "rpc"]


class ProviderProtocol(Protocol):
    def execute(
        self,
        *,
        model_id: str,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
    ) -> NormalizedResponse: ...

    def get_capabilities(self) -> ProviderCapabilities: ...
