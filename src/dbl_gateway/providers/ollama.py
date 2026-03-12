from __future__ import annotations
import json as _json
import os
from typing import Any
import httpx
from .contract import ProviderCapabilities, ProviderFeatures, ProviderLimits
from .errors import ProviderError
from ..ports.execution_port import NormalizedResponse


def get_capabilities() -> ProviderCapabilities:
    return ProviderCapabilities(
        provider_id="ollama",
        features=ProviderFeatures(streaming=False, tools=False, json_mode=False),
        limits=ProviderLimits(
            max_output_tokens=4096,
            default_max_tokens=4096,
            timeout_seconds=240.0,
        ),
        requires_api_key=False,
        execution_mode="http",
    )


def _base_url() -> str:
    val = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST")
    if val and not val.startswith(("http://", "https://")):
        val = f"http://{val}"
    return (val or "http://localhost:11434").rstrip("/")

def execute(*, model_id: str, messages: list[dict[str, str]], base_url: str | None = None, max_tokens: int | None = None, **_: Any) -> NormalizedResponse:
    url = f"{(base_url or _base_url())}/api/chat"
    payload: dict[str, Any] = {"model": model_id, "messages": messages, "stream": False}
    if max_tokens is not None:
        payload.setdefault("options", {})["num_predict"] = max_tokens

    try:
        with httpx.Client(timeout=httpx.Timeout(240.0)) as client:
            resp = client.post(url, json=payload)
            if resp.status_code >= 400:
                data = {}
                try:
                    data = resp.json()
                except Exception:
                    pass
                err = ProviderError(str(data.get("error") or f"HTTP {resp.status_code}"))
                err.status_code = resp.status_code
                err.code = "ollama.http_error"
                raise err

            data = resp.json()
            msg = data.get("message", {})
            text = str(msg.get("content", "") or "")
            tool_calls: list[dict[str, Any]] = []
            for tc in msg.get("tool_calls", []):
                func = tc.get("function", {})
                tool_calls.append({
                    "tool_name": func.get("name", ""),
                    "arguments": func.get("arguments", {}),
                })
            return NormalizedResponse(text=text, tool_calls=tool_calls)
    except httpx.TimeoutException as ex:
        err = ProviderError(f"timeout: {ex}")
        err.code = "timeout"
        raise err
