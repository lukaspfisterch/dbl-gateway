from __future__ import annotations

import os
from typing import Any

import httpx

from .errors import ProviderError


def _max_tokens(default: int) -> int:
    raw = os.getenv("ANTHROPIC_MAX_TOKENS", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def execute(*, model_id: str, messages: list[dict[str, str]], api_key: str | None = None, **_: Any) -> str:
    key = (api_key or os.getenv("ANTHROPIC_API_KEY", "")).strip()
    if not key:
        raise ProviderError("missing Anthropic credentials")

    # Use last user content as primary input; include full messages for 3.0 API if needed later
    last_user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), None)
    if not last_user:
        raise ProviderError("no user message")

    headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    payload: dict[str, Any] = {
        "model": model_id,
        "max_tokens": _max_tokens(256),
        "messages": [{"role": "user", "content": [{"type": "text", "text": last_user}]}],
        "temperature": 0.2,
    }

    with httpx.Client(timeout=60.0) as client:
        try:
            resp = client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
        except httpx.RequestError as exc:
             raise ProviderError(f"connection error: {str(exc)}") from exc
             
        if resp.status_code >= 400:
            try:
                data = resp.json()
            except Exception:
                data = {}
            msg = data.get("error", {}).get("message") or f"HTTP {resp.status_code}"
            err = ProviderError(msg)
            err.status_code = resp.status_code
            err.code = data.get("error", {}).get("type")
            raise err
        
        data = resp.json()
        blocks = data.get("content", [])
        text = "".join([b.get("text", "") for b in blocks if b.get("type") == "text"])
        return str(text or "")
