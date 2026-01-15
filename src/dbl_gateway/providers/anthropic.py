from __future__ import annotations

import os
from typing import Any

import httpx

from .errors import ProviderError


def execute(message: str, model_id: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise ProviderError("missing Anthropic credentials")
    
    # Use defensive default if model_id is empty or suspicious
    if not model_id or not model_id.strip():
        model_id = _default_model()
    
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    
    payload: dict[str, Any] = {
        "model": model_id,
        "max_tokens": 256,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": message}]}
        ],
        "temperature": 0.2,  # Defensive: reduce randomness for consistent behavior
    }
    
    with httpx.Client(timeout=60.0) as client:
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            json=payload,
            headers=headers
        )
        if resp.status_code >= 400:
            _raise_anthropic(resp)
        data = resp.json()
    
    return _parse_text(data)


def _default_model() -> str:
    """Defensive default: use environment override or fall back to reliable model."""
    raw = os.getenv("ANTHROPIC_DEFAULT_MODEL", "").strip()
    if raw:
        return raw
    # claude-3-5-sonnet-20241022 is stable, fast, and cost-effective
    return "claude-3-5-sonnet-20241022"


def _parse_text(data: dict[str, Any]) -> str:
    content = data.get("content", [])
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for entry in content:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "text":
            text = entry.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def _raise_anthropic(resp: httpx.Response) -> None:
    code = None
    msg = None
    try:
        j = resp.json()
        err = j.get("error") if isinstance(j, dict) else None
        if isinstance(err, dict):
            code = err.get("type")
            msg = err.get("message")
    except Exception:
        pass
    detail = msg or resp.text[:500]
    raise ProviderError(
        f"anthropic.messages failed: {detail}",
        status_code=resp.status_code,
        code=str(code) if code else None,
    )