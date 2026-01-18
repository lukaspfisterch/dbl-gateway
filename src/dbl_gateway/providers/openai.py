from __future__ import annotations

import os
from typing import Any, Mapping, Sequence

import httpx

from .errors import ProviderError


def execute(
    message: str | None = None,
    model_id: str = "",
    *,
    messages: Sequence[Mapping[str, str]] | None = None,
) -> str:
    """
    Execute a chat completion.
    
    Args:
        message: Single user message (legacy interface)
        model_id: Model to use
        messages: Pre-assembled messages list (takes precedence over message)
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ProviderError("missing OpenAI credentials")
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # Use messages list if provided, otherwise build from single message
    if messages is not None:
        chat_messages = [dict(m) for m in messages]
    elif message is not None:
        chat_messages = [{"role": "user", "content": message}]
    else:
        raise ProviderError("either message or messages must be provided")
    
    if _use_responses(model_id):
        # Responses API still needs single message for now
        user_content = _extract_user_content(chat_messages)
        return _execute_responses(user_content, model_id, headers)
    return _execute_chat_messages(chat_messages, model_id, headers)


def _extract_user_content(messages: list[dict[str, str]]) -> str:
    """Extract user content from messages list for legacy APIs."""
    for m in reversed(messages):
        if m.get("role") == "user":
            return m.get("content", "")
    return ""


def _use_responses(model_id: str) -> bool:
    if model_id.startswith("gpt-5"):
        return True
    return model_id in _responses_models()


def _responses_models() -> list[str]:
    raw = os.getenv("OPENAI_RESPONSES_MODEL_IDS", "").strip()
    if not raw:
        return ["gpt-5.2"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _execute_responses(message: str, model_id: str, headers: dict[str, str]) -> str:
    payload: dict[str, Any] = {
        "model": model_id,
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": message}],
            }
        ],
    }
    with httpx.Client(timeout=30.0) as client:
        resp = client.post("https://api.openai.com/v1/responses", json=payload, headers=headers)
        if resp.status_code >= 400:
            _raise_openai(resp, "openai.responses failed")
        data = resp.json()
    return _parse_response_text(data)


def _execute_chat_messages(messages: list[dict[str, str]], model_id: str, headers: dict[str, str]) -> str:
    """Execute chat completion with full messages list."""
    payload: dict[str, Any] = {
        "model": model_id,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1024,  # Increased for context scenarios
    }
    with httpx.Client(timeout=30.0) as client:
        resp = client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
        if resp.status_code >= 400:
            _raise_openai(resp, "openai.chat failed")
        data = resp.json()
    return _parse_chat_text(data)


def _parse_chat_text(data: dict[str, Any]) -> str:
    choices = data.get("choices", [])
    if not choices:
        return ""
    message = choices[0].get("message", {})
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _parse_response_text(data: dict[str, Any]) -> str:
    outputs = data.get("output", [])
    parts: list[str] = []
    for item in outputs:
        content = item.get("content", [])
        for entry in content:
            if entry.get("type") == "output_text":
                text = entry.get("text")
                if isinstance(text, str):
                    parts.append(text)
    return "\n".join(parts)


def _raise_openai(resp: httpx.Response, where: str) -> None:
    code = None
    msg = None
    try:
        j = resp.json()
        err = j.get("error") if isinstance(j, dict) else None
        if isinstance(err, dict):
            code = err.get("code")
            msg = err.get("message")
    except Exception:
        pass
    detail = msg or resp.text[:500]
    raise ProviderError(
        f"{where}: {detail}",
        status_code=resp.status_code,
        code=str(code) if code else None,
    )
