from __future__ import annotations

import os
from typing import Any, Mapping, Sequence

import httpx

from .errors import ProviderError


def _base_url() -> str:
    return os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")


def _max_tokens(default: int) -> int:
    raw = os.getenv("OPENAI_MAX_TOKENS", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _token_param_name(model_id: str) -> str:
    if model_id.startswith(("o1", "o3", "gpt-4.1")):
        return "max_completion_tokens"
    return "max_tokens"


def execute(*, model_id: str, messages: list[dict[str, str]], api_key: str | None = None, **_: Any) -> str:
    key = (api_key or os.getenv("OPENAI_API_KEY", "")).strip()
    if not key:
        raise ProviderError("missing OpenAI credentials")

    if not isinstance(messages, list) or not messages:
        raise ProviderError("invalid messages")

    headers = {"authorization": f"Bearer {key}", "content-type": "application/json"}
    if _use_responses(model_id):
        message = _extract_user_content(messages)
        if not message:
            raise ProviderError("no user message")
        return _execute_responses(message, model_id, headers)
    return _execute_chat_messages(messages, model_id, headers)


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
        "max_output_tokens": _max_tokens(1024),
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
    }
    payload[_token_param_name(model_id)] = _max_tokens(1024)  # Increased for context scenarios
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
