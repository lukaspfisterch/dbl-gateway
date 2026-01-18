from __future__ import annotations
import os
from typing import Any
import httpx
from .errors import ProviderError

def _base_url() -> str:
    return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

def execute(*, model_id: str, messages: list[dict[str, str]], base_url: str | None = None, **_: Any) -> str:
    url = f"{(base_url or _base_url())}/api/chat"
    payload = {"model": model_id, "messages": messages, "stream": False}

    try:
        with httpx.Client(timeout=httpx.Timeout(120.0)) as client:
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
            # Chat endpoint returns {"message": {"role": "...", "content": "..."}}
            msg = data.get("message", {})
            return str(msg.get("content", "") or "")
    except httpx.TimeoutException as ex:
        err = ProviderError(f"timeout: {ex}")
        err.code = "timeout"
        raise err
