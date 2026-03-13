"""Stub provider for zero-config demo mode.

Two modes selected via STUB_MODE env:

* ``echo`` (default) -- mirrors the user message back, predictable for contract
  testing.  Response is obviously synthetic.
* ``scenario`` -- rotates through a small built-in sequence of canned responses
  that match the governance-demo steps.  Rotation is deterministic by turn index
  so replay produces identical output.

Both modes go through the full governance pipeline -- no shortcuts.
"""

from __future__ import annotations

import os
from typing import Any

from .contract import ProviderCapabilities, ProviderFeatures, ProviderLimits
from ..ports.execution_port import NormalizedResponse


STUB_MODEL_IDS: list[str] = ["stub-echo", "stub-scenario"]

_SCENARIO_RESPONSES: list[str] = [
    (
        "Hello! I am the stub provider running in scenario mode. "
        "This response traveled through the full governance pipeline: "
        "INTENT, DECISION, EXECUTION."
    ),
    (
        "Follow-up acknowledged. Each turn produces a new event chain "
        "that the observer UI displays in real time."
    ),
    (
        "Tools and budget received. In a real deployment the policy "
        "would gate tool access and enforce budget limits before "
        "execution reaches the provider."
    ),
    (
        "This response should never appear -- the governance layer "
        "should have denied this turn before it reached execution."
    ),
    (
        "Recovery successful. The governance pipeline resumed normal "
        "operation after the intentional deny."
    ),
]


def get_capabilities() -> ProviderCapabilities:
    return ProviderCapabilities(
        provider_id="stub",
        features=ProviderFeatures(streaming=False, tools=False, json_mode=False),
        limits=ProviderLimits(
            max_output_tokens=1024,
            default_max_tokens=256,
            timeout_seconds=1.0,
        ),
        requires_api_key=False,
        execution_mode="local",
    )


def execute(
    *,
    model_id: str,
    messages: list[dict[str, str]],
    max_tokens: int | None = None,
    **_: Any,
) -> NormalizedResponse:
    mode = os.getenv("STUB_MODE", "echo").lower()

    # Extract last user message
    last_user_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg.get("content", "")
            break

    if mode == "scenario":
        # Deterministic rotation by number of user messages
        user_count = sum(1 for m in messages if m.get("role") == "user")
        idx = (user_count - 1) % len(_SCENARIO_RESPONSES)
        text = _SCENARIO_RESPONSES[idx]
    else:
        # Echo mode (default)
        text = f"[stub-echo] You said: {last_user_msg}"

    return NormalizedResponse(text=text)
