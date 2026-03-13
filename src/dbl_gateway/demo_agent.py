from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


DEMO_SCENARIO_NAME = "governance-demo"
DEMO_SCENARIO_VERSION = "1"
DEMO_SCENARIO_DESCRIPTION = (
    "Deterministic governance demonstration: 3 ALLOW turns -> 1 intentional DENY -> recovery."
)


@dataclass(frozen=True)
class DemoStep:
    name: str
    description: str
    expected: str
    payload: dict[str, Any] = field(default_factory=dict)
    pause_s: float = 2.0


def default_steps(step_delay: float = 2.0) -> list[DemoStep]:
    return [
        DemoStep(
            name="hello",
            description="Normal greeting turn to establish the stream.",
            expected="ALLOW->EXECUTION",
            payload={"message": "Hello from the demo agent."},
            pause_s=step_delay,
        ),
        DemoStep(
            name="follow-up",
            description="Second normal turn so the observer shows continuity across turns.",
            expected="ALLOW->EXECUTION",
            payload={"message": "Follow-up question from the demo agent."},
            pause_s=step_delay,
        ),
        DemoStep(
            name="tools-and-budget",
            description="Declared tools and budget so DECISION exposes tool and budget fields.",
            expected="ALLOW->EXECUTION",
            payload={
                "message": "Search the docs if needed, but stay within budget.",
                "declared_tools": ["web.search"],
                "tool_scope": "strict",
                "budget": {"max_tokens": 512, "max_duration_ms": 8000},
            },
            pause_s=step_delay,
        ),
        DemoStep(
            name="policy-deny",
            description="Intentional invalid governance shape to trigger a deterministic DENY.",
            expected="DENY",
            payload={
                "message": "This turn should fail governance shape validation.",
                "inputs": {
                    "principal_id": "demo-user",
                    "extensions": {"note": "nested objects are not scalar"},
                },
            },
            pause_s=step_delay,
        ),
        DemoStep(
            name="recovery",
            description="Return to a valid turn so the demo ends on a healthy path.",
            expected="ALLOW->EXECUTION",
            payload={"message": "Recovery turn after the intentional deny."},
            pause_s=step_delay,
        ),
    ]


def active_provider_model(capabilities: Mapping[str, Any]) -> tuple[str, str] | None:
    providers = capabilities.get("providers") or []
    for provider in providers:
        provider_id = str(provider.get("id") or "unknown")
        for model in provider.get("models") or []:
            health_info = model.get("health") or {}
            if health_info.get("status") == "ok":
                return provider_id, str(model.get("id") or "")
    return None


def scenario_metadata(step_delay: float = 2.0) -> dict[str, Any]:
    steps = default_steps(step_delay)
    return {
        "name": DEMO_SCENARIO_NAME,
        "version": DEMO_SCENARIO_VERSION,
        "description": DEMO_SCENARIO_DESCRIPTION,
        "steps": [asdict(step) for step in steps],
    }


def build_envelope(
    *,
    step: DemoStep,
    requested_model_id: str,
    stream_id: str,
    lane: str,
    actor: str,
    thread_id: str,
    turn_id: str,
    parent_turn_id: str | None,
) -> dict[str, Any]:
    return {
        "interface_version": 3,
        "correlation_id": uuid.uuid4().hex,
        "payload": {
            "stream_id": stream_id,
            "lane": lane,
            "actor": actor,
            "intent_type": "chat.message",
            "thread_id": thread_id,
            "turn_id": turn_id,
            "parent_turn_id": parent_turn_id,
            "requested_model_id": requested_model_id,
            "payload": dict(step.payload),
        },
    }
