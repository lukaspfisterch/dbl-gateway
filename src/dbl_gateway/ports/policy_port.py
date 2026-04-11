from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class DecisionResult:
    decision: str
    reason_codes: list[str]
    policy_id: str | None = None
    policy_version: str | None = None
    gate_event: object | None = None
    declared_tool_families: list[str] | None = None
    allowed_tool_families: list[str] | None = None
    permitted_tool_families: list[str] | None = None
    permitted_tools: list[str] | None = None
    tool_scope_enforced: str | None = None
    tools_denied: list[str] | None = None
    tools_denied_reason: str | None = None
    enforced_budget: dict[str, Any] | None = None
    policy_config_digest: str | None = None


class PolicyPort(Protocol):
    def decide(self, authoritative_input: Mapping[str, Any]) -> DecisionResult:
        ...
