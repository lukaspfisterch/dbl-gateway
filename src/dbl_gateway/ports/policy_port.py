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


class PolicyPort(Protocol):
    def decide(self, authoritative_input: Mapping[str, Any]) -> DecisionResult:
        ...
