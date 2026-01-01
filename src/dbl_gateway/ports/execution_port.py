from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class ExecutionResult:
    output_text: str | None = None
    provider: str | None = None
    model_id: str | None = None
    trace: dict[str, Any] | None = None
    trace_digest: str | None = None
    error: dict[str, Any] | None = None


class ExecutionPort(Protocol):
    async def run(self, intent_event: Mapping[str, Any]) -> ExecutionResult:
        ...
