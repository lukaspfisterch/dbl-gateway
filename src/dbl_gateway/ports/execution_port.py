from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class ExecutionResult:
    output_text: str | None = None
    provider: str | None = None
    model_id: str | None = None
    trace: dict[str, Any] | None = None
    trace_digest: str | None = None
    error: dict[str, Any] | None = None


class ExecutionPort(Protocol):
    async def run(
        self, 
        intent_event: Mapping[str, Any],
        *,
        model_messages: Sequence[Mapping[str, str]] | None = None,
    ) -> ExecutionResult:
        """
        Execute the intent.
        
        Args:
            intent_event: The INTENT event record
            model_messages: Optional pre-assembled messages from context builder.
                           If provided, these are used instead of extracting from payload.
                           This ensures declared_refs content flows into execution.
        """
        ...

