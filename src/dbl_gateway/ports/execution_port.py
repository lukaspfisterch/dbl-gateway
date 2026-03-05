from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class NormalizedResponse:
    """Provider-agnostic response. Providers return this instead of raw str."""
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionResult:
    output_text: str | None = None
    provider: str | None = None
    model_id: str | None = None
    trace: dict[str, Any] | None = None
    trace_digest: str | None = None
    error: dict[str, Any] | None = None
    render_digest: str | None = None
    render_manifest: dict[str, Any] | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_blocked: list[dict[str, Any]] | None = None
    usage: dict[str, Any] | None = None


class ExecutionPort(Protocol):
    async def run(
        self,
        intent_event: Mapping[str, Any],
        *,
        model_messages: Sequence[Mapping[str, str]] | None = None,
        llm_semaphore: asyncio.Semaphore | None = None,
        llm_wall_clock_s: int | None = None,
        permitted_tools: list[str] | None = None,
        tool_scope_enforced: str | None = None,
        enforced_budget: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        """
        Execute the intent.

        Args:
            intent_event: The INTENT event record
            model_messages: Optional pre-assembled messages from context builder.
                           If provided, these are used instead of extracting from payload.
                           This ensures declared_refs content flows into execution.
            llm_semaphore: Optional semaphore to gate provider calls.
            llm_wall_clock_s: Optional wall clock timeout for provider calls.
            permitted_tools: Tool names allowed by DECISION. None = no tool gating.
            tool_scope_enforced: "strict" or "advisory". None = no tool gating.
            enforced_budget: Budget constraints from DECISION. None = no budget.
        """
        ...
