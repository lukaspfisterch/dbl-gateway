from __future__ import annotations

from .adapters.execution_adapter_kl import KlExecutionAdapter, schedule_execution
from .ports.execution_port import ExecutionResult

__all__ = [
    "ExecutionResult",
    "KlExecutionAdapter",
    "run_execution",
    "schedule_execution",
]


async def run_execution(intent_event):
    return await KlExecutionAdapter().run(intent_event)
