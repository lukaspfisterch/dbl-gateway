from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Mapping

from dbl_core import normalize_trace

from ..ports.execution_port import ExecutionPort, ExecutionResult
from ..providers import anthropic, openai
from ..providers.errors import ProviderError
from ..capabilities import resolve_provider


@dataclass(frozen=True)
class KlExecutionAdapter(ExecutionPort):
    async def run(self, intent_event: Mapping[str, Any]) -> ExecutionResult:
        payload = intent_event.get("payload")
        if not isinstance(payload, Mapping):
            return ExecutionResult(error={"message": "invalid payload"})
        requested_model_id = payload.get("requested_model_id")
        model_id = str(requested_model_id) if requested_model_id else ""
        provider, reason = resolve_provider(model_id)
        if provider is None or reason is not None:
            return ExecutionResult(
                provider=provider,
                model_id=model_id,
                error={"provider": provider, "message": reason or "model.unavailable"},
            )
        message = _extract_message(payload)
        if message is None:
            return ExecutionResult(provider=provider, model_id=model_id, error={"message": "input.invalid"})
        call = _select_provider(provider)
        try:
            output_text, trace, trace_digest, error = await _call_kernel(message, model_id, provider, call)
            return ExecutionResult(
                output_text=output_text,
                provider=provider,
                model_id=model_id,
                trace=trace,
                trace_digest=trace_digest,
                error=error,
            )
        except Exception:
            return ExecutionResult(
                provider=provider,
                model_id=model_id,
                error={
                    "provider": provider,
                    "message": "execution failed",
                },
            )


def schedule_execution(coro: asyncio.Task | asyncio.Future | Any) -> None:
    asyncio.create_task(coro)


def _select_provider(name: str):
    if name == "openai":
        return openai.execute
    if name == "anthropic":
        return anthropic.execute
    raise RuntimeError("unsupported provider")


async def _call_kernel(message: str, model_id: str, provider: str, provider_call):
    import kl_kernel_logic

    psi = kl_kernel_logic.PsiDefinition(
        psi_type="llm",
        name=provider,
        metadata={"model_id": model_id},
    )
    kernel = kl_kernel_logic.Kernel()

    def _task(message: str, model_id: str) -> dict[str, object]:
        try:
            return {"ok": True, "output": provider_call(message, model_id)}
        except ProviderError as exc:
            return {
                "ok": False,
                "error": {
                    "status_code": exc.status_code,
                    "code": exc.code,
                    "message": str(exc),
                },
            }

    trace = await asyncio.to_thread(
        kernel.execute,
        psi=psi,
        task=_task,
        metadata={"provider": provider, "model_id": model_id},
        message=message,
        model_id=model_id,
    )
    trace_dict, trace_digest_value = normalize_trace(trace)
    if not trace.success:
        return (
            "",
            trace_dict,
            trace_digest_value,
            {
                "provider": provider,
                "message": trace.error or "execution failed",
                "failure_code": getattr(trace.failure_code, "value", None),
            },
        )
    output = trace.output
    if isinstance(output, dict) and output.get("ok") is False:
        err = output.get("error") if isinstance(output.get("error"), dict) else {}
        return (
            "",
            trace_dict,
            trace_digest_value,
            {
                "provider": provider,
                "status_code": err.get("status_code"),
                "code": err.get("code"),
                "message": str(err.get("message") or "execution failed"),
            },
        )
    if isinstance(output, dict) and "output" in output:
        return str(output.get("output") or ""), trace_dict, trace_digest_value, None
    return str(output or ""), trace_dict, trace_digest_value, None


def _extract_message(payload: Mapping[str, Any]) -> str | None:
    message = payload.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    return None
