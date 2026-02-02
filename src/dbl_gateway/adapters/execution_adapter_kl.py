from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from dbl_core import normalize_trace

from ..ports.execution_port import ExecutionPort, ExecutionResult
from ..providers import anthropic, openai, ollama
from ..providers.errors import ProviderError
from ..capabilities import resolve_model, resolve_provider


@dataclass(frozen=True)
class KlExecutionAdapter(ExecutionPort):
    async def run(
        self, 
        intent_event: Mapping[str, Any],
        *,
        model_messages: Sequence[Mapping[str, str]] | None = None,
        llm_semaphore: asyncio.Semaphore | None = None,
        llm_wall_clock_s: int | None = None,
    ) -> ExecutionResult:
        payload = intent_event.get("payload")
        if not isinstance(payload, Mapping):
            return ExecutionResult(error={"message": "invalid payload"})
        requested_model_id = payload.get("requested_model_id")
        requested_model = str(requested_model_id) if requested_model_id else ""
        resolved_model, reason = resolve_model(requested_model)
        if resolved_model is None or reason is not None:
            return ExecutionResult(
                provider=None,
                model_id="",
                error={
                    "code": "model_unavailable",
                    "message": reason or "model.unavailable",
                },
            )
        provider, provider_reason = resolve_provider(resolved_model)
        if provider is None or provider_reason is not None:
            return ExecutionResult(
                provider=None,
                model_id=resolved_model,
                error={
                    "code": "model_unavailable",
                    "message": provider_reason or "model.unavailable",
                },
            )
        
        # Use model_messages if provided (from context builder with refs)
        # Otherwise fall back to extracting single message from payload
        if model_messages is not None:
            messages = list(model_messages)
        else:
            message = _extract_message(payload)
            if message is None:
                return ExecutionResult(provider=provider, model_id=resolved_model, error={"message": "input.invalid"})
            messages = [{"role": "user", "content": message}]
        
        call = _select_provider(provider)
        try:
            output_text, trace, trace_digest, error = await _execute_llm_call(
                messages,
                resolved_model,
                provider,
                call,
                llm_semaphore=llm_semaphore,
                llm_wall_clock_s=llm_wall_clock_s,
            )
            return ExecutionResult(
                output_text=output_text,
                provider=provider,
                model_id=resolved_model,
                trace=trace,
                trace_digest=trace_digest,
                error=error,
            )
        except asyncio.TimeoutError:
            return ExecutionResult(
                provider=provider,
                model_id=resolved_model,
                error={
                    "provider": provider,
                    "code": "llm.timeout",
                    "message": f"wall clock exceeded {llm_wall_clock_s}s",
                },
            )
        except Exception:
            return ExecutionResult(
                provider=provider,
                model_id=resolved_model,
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
    if name == "ollama":
        return ollama.execute
    raise RuntimeError("unsupported provider")


def _run_kernel_sync(messages: list[dict[str, str]], model_id: str, provider: str, provider_call):
    import kl_kernel_logic

    psi = kl_kernel_logic.PsiDefinition(
        psi_type="llm",
        name=provider,
        metadata={"model_id": model_id},
    )
    kernel = kl_kernel_logic.Kernel()

    def _task(messages: list[dict[str, str]], model_id: str) -> dict[str, object]:
        try:
            # Pass messages list to provider
            return {"ok": True, "output": provider_call(model_id=model_id, messages=messages)}
        except ProviderError as exc:
            return {
                "ok": False,
                "error": {
                    "status_code": exc.status_code,
                    "code": exc.code,
                    "message": str(exc),
                },
            }

    trace = kernel.execute(
        psi=psi,
        task=_task,
        metadata={"provider": provider, "model_id": model_id},
        messages=messages,
        model_id=model_id,
    )
    return trace


def _normalize_kernel_trace(trace, provider: str, model_id: str):
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


async def _call_kernel(messages: list[dict[str, str]], model_id: str, provider: str, provider_call, *, offload: bool = True):
    if offload:
        trace = await asyncio.to_thread(
            _run_kernel_sync,
            messages,
            model_id,
            provider,
            provider_call,
        )
    else:
        trace = _run_kernel_sync(messages, model_id, provider, provider_call)
    return _normalize_kernel_trace(trace, provider, model_id)


async def _execute_llm_call(
    messages: list[dict[str, str]],
    model_id: str,
    provider: str,
    provider_call,
    *,
    llm_semaphore: asyncio.Semaphore | None,
    llm_wall_clock_s: int | None,
):
    async def _run():
        return await _call_kernel(messages, model_id, provider, provider_call)

    async def _run_with_timeout():
        if llm_wall_clock_s and llm_wall_clock_s > 0:
            task = asyncio.create_task(_run())
            try:
                return await asyncio.wait_for(task, timeout=llm_wall_clock_s)
            except asyncio.TimeoutError:
                task.cancel()
                with suppress(Exception):
                    await task
                raise
        return await _run()

    if llm_semaphore is None:
        return await _run_with_timeout()

    async with llm_semaphore:
        return await _run_with_timeout()


def _extract_message(payload: Mapping[str, Any]) -> str | None:
    message = payload.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    return None
