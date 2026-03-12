from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from dbl_core import normalize_trace

from ..ports.execution_port import ExecutionPort, ExecutionResult, NormalizedResponse
from ..providers import PROVIDER_MODULES
from ..providers.errors import ProviderError
from ..capabilities import resolve_model, resolve_provider

_LOGGER = logging.getLogger("dbl_gateway")


@dataclass(frozen=True)
class KlExecutionAdapter(ExecutionPort):
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

        if model_messages is not None:
            messages = list(model_messages)
        else:
            message = _extract_message(payload)
            if message is None:
                return ExecutionResult(provider=provider, model_id=resolved_model, error={"message": "input.invalid"})
            messages = [{"role": "user", "content": message}]

        # Extract max_tokens from enforced_budget for provider passthrough
        max_tokens_budget: int | None = None
        if enforced_budget:
            max_tokens_budget = enforced_budget.get("max_tokens")

        call = _select_provider(provider)
        exec_start = time.monotonic()
        try:
            output_text, trace, trace_digest, error, raw_tool_calls = await _execute_llm_call(
                messages,
                resolved_model,
                provider,
                call,
                llm_semaphore=llm_semaphore,
                llm_wall_clock_s=llm_wall_clock_s,
                max_tokens=max_tokens_budget,
            )
            duration_ms = int((time.monotonic() - exec_start) * 1000)

            # Tool enforcement
            tool_calls_out: list[dict[str, Any]] = []
            tool_blocked_out: list[dict[str, Any]] = []
            if raw_tool_calls and permitted_tools is not None:
                permitted_set = set(permitted_tools)
                for tc in raw_tool_calls:
                    tc_name = tc.get("tool_name", "")
                    if tc_name in permitted_set:
                        tool_calls_out.append(tc)
                    elif tool_scope_enforced == "strict":
                        tool_blocked_out.append({
                            "tool_call": tc_name,
                            "reason": "not_in_permitted_tools",
                        })
                    else:
                        # advisory: log but allow
                        _LOGGER.warning("tool_scope=advisory: allowing undeclared tool %s", tc_name)
                        tool_calls_out.append(tc)
            elif raw_tool_calls:
                tool_calls_out = raw_tool_calls

            usage: dict[str, Any] = {"duration_ms": duration_ms}

            return ExecutionResult(
                output_text=output_text,
                provider=provider,
                model_id=resolved_model,
                trace=trace,
                trace_digest=trace_digest,
                error=error,
                tool_calls=tool_calls_out or None,
                tool_blocked=tool_blocked_out or None,
                usage=usage,
            )
        except asyncio.TimeoutError:
            duration_ms = int((time.monotonic() - exec_start) * 1000)
            return ExecutionResult(
                provider=provider,
                model_id=resolved_model,
                error={
                    "provider": provider,
                    "code": "llm.timeout",
                    "message": f"wall clock exceeded {llm_wall_clock_s}s",
                },
                usage={"duration_ms": duration_ms},
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
    mod = PROVIDER_MODULES.get(name)
    if mod is None:
        raise RuntimeError(f"unsupported provider: {name}")
    return mod.execute


def _run_kernel_sync(
    messages: list[dict[str, str]],
    model_id: str,
    provider: str,
    provider_call,
    *,
    max_tokens: int | None = None,
):
    import kl_kernel_logic

    psi = kl_kernel_logic.PsiDefinition(
        psi_type="llm",
        name=provider,
        metadata={"model_id": model_id},
    )
    kernel = kl_kernel_logic.Kernel()

    def _task(messages: list[dict[str, str]], model_id: str) -> dict[str, object]:
        try:
            # Provider returns NormalizedResponse; unpack for kernel trace
            resp: NormalizedResponse = provider_call(
                model_id=model_id,
                messages=messages,
                max_tokens=max_tokens,
            )
            return {
                "ok": True,
                "output": resp.text,
                "tool_calls": resp.tool_calls,
            }
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
    """Return 5-tuple: (output_text, trace_dict, trace_digest, error, raw_tool_calls)."""
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
            [],
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
            [],
        )
    if isinstance(output, dict) and "output" in output:
        tool_calls = output.get("tool_calls", [])
        return str(output.get("output") or ""), trace_dict, trace_digest_value, None, tool_calls
    return str(output or ""), trace_dict, trace_digest_value, None, []


async def _call_kernel(
    messages: list[dict[str, str]],
    model_id: str,
    provider: str,
    provider_call,
    *,
    offload: bool = True,
    max_tokens: int | None = None,
):
    if offload:
        trace = await asyncio.to_thread(
            _run_kernel_sync,
            messages,
            model_id,
            provider,
            provider_call,
            max_tokens=max_tokens,
        )
    else:
        trace = _run_kernel_sync(
            messages, model_id, provider, provider_call, max_tokens=max_tokens,
        )
    return _normalize_kernel_trace(trace, provider, model_id)


async def _execute_llm_call(
    messages: list[dict[str, str]],
    model_id: str,
    provider: str,
    provider_call,
    *,
    llm_semaphore: asyncio.Semaphore | None,
    llm_wall_clock_s: int | None,
    max_tokens: int | None = None,
):
    async def _run():
        return await _call_kernel(
            messages, model_id, provider, provider_call, max_tokens=max_tokens,
        )

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
