from __future__ import annotations

from typing import Any, Mapping

from ...contracts import AssembledContext


def render_delta_v1(
    *,
    assembled_context: AssembledContext,
    task: str | None,
) -> dict[str, Any]:
    messages = assembled_context.get("model_messages") or []
    if not messages and task:
        messages = [{"role": "user", "content": task}]
    return {"messages": list(messages)}


def build_manifest_delta_v1(
    *,
    assembled_context: AssembledContext,
    task: str | None,
) -> dict[str, Any]:
    refs = []
    for ref in assembled_context.get("assembled_from") or []:
        if isinstance(ref, Mapping):
            ref_id = ref.get("ref_id")
            if isinstance(ref_id, str):
                refs.append(ref_id)
    return {
        "spec": "render.delta_v1",
        "message_count": len(assembled_context.get("model_messages") or []),
        "task_present": bool(task),
        "refs": refs,
    }
