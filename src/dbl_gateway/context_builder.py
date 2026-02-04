from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any, Mapping, Sequence

from .boundary import admit_model_messages
from .config import get_context_config, ContextConfig
from .models import EventRecord
from .ref_resolver import (
    resolve_declared_refs,
    ResolutionResult,
    RefResolutionError,
)
from dbl_gateway.contracts import (
    AssembledContext,
    ContextSpec,
    DeclaredRef,
    NormalizationRecord,
    ResolvedRef,
    context_digest,
)

__all__ = ["ContextArtifacts", "build_context", "build_context_with_refs", "RefResolutionError"]

# Version of ContextSpec schema (separate from config schema)
CONTEXT_SPEC_SCHEMA_VERSION = "ctxspec.2"

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContextArtifacts:
    context_spec: ContextSpec
    assembled_context: AssembledContext
    context_digest: str
    config_digest: str  # NEW: Config digest for DECISION materialization
    boundary_meta: Mapping[str, Any] | None = None
    transforms: list[dict[str, Any]] = field(default_factory=list)


def build_context(
    payload: Mapping[str, Any] | None,
    *,
    intent_type: str,
    config: ContextConfig | None = None,
) -> ContextArtifacts:
    """
    Deterministic assembly of ContextSpec, AssembledContext, and digest.
    
    Config-driven normalization:
    - Loads config from get_context_config() if not provided
    - Applies normalization rules from config
    - Materializes NormalizationRecord for replay verification
    
    Args:
        payload: Intent payload with message, thread_id, turn_id, declared_refs
        intent_type: The intent type (e.g., "chat.message")
        config: Optional config override for testing
        
    Returns:
        ContextArtifacts with context_spec, assembled_context, digests
    """
    if not isinstance(intent_type, str) or not intent_type.strip():
        raise ValueError("intent_type is required to build context")
    
    # Load config (cached)
    cfg = config or get_context_config()
    
    payload_obj: Mapping[str, Any] = payload if isinstance(payload, Mapping) else {}

    user_input = _extract_user_input(payload_obj)
    identity = _extract_identity(payload_obj)
    declared_refs = _extract_declared_refs(payload_obj)
    
    # Build normalization record (materializes what boundary did)
    normalization: NormalizationRecord = {
        "applied_rules": list(cfg.normalization_rules),
        "boundary_version": cfg.schema_version,
        "config_digest": cfg.config_digest,
    }
    
    # Resolved refs: empty for now (Step 2 will populate from declared_refs)
    # When declared_refs are resolved against store, they become ResolvedRef
    resolved_refs: list[ResolvedRef] = []

    context_spec: ContextSpec = {
        "identity": identity,
        "intent": {
            "intent_type": intent_type.strip(),
            "user_input": user_input,
        },
        "retrieval": {
            "declared_refs": declared_refs,
            "resolved_refs": resolved_refs,
            "normalization": normalization,
        },
        "assembly_rules": {
            "schema_version": CONTEXT_SPEC_SCHEMA_VERSION,
            "ordering": cfg.canonical_sort,
        },
    }

    raw_model_messages = _build_model_messages(user_input)
    admitted_model_messages, boundary_meta = admit_model_messages(raw_model_messages)
    transforms = _boundary_transforms(raw_model_messages, admitted_model_messages, boundary_meta)
    
    assembled_context: AssembledContext = {
        "model_messages": admitted_model_messages,
        "assembled_from": resolved_refs,  # Will match resolved_refs when populated
        "normative_input_digests": [],    # Will contain INTENT payload digests
    }
    
    context_digest_value = context_digest(context_spec, assembled_context)
    
    return ContextArtifacts(
        context_spec=context_spec,
        assembled_context=assembled_context,
        context_digest=context_digest_value,
        config_digest=cfg.config_digest,
        boundary_meta=boundary_meta,
        transforms=transforms,
    )


def _extract_identity(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    thread_id = payload.get("thread_id")
    turn_id = payload.get("turn_id")
    parent_turn_id = payload.get("parent_turn_id")
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise ValueError("thread_id is required for context assembly")
    if not isinstance(turn_id, str) or not turn_id.strip():
        raise ValueError("turn_id is required for context assembly")
    parent_value = parent_turn_id if parent_turn_id is None else str(parent_turn_id)
    return {
        "thread_id": thread_id.strip(),
        "turn_id": turn_id.strip(),
        "parent_turn_id": parent_value if parent_value is None else str(parent_value),
    }


def _extract_user_input(payload: Mapping[str, Any]) -> str:
    message = payload.get("message")
    if not isinstance(message, str):
        raise ValueError("payload.message must be a string")
    user_input = message.strip()
    if not user_input:
        raise ValueError("payload.message must not be empty")
    return user_input


def _extract_declared_refs(payload: Mapping[str, Any]) -> list[DeclaredRef]:
    refs = payload.get("declared_refs")
    if not isinstance(refs, Sequence):
        return []
    normalized: list[DeclaredRef] = []
    for item in refs:
        if not isinstance(item, Mapping):
            continue
        ref_type = item.get("ref_type")
        ref_id = item.get("ref_id")
        version = item.get("version")
        if not isinstance(ref_type, str) or not ref_type.strip():
            continue
        if not isinstance(ref_id, str) or not ref_id.strip():
            continue
        ref: DeclaredRef = {"ref_type": ref_type.strip(), "ref_id": ref_id.strip()}
        if version is not None:
            ref["version"] = str(version)
        normalized.append(ref)
    normalized.sort(key=lambda r: (r["ref_type"], r["ref_id"], r.get("version") or ""))
    return normalized


def _build_model_messages(
    user_input: str,
    resolved_refs: list[ResolvedRef] | None = None,
) -> list[dict[str, str]]:
    """
    Build model messages with optional context from resolved refs.
    
    If resolved_refs have content, prepend a system message with a
    deterministic, read-only context block. This ensures:
    - Refs declared become refs used (digest integrity)
    - No assistant role spoofing (security)
    - Clear audit trail (transparency)
    """
    messages: list[dict[str, str]] = []
    
    if resolved_refs:
        refs_block = _render_refs_block(resolved_refs)
        if refs_block:
            messages.append({"role": "system", "content": refs_block})
    
    messages.append({"role": "user", "content": user_input})
    return messages


def _resolve_auto_context(events: list[EventRecord], n: int, config: ContextConfig) -> list[ResolvedRef]:
    """
    Deterministically expand context from thread events.
    Strategy: First valid Turn (Intent+Exec) + Last N valid Turns.
    """
    # Group events by turn_id, preserving order relative to first appearance
    turns: dict[str, list[EventRecord]] = {}
    turn_order: list[str] = []
    
    for e in events:
        t_id = e.get("turn_id")
        if not t_id:
            continue
        if t_id not in turns:
            turns[t_id] = []
            turn_order.append(t_id)
        turns[t_id].append(e)
        
    resolved: list[ResolvedRef] = []
    
    # Identify qualifying turns (those with at least INTENT and maybe EXECUTION)
    # Actually we just want everything from the turn if it's relevant
    
    selected_turn_ids: set[str] = set()
    
    if turn_order:
        # First turn
        selected_turn_ids.add(turn_order[0])
        
        # Last N turns
        last_n = turn_order[-n:] if n > 0 else []
        for t in last_n:
            selected_turn_ids.add(t)
            
    # Iterate all events, if they belong to selected turns, include them
    # AND if they are allowed types
    
    for event in events:
        t_id = event.get("turn_id")
        if t_id not in selected_turn_ids:
            continue
            
        kind = event.get("kind")
        if kind == "INTENT":
            admitted_for = "governance"
        elif kind == "EXECUTION":
            # Only include execution if allowed
            if not config.allow_execution_refs_for_prompt:
                continue
            admitted_for = "execution_only"
        else:
            # Skip DECISION/other for prompt context usually
            continue
            
        # Extract content
        content = _extract_event_content_for_auto(event)
        if not content:
            continue
            
        resolved.append({
            "ref_type": "event",
            "ref_id": event.get("correlation_id") or t_id or "unknown",
            "event_index": event.get("index", 0),
            "event_digest": event.get("digest", ""),
            "event_kind": kind,
            "admitted_for": admitted_for,
            "content": content,
            "version": "1"
        })
        
    return resolved


def _extract_event_content_for_auto(event: EventRecord) -> str:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return ""
    kind = event.get("kind", "")
    
    if kind == "INTENT":
        # payload.message or payload.payload.message
        msg = payload.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
        inner = payload.get("payload")
        if isinstance(inner, dict):
            m = inner.get("message")
            if isinstance(m, str):
                return m.strip()
                
    if kind == "EXECUTION":
        # output_text or result
        out = payload.get("output_text")
        if isinstance(out, str):
            return out.strip()
        res = payload.get("result")
        if isinstance(res, str):
            return res.strip()
        if isinstance(res, dict):
             return str(res.get("text") or "").strip()
             
    return ""


def _render_refs_block(resolved_refs: list[ResolvedRef]) -> str:
    """
    Render resolved refs as a deterministic system context block.
    
    Format is fixed and parseable:
    - Clear delimiters (DBL_CONTEXT_REFS_BEGIN/END)
    - Per-ref metadata (ref_id, kind)
    - Content separated by ---
    
    This block is read-only context, never interpreted as assistant history.
    """
    parts: list[str] = []
    parts.append("DBL_CONTEXT_REFS_BEGIN")
    parts.append("The following is referenced context from previous events in this conversation.")
    parts.append("")
    
    has_content = False
    for ref in resolved_refs:
        content = (ref.get("content") or "").strip()
        if not content:
            continue
        has_content = True
        ref_id = ref.get("ref_id", "")
        kind = ref.get("event_kind", "")
        parts.append(f"[ref_id={ref_id} kind={kind}]")
        parts.append(content)
        parts.append("---")
    
    if not has_content:
        return ""
    
    parts.append("DBL_CONTEXT_REFS_END")
    return "\n".join(parts)


def _boundary_transforms(
    raw_messages: Sequence[Mapping[str, Any]],
    admitted_messages: Sequence[Mapping[str, Any]],
    boundary_meta: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    transforms: list[dict[str, Any]] = []
    rejections = []
    if isinstance(boundary_meta, Mapping):
        rejections = boundary_meta.get("rejections") or []
    if isinstance(rejections, list):
        for item in rejections:
            if not isinstance(item, Mapping):
                continue
            idx = item.get("index")
            reason = item.get("reason")
            if not isinstance(idx, int):
                continue
            transform: dict[str, Any] = {
                "op": "DROP_MESSAGE",
                "target": f"model_messages[{idx}]",
            }
            if isinstance(reason, str) and reason.strip():
                transform["params"] = {"reason": reason.strip()}
            transforms.append(transform)

    # If no drops but boundary normalized content, record that normalization occurred.
    if len(raw_messages) == len(admitted_messages):
        for idx, (raw_msg, admitted) in enumerate(zip(raw_messages, admitted_messages)):
            if _normalized_message(raw_msg) != _normalized_message(admitted):
                transforms.append(
                    {
                        "op": "NORMALIZE_MESSAGE",
                        "target": f"model_messages[{idx}]",
                        "params": {"reason": "boundary.normalized"},
                    }
                )
    return transforms


def _normalized_message(value: Mapping[str, Any]) -> Mapping[str, str]:
    role = value.get("role")
    content = value.get("content")
    return {
        "role": role.strip() if isinstance(role, str) else "",
        "content": content.strip() if isinstance(content, str) else "",
    }


def build_context_with_refs(
    payload: Mapping[str, Any] | None,
    *,
    intent_type: str,
    thread_events: Sequence[EventRecord],
    config: ContextConfig | None = None,
) -> ContextArtifacts:
    """
    Build context with declared_refs resolution.
    
    This is the main entry point for context building when refs need to be
    resolved against the event store.
    
    Resolution flow:
    1. Extract declared_refs from payload
    2. Resolve each ref against thread_events
    3. Classify refs (governance vs execution_only)
    4. Build ContextSpec with resolved_refs materialized
    5. Compute context_digest over the full context
    
    Args:
        payload: Intent payload with message, thread_id, turn_id, declared_refs
        intent_type: The intent type (e.g., "chat.message")
        thread_events: Events in the current thread (from store.timeline)
        config: Optional config override for testing
        
    Returns:
        ContextArtifacts with fully resolved refs and digests
        
    Raises:
        RefResolutionError: If ref validation fails (not found, cross-thread, etc.)
        ValueError: If payload is invalid
    """
    if not isinstance(intent_type, str) or not intent_type.strip():
        raise ValueError("intent_type is required to build context")
    
    # Load config (cached)
    cfg = config or get_context_config()
    
    payload_obj: Mapping[str, Any] = payload if isinstance(payload, Mapping) else {}

    user_input = _extract_user_input(payload_obj)
    identity = _extract_identity(payload_obj)
    declared_refs = _extract_declared_refs(payload_obj)
    thread_id = identity["thread_id"]
    
    # Resolve declared_refs OR declarative context logic
    resolution: ResolutionResult | None = None
    resolved_refs: list[ResolvedRef] = []
    normative_input_digests: list[str] = []
    transforms: list[dict[str, Any]] = []
    
    # 1. Automatic Context Expansion (explicit and gated by config)
    auto_refs: list[ResolvedRef] = []

    if not declared_refs:
        ctx_mode = payload_obj.get("context_mode")
        ctx_n = payload_obj.get("context_n")
        allow_auto = cfg.expand_thread_history_enabled

        if allow_auto and ctx_mode == "first_plus_last_n":
            n = ctx_n if isinstance(ctx_n, int) else cfg.expand_last_n
            n = max(1, min(20, n))
            auto_refs = _resolve_auto_context(list(thread_events), n, cfg)
        elif allow_auto and ctx_mode is None and cfg.empty_refs_policy == "EXPAND_LAST_N":
            n = max(1, min(20, cfg.expand_last_n))
            auto_refs = _resolve_auto_context(list(thread_events), n, cfg)

        if auto_refs:
            resolved_refs = auto_refs
            normative_input_digests = [
                r["event_digest"] for r in resolved_refs
                if r.get("admitted_for") == "governance" and r.get("event_digest")
            ]
            transforms.append(
                {
                    "op": "AUTO_DECLARE_REFS",
                    "target": "context.refs",
                    "params": {
                        "mode": ctx_mode or "first_plus_last_n",
                        "n": n,
                        "count": len(resolved_refs),
                        "result": "expanded",
                    },
                }
            )
        elif cfg.empty_refs_policy == "DENY":
            if intent_type == "chat.message":
                _LOGGER.info("declared_refs empty; policy=DENY; chat.message allowed")
            else:
                _LOGGER.info("declared_refs empty; policy=DENY; auto-expand disabled")
                raise RefResolutionError("EMPTY_REFS_DENIED", "declared_refs is empty and policy is DENY")
        elif cfg.empty_refs_policy == "EXPAND_LAST_N" and not allow_auto:
            _LOGGER.info("declared_refs empty; EXPAND_LAST_N configured but auto-expand disabled")
            raise RefResolutionError("EMPTY_REFS_DENIED", "auto expansion disabled by config")

    # 2. Explicit Resolution (if no auto refs)
    if declared_refs and not resolved_refs:
        resolution = resolve_declared_refs(
            declared_refs=declared_refs,
            thread_id=thread_id,
            thread_events=list(thread_events),
            config=cfg,
        )
        resolved_refs = list(resolution.resolved_refs)
        normative_input_digests = list(resolution.normative_input_digests)
    
        # Also, check if we need to expand resolved_refs if some auto-mode was requested on TOP?
        # Non-goal for now. Explicit > Implicit.

    # 3. Create context model messages (system + user) including resolved refs(materializes what boundary did)
    normalization: NormalizationRecord = {
        "applied_rules": list(cfg.normalization_rules),
        "boundary_version": cfg.schema_version,
        "config_digest": cfg.config_digest,
    }

    context_spec: ContextSpec = {
        "identity": identity,
        "intent": {
            "intent_type": intent_type.strip(),
            "user_input": user_input,
        },
        "retrieval": {
            "declared_refs": declared_refs,
            "resolved_refs": resolved_refs,
            "normalization": normalization,
        },
        "assembly_rules": {
            "schema_version": CONTEXT_SPEC_SCHEMA_VERSION,
            "ordering": cfg.canonical_sort,
        },
    }

    raw_model_messages = _build_model_messages(user_input, resolved_refs=resolved_refs or None)
    
    admitted_model_messages, boundary_meta = admit_model_messages(raw_model_messages)
    
    # Calculate boundary transforms and merge with earlier auto-context transforms
    boundary_transforms = _boundary_transforms(raw_model_messages, admitted_model_messages, boundary_meta)
    all_transforms = transforms + boundary_transforms
    
    # Update normalization record (mutable update before digest computation)
    normalization["transformations"] = all_transforms
    
    assembled_context: AssembledContext = {
        "model_messages": admitted_model_messages,
        "assembled_from": resolved_refs,
        "normative_input_digests": normative_input_digests,
    }
    
    context_digest_value = context_digest(context_spec, assembled_context)
    
    return ContextArtifacts(
        context_spec=context_spec,
        assembled_context=assembled_context,
        context_digest=context_digest_value,
        config_digest=cfg.config_digest,
        boundary_meta=boundary_meta,
        transforms=all_transforms,
    )
