from __future__ import annotations

from dataclasses import dataclass, field
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
    
    # Resolve declared_refs against thread events
    resolution: ResolutionResult | None = None
    resolved_refs: list[ResolvedRef] = []
    normative_input_digests: list[str] = []
    
    if declared_refs:
        resolution = resolve_declared_refs(
            declared_refs=declared_refs,
            thread_id=thread_id,
            thread_events=list(thread_events),
            config=cfg,
        )
        resolved_refs = list(resolution.resolved_refs)
        normative_input_digests = list(resolution.normative_input_digests)
    
    # Build normalization record (materializes what boundary did)
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

    # DEBUG: Log what we're working with
    import logging
    _log = logging.getLogger("dbl_gateway.context")
    _log.info(f"[CONTEXT DEBUG] declared_refs: {declared_refs}")
    _log.info(f"[CONTEXT DEBUG] resolved_refs count: {len(resolved_refs)}")
    for r in resolved_refs:
        _log.info(f"[CONTEXT DEBUG] resolved ref: kind={r.get('event_kind')}, content_len={len(r.get('content', ''))}")

    raw_model_messages = _build_model_messages(user_input, resolved_refs=resolved_refs or None)
    _log.info(f"[CONTEXT DEBUG] model_messages count: {len(raw_model_messages)}")
    for m in raw_model_messages:
        _log.info(f"[CONTEXT DEBUG] message role={m.get('role')}, content_len={len(m.get('content', ''))}")
    
    admitted_model_messages, boundary_meta = admit_model_messages(raw_model_messages)
    transforms = _boundary_transforms(raw_model_messages, admitted_model_messages, boundary_meta)
    
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
        transforms=transforms,
    )
