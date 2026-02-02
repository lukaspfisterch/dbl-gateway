"""
Context reference resolver for DBL Gateway.

Resolves declared_refs against the event store, validates scope, 
and classifies refs for governance vs execution-only use.

This module is a pure function layer - no side effects.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .config import ContextConfig
from .contracts import DeclaredRef, ResolvedRef
from .models import EventRecord


__all__ = [
    "RefResolutionError",
    "RefNotFoundError", 
    "CrossThreadRefError",
    "MaxRefsExceededError",
    "resolve_declared_refs",
    "ResolutionResult",
]


class RefResolutionError(ValueError):
    """Base error for ref resolution failures."""
    
    def __init__(self, code: str, message: str, ref_id: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.ref_id = ref_id


class RefNotFoundError(RefResolutionError):
    """Referenced event does not exist."""
    
    def __init__(self, ref_id: str) -> None:
        super().__init__("REF_NOT_FOUND", f"Referenced event not found: {ref_id}", ref_id)


class CrossThreadRefError(RefResolutionError):
    """Referenced event belongs to a different thread."""
    
    def __init__(self, ref_id: str, expected_thread: str, actual_thread: str) -> None:
        super().__init__(
            "CROSS_THREAD_REF",
            f"Reference {ref_id} belongs to thread {actual_thread}, expected {expected_thread}",
            ref_id,
        )
        self.expected_thread = expected_thread
        self.actual_thread = actual_thread


class MaxRefsExceededError(RefResolutionError):
    """Too many refs in request."""
    
    def __init__(self, count: int, max_refs: int) -> None:
        super().__init__(
            "MAX_REFS_EXCEEDED",
            f"declared_refs count {count} exceeds maximum {max_refs}",
        )
        self.count = count
        self.max_refs = max_refs


@dataclass(frozen=True)
class ResolutionResult:
    """Result of resolving declared_refs."""
    
    # All resolved refs (both governance and execution_only)
    resolved_refs: tuple[ResolvedRef, ...]
    
    # Only refs admitted for governance (INTENT only)
    normative_refs: tuple[ResolvedRef, ...]
    
    # Digests of normative input payloads (for assembled_context)
    normative_input_digests: tuple[str, ...]


def _extract_event_content(event: EventRecord) -> str:
    """
    Extract text content from an event for context building.
    
    - INTENT: payload.message or payload.payload.message
    - EXECUTION: payload.output_text or payload.result
    - Other: empty string
    """
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return ""
    
    kind = event.get("kind", "")
    
    if kind == "INTENT":
        # Try payload.message first, then nested payload.payload.message
        message = payload.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()
        inner_payload = payload.get("payload")
        if isinstance(inner_payload, dict):
            inner_message = inner_payload.get("message")
            if isinstance(inner_message, str) and inner_message.strip():
                return inner_message.strip()
        return ""
    
    if kind == "EXECUTION":
        # Try output_text first, then result
        output_text = payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()
        result = payload.get("result")
        if isinstance(result, str) and result.strip():
            return result.strip()
        if isinstance(result, dict):
            text = result.get("text")
            if isinstance(text, str) and text.strip():
                return text.strip()
        return ""
    
    return ""


def resolve_declared_refs(
    declared_refs: Sequence[DeclaredRef],
    thread_id: str,
    thread_events: Sequence[EventRecord],
    config: ContextConfig,
) -> ResolutionResult:
    """
    Resolve declared_refs against thread events.
    
    Resolution rules (in order):
    1. Validate count <= config.max_refs
    2. Build event lookup by correlation_id and turn_id
    3. For each declared_ref:
       - Validate existence (REF_NOT_FOUND if missing)
       - Validate scope (CROSS_THREAD_REF if wrong thread)
       - Classify: INTENT -> governance, EXECUTION -> execution_only
       - Extract event_index, event_digest
    4. Sort by event_index (canonical ordering)
    
    Args:
        declared_refs: Refs from client request
        thread_id: Current thread_id (for scope validation)
        thread_events: Events in the thread (from store.timeline)
        config: Context configuration
        
    Returns:
        ResolutionResult with resolved_refs, normative_refs, normative_input_digests
        
    Raises:
        RefNotFoundError: If a ref doesn't exist
        CrossThreadRefError: If ref belongs to different thread
        MaxRefsExceededError: If too many refs
    """
    # 1. Validate count
    if len(declared_refs) > config.max_refs:
        raise MaxRefsExceededError(len(declared_refs), config.max_refs)
    
    # 2. Build lookup indexes
    # Map: correlation_id -> event, turn_id -> event
    by_correlation: dict[str, EventRecord] = {}
    by_turn: dict[str, EventRecord] = {}
    
    for event in thread_events:
        if event.get("correlation_id"):
            by_correlation[event["correlation_id"]] = event
        if event.get("turn_id"):
            by_turn[event["turn_id"]] = event
    
    # 3. Resolve each ref
    resolved: list[ResolvedRef] = []
    normative: list[ResolvedRef] = []
    normative_digests: list[str] = []
    
    for ref in declared_refs:
        ref_id = ref.get("ref_id", "")
        ref_type = ref.get("ref_type", "event")
        
        # Lookup by ref_id (try correlation_id first, then turn_id)
        event = by_correlation.get(ref_id) or by_turn.get(ref_id)
        
        if event is None:
            raise RefNotFoundError(ref_id)
        
        # Scope validation
        event_thread = event.get("thread_id", "")
        if config.enforce_scope_bound and event_thread != thread_id:
            raise CrossThreadRefError(ref_id, thread_id, event_thread)
        
        # Classify based on event kind
        event_kind = event.get("kind", "")
        if event_kind == "INTENT":
            admitted_for = "governance"
        elif event_kind == "EXECUTION":
            if config.allow_execution_refs_for_prompt:
                admitted_for = "execution_only"
            else:
                # Skip EXECUTION refs entirely if not allowed
                continue
        else:
            # Other kinds (DECISION, PROOF) - execution_only for audit
            admitted_for = "execution_only"
        
        resolved_ref: ResolvedRef = {
            "ref_type": ref_type,
            "ref_id": ref_id,
            "event_index": event.get("index", 0),
            "event_digest": event.get("digest", ""),
            "event_kind": event_kind,
            "admitted_for": admitted_for,
            "content": _extract_event_content(event),
        }
        
        if ref.get("version"):
            resolved_ref["version"] = str(ref["version"])
        
        resolved.append(resolved_ref)
        
        if admitted_for == "governance":
            normative.append(resolved_ref)
            # Add the event digest for normative inputs
            if event.get("digest"):
                normative_digests.append(event["digest"])
    
    # 4. Sort by event_index (canonical)
    if config.canonical_sort == "event_index_asc":
        resolved.sort(key=lambda r: r.get("event_index", 0))
        normative.sort(key=lambda r: r.get("event_index", 0))
    elif config.canonical_sort == "event_index_desc":
        resolved.sort(key=lambda r: r.get("event_index", 0), reverse=True)
        normative.sort(key=lambda r: r.get("event_index", 0), reverse=True)
    # else: "none" - preserve client order (not recommended)
    
    # Sort digests for determinism
    normative_digests.sort()
    
    return ResolutionResult(
        resolved_refs=tuple(resolved),
        normative_refs=tuple(normative),
        normative_input_digests=tuple(normative_digests),
    )
