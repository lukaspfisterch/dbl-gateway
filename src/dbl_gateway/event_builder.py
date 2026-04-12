from __future__ import annotations

from typing import Any

from .digest import event_digest
from .models import EventRecord


def make_event(
    *,
    kind: str,
    thread_id: str,
    turn_id: str,
    parent_turn_id: str | None,
    lane: str,
    actor: str,
    intent_type: str,
    stream_id: str,
    correlation_id: str,
    payload: dict[str, object],
) -> EventRecord:
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise ValueError("thread_id is required")
    if not isinstance(turn_id, str) or not turn_id.strip():
        raise ValueError("turn_id is required")
    digest_ref, canon_len = event_digest(kind, correlation_id, payload)
    if not digest_ref.startswith("sha256:"):
        digest_ref = f"sha256:{digest_ref}"
    is_authoritative = kind == "DECISION"
    return {
        "index": -1,
        "kind": kind,
        "prev_event_digest": "",
        "thread_id": thread_id,
        "turn_id": turn_id,
        "parent_turn_id": parent_turn_id,
        "lane": lane,
        "actor": actor,
        "intent_type": intent_type,
        "stream_id": stream_id,
        "correlation_id": correlation_id,
        "payload": payload,
        "digest": digest_ref,
        "canon_len": canon_len,
        "is_authoritative": is_authoritative,
    }
