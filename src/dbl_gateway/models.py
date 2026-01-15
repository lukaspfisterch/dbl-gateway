from __future__ import annotations

from typing import Any, TypedDict


class EventRecord(TypedDict):
    index: int
    kind: str
    thread_id: str
    turn_id: str
    parent_turn_id: str | None
    lane: str
    actor: str
    intent_type: str
    stream_id: str
    correlation_id: str
    payload: dict[str, Any]
    digest: str
    canon_len: int
    is_authoritative: bool


class Snapshot(TypedDict):
    length: int
    offset: int
    limit: int
    v_digest: str
    events: list[EventRecord]
