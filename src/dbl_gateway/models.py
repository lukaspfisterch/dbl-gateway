from __future__ import annotations

from typing import Any, TypedDict

from .wire_contract import StackFingerprint


class EventSummary(TypedDict):
    index: int
    kind: str
    correlation_id: str
    payload: dict[str, Any]
    canon_len: int
    digest: str


class StreamSnapshot(TypedDict):
    interface_version: int
    v_digest: str
    length: int
    stack_fingerprint: StackFingerprint
    events: list[EventSummary]
