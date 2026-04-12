from __future__ import annotations

from typing import Protocol

from ..models import EventRecord, Snapshot


class StorePort(Protocol):
    def append(
        self,
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
        ...

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stream_id: str | None = None,
        lane: str | None = None,
    ) -> Snapshot:
        ...

    def timeline(
        self,
        *,
        thread_id: str,
        include_payload: bool = False,
    ) -> list[EventRecord]:
        ...

    def recompute_v_digest(self) -> str:
        ...

    def verify_event_chain(self) -> list[dict[str, object]]:
        ...

    def close(self) -> None:
        ...
