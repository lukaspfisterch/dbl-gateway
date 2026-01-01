from __future__ import annotations

from typing import Protocol

from ..models import EventRecord, Snapshot


class StorePort(Protocol):
    def append(
        self,
        *,
        kind: str,
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

    def close(self) -> None:
        ...
