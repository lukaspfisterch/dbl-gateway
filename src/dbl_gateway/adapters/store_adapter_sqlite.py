from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..ports.store_port import StorePort
from ..store.sqlite import SQLiteStore


@dataclass
class SQLiteStoreAdapter(StorePort):
    _store: SQLiteStore

    @classmethod
    def from_path(cls, db_path: Path) -> "SQLiteStoreAdapter":
        return cls(SQLiteStore(db_path))

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
    ):
        return self._store.append(
            kind=kind,
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
            lane=lane,
            actor=actor,
            intent_type=intent_type,
            stream_id=stream_id,
            correlation_id=correlation_id,
            payload=payload,
        )

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stream_id: str | None = None,
        lane: str | None = None,
    ):
        return self._store.snapshot(
            limit=limit,
            offset=offset,
            stream_id=stream_id,
            lane=lane,
        )

    def timeline(
        self,
        *,
        thread_id: str,
        include_payload: bool = False,
    ):
        return self._store.timeline(thread_id=thread_id, include_payload=include_payload)

    def recompute_v_digest(self) -> str:
        return self._store.recompute_v_digest()

    def verify_event_chain(self) -> list[dict[str, object]]:
        return self._store.verify_event_chain()

    def close(self) -> None:
        self._store.close()
