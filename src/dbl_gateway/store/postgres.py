from __future__ import annotations

from typing import Any

from ..models import EventSummary, StreamSnapshot
from ..wire_contract import StackFingerprint


class TrailStorePostgres:
    def __init__(self, *, db_url: str) -> None:
        self._db_url = db_url

    def append(
        self,
        *,
        kind: str,
        correlation_id: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> EventSummary:
        raise NotImplementedError("postgres backend not implemented")

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        raise NotImplementedError("postgres backend not implemented")

    def snapshot_norm(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        raise NotImplementedError("postgres backend not implemented")

    def get_event(self, *, index: int) -> EventSummary | None:
        raise NotImplementedError("postgres backend not implemented")

    def stream_status(self) -> tuple[int, str]:
        raise NotImplementedError("postgres backend not implemented")

    def close(self) -> None:
        raise NotImplementedError("postgres backend not implemented")
