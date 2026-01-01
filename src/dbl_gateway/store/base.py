from __future__ import annotations

from typing import Any, Protocol

from ..models import EventSummary, StreamSnapshot
from ..wire_contract import StackFingerprint


class IdempotencyConflictError(Exception):
    pass


class TrailStore(Protocol):
    def append(
        self,
        *,
        kind: str,
        correlation_id: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> EventSummary:
        ...

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        ...

    def snapshot_norm(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        ...

    def get_event(self, *, index: int) -> EventSummary | None:
        ...

    def stream_status(self) -> tuple[int, str]:
        ...

    def close(self) -> None:
        ...
