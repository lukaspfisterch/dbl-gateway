from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from ..digest import event_digest, v_digest
from ..models import EventSummary, StreamSnapshot
from ..wire_contract import INTERFACE_VERSION, StackFingerprint
from .base import IdempotencyConflictError


@dataclass(frozen=True)
class TrailStoreConfig:
    db_path: Path
    lock_path: Path
    mode: str
    lock_enabled: bool


class TrailStoreSQLite:
    def __init__(self, config: TrailStoreConfig) -> None:
        self._db_path = config.db_path
        self._lock_path = config.lock_path
        self._mode = config.mode
        self._lock_enabled = config.lock_enabled
        self._lock = Lock()
        self._lock_file = None
        self._conn = self._connect()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        self._acquire_leader_lock()
        if self._mode == "follower" and not self._db_path.exists():
            raise RuntimeError("sqlite db not found for follower mode")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        if self._mode == "follower":
            conn.execute("PRAGMA query_only=ON;")
        return conn

    def close(self) -> None:
        self._conn.close()
        self._release_leader_lock()

    def _init_schema(self) -> None:
        if self._mode == "follower":
            return
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    idx INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    canon_len INTEGER NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    idempotency_key TEXT PRIMARY KEY,
                    event_idx INTEGER NOT NULL,
                    digest TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS events_correlation_id ON events(correlation_id)"
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_kind ON events(kind)")

    def _acquire_leader_lock(self) -> None:
        if self._mode != "leader":
            return
        if not self._lock_enabled:
            return
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._lock_file = open(self._lock_path, "x", encoding="utf-8")
            self._lock_file.write(f"pid={os.getpid()}\n")
            self._lock_file.flush()
        except FileExistsError as exc:
            raise RuntimeError("leader lock already held") from exc

    def _release_leader_lock(self) -> None:
        if self._lock_file is None:
            return
        try:
            self._lock_file.close()
        finally:
            try:
                self._lock_path.unlink(missing_ok=True)
            except OSError:
                pass

    def append(
        self,
        *,
        kind: str,
        correlation_id: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> EventSummary:
        if self._mode == "follower":
            raise RuntimeError("writes disabled in follower mode")
        digest_ref, canon_len = event_digest(kind, correlation_id, payload)
        payload_json = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn:
                if idempotency_key:
                    existing = self._conn.execute(
                        """
                        SELECT event_idx, digest
                        FROM idempotency_keys
                        WHERE idempotency_key = ?
                        """,
                        (idempotency_key,),
                    ).fetchone()
                    if existing:
                        existing_idx = int(existing[0])
                        existing_digest = str(existing[1])
                        if existing_digest != digest_ref:
                            raise IdempotencyConflictError(
                                "idempotency key reused with different payload"
                            )
                        event = self._fetch_event_by_idx(existing_idx)
                        if event is None:
                            raise RuntimeError("idempotency record missing event")
                        return event
                self._conn.execute(
                    """
                    INSERT INTO events (idx, kind, correlation_id, payload_json, digest, canon_len, created_at_utc)
                    VALUES ((SELECT COALESCE(MAX(idx), -1) + 1 FROM events), ?, ?, ?, ?, ?, ?)
                    """,
                    (kind, correlation_id, payload_json, digest_ref, canon_len, created_at),
                )
                cur = self._conn.execute("SELECT idx FROM events WHERE rowid = last_insert_rowid()")
                row = cur.fetchone()
                idx = int(row[0]) if row else 0
                if idempotency_key:
                    self._conn.execute(
                        """
                        INSERT INTO idempotency_keys (
                            idempotency_key,
                            event_idx,
                            digest,
                            kind,
                            correlation_id,
                            created_at_utc
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (idempotency_key, idx, digest_ref, kind, correlation_id, created_at),
                    )
        return {
            "index": idx,
            "kind": kind,
            "correlation_id": correlation_id,
            "payload": payload,
            "canon_len": canon_len,
            "digest": digest_ref,
        }

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        events = self._fetch_events(
            limit=limit, offset=offset, kinds=None, correlation_id=correlation_id
        )
        length = self._count_events()
        v_digest_value = self._v_digest_all()
        return {
            "interface_version": INTERFACE_VERSION,
            "v_digest": v_digest_value,
            "length": length,
            "stack_fingerprint": stack_fingerprint,
            "events": events,
        }

    def stream_status(self) -> tuple[int, str]:
        length = self._count_events()
        v_digest_value = self._v_digest_all()
        return length, v_digest_value

    def snapshot_norm(
        self,
        *,
        limit: int,
        offset: int,
        stack_fingerprint: StackFingerprint,
        correlation_id: str | None = None,
    ) -> StreamSnapshot:
        events = self._fetch_events(
            limit=limit,
            offset=offset,
            kinds=["DECISION", "POLICY_UPDATE_DECISION", "BOUNDARY_UPDATE_DECISION"],
            correlation_id=correlation_id,
        )
        length = self._count_events()
        v_digest_value = self._v_digest_all()
        # Norm snapshots preserve original indices and report total V length.
        return {
            "interface_version": INTERFACE_VERSION,
            "v_digest": v_digest_value,
            "length": length,
            "stack_fingerprint": stack_fingerprint,
            "events": events,
        }

    def get_event(self, *, index: int) -> EventSummary | None:
        return self._fetch_event_by_idx(index)

    def _fetch_events(
        self,
        *,
        limit: int,
        offset: int,
        kinds: list[str] | None,
        correlation_id: str | None,
    ) -> list[EventSummary]:
        query = "SELECT idx, kind, correlation_id, payload_json, digest, canon_len FROM events"
        params: list[Any] = []
        filters: list[str] = []
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            filters.append(f"kind IN ({placeholders})")
            params.extend(kinds)
        if correlation_id:
            filters.append("correlation_id = ?")
            params.append(correlation_id)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY idx ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur = self._conn.execute(query, params)
        rows = cur.fetchall()
        events: list[EventSummary] = []
        for row in rows:
            payload = json.loads(row[3])
            events.append(
                {
                    "index": int(row[0]),
                    "kind": str(row[1]),
                    "correlation_id": str(row[2]),
                    "payload": payload,
                    "digest": str(row[4]),
                    "canon_len": int(row[5]),
                }
            )
        return events

    def _fetch_event_by_idx(self, index: int) -> EventSummary | None:
        cur = self._conn.execute(
            """
            SELECT idx, kind, correlation_id, payload_json, digest, canon_len
            FROM events
            WHERE idx = ?
            """,
            (index,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        payload = json.loads(row[3])
        return {
            "index": int(row[0]),
            "kind": str(row[1]),
            "correlation_id": str(row[2]),
            "payload": payload,
            "digest": str(row[4]),
            "canon_len": int(row[5]),
        }

    def _count_events(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM events")
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def _v_digest_all(self) -> str:
        cur = self._conn.execute("SELECT idx, digest FROM events ORDER BY idx ASC")
        rows = cur.fetchall()
        indexed = [(int(idx), str(digest)) for idx, digest in rows]
        return v_digest(indexed)

    def _v_digest_kind(self, kinds: list[str]) -> str:
        placeholders = ",".join("?" for _ in kinds)
        cur = self._conn.execute(
            f"SELECT idx, digest FROM events WHERE kind IN ({placeholders}) ORDER BY idx ASC",
            kinds,
        )
        rows = cur.fetchall()
        indexed = [(int(idx), str(digest)) for idx, digest in rows]
        return v_digest(indexed)
