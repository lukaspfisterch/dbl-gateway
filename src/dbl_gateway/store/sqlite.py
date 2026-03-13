from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..digest import v_digest, v_digest_step


class ParentValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class OrderViolationError(RuntimeError):
    """I-ORDER-1: EXECUTION appended without a preceding DECISION."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
from ..event_builder import make_event

from ..models import EventRecord, Snapshot


class PayloadDecodeError(RuntimeError):
    def __init__(self, *, idx: int, kind: str, correlation_id: str, payload_prefix: str, error: Exception) -> None:
        message = (
            f"failed to decode payload_json for idx={idx}, kind={kind}, correlation_id={correlation_id}: "
            f"{error}; payload_json_prefix={payload_prefix!r}"
        )
        super().__init__(message)
        self.idx = idx
        self.kind = kind
        self.correlation_id = correlation_id
        self.payload_prefix = payload_prefix
        self.__cause__ = error


class SQLiteStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    idx INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    thread_id TEXT NOT NULL DEFAULT '',
                    turn_id TEXT NOT NULL DEFAULT '',
                    parent_turn_id TEXT,
                    actor TEXT NOT NULL,
                    intent_type TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    canon_len INTEGER NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            self._ensure_column("events", "lane", "TEXT NOT NULL DEFAULT 'unknown'")
            self._ensure_column("events", "thread_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "turn_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "parent_turn_id", "TEXT")
            self._ensure_column("events", "actor", "TEXT NOT NULL DEFAULT 'unknown'")
            self._ensure_column("events", "intent_type", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "stream_id", "TEXT NOT NULL DEFAULT 'default'")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_stream_id ON events(stream_id)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_lane ON events(lane)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_kind ON events(kind)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS events_correlation_id ON events(correlation_id)"
            )
            # I-STREAM-1: Append-only event stream (A1).
            # Events are immutable once appended. UPDATE and DELETE are forbidden.
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'I-STREAM-1: events are immutable once appended');
                END
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'I-STREAM-1: events are immutable once appended');
                END
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS v_state (
                    id TEXT PRIMARY KEY,
                    v_digest TEXT NOT NULL,
                    last_index INTEGER NOT NULL
                )
                """
            )
            self._ensure_v_state()
    
    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        cols = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {row[1] for row in cols}
        if column in existing:
            return
        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

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
        if not isinstance(payload, (dict, Mapping)):
            raise TypeError(f"payload must be a dict; got {type(payload).__name__}")
        payload_obj: dict[str, object] = dict(payload)
        self._validate_parent(thread_id, turn_id, parent_turn_id)
        # I-ORDER-1: EXECUTION requires a preceding DECISION in the same turn.
        if kind == "EXECUTION":
            self._require_preceding_decision(thread_id, turn_id, correlation_id)
        event = make_event(
            kind=kind,
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
            lane=lane,
            actor=actor,
            intent_type=intent_type,
            stream_id=stream_id,
            correlation_id=correlation_id,
            payload=payload_obj,
        )
        payload_json = json.dumps(
            payload_obj,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        created_at = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO events (
                    kind,
                    lane,
                    thread_id,
                    turn_id,
                    parent_turn_id,
                    actor,
                    intent_type,
                    stream_id,
                    correlation_id,
                    payload_json,
                    digest,
                    canon_len,
                    created_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kind,
                    lane,
                    thread_id,
                    turn_id,
                    parent_turn_id,
                    actor,
                    intent_type,
                    stream_id,
                    correlation_id,
                    payload_json,
                    event["digest"],
                    event["canon_len"],
                    created_at,
                ),
            )
            cur = self._conn.execute("SELECT idx FROM events WHERE rowid = last_insert_rowid()")
            row = cur.fetchone()
            idx = int(row[0]) if row else 0
            index = max(0, idx - 1)
            prev_digest, _prev_index = self._get_v_state()
            next_digest = v_digest_step(prev_digest, index, event["digest"])
            self._conn.execute(
                "UPDATE v_state SET v_digest = ?, last_index = ? WHERE id = ?",
                (next_digest, index, "current"),
            )
        event["index"] = index
        return event

    def timeline(self, *, thread_id: str, include_payload: bool = False) -> list[EventRecord]:
        columns = [
            "idx",
            "kind",
            "lane",
            "thread_id",
            "turn_id",
            "parent_turn_id",
            "actor",
            "intent_type",
            "stream_id",
            "correlation_id",
            "payload_json",
            "digest",
            "canon_len",
        ]
        rows = self._conn.execute(
            f"SELECT {', '.join(columns)} FROM events WHERE thread_id = ? ORDER BY idx ASC",
            (thread_id,),
        ).fetchall()
        events: list[EventRecord] = []
        for row in rows:
            payload_json = row["payload_json"]
            payload: dict[str, Any] | None = None
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError as exc:
                prefix = str(payload_json)[:200]
                raise PayloadDecodeError(
                    idx=int(row["idx"]),
                    kind=str(row["kind"]),
                    correlation_id=str(row["correlation_id"]),
                    payload_prefix=prefix,
                    error=exc,
                ) from exc
            event: EventRecord = {
                "index": max(0, int(row["idx"]) - 1),
                "kind": str(row["kind"]),
                "lane": str(row["lane"]),
                "thread_id": str(row["thread_id"]),
                "turn_id": str(row["turn_id"]),
                "parent_turn_id": row["parent_turn_id"] if row["parent_turn_id"] is None else str(row["parent_turn_id"]),
                "actor": str(row["actor"]),
                "intent_type": str(row["intent_type"]),
                "stream_id": str(row["stream_id"]),
                "correlation_id": str(row["correlation_id"]),
                "digest": str(row["digest"]),
                "canon_len": int(row["canon_len"]),
                "is_authoritative": str(row["kind"]) == "DECISION",
            }
            event["payload"] = payload
            events.append(event)
        return events

    def _validate_parent(self, thread_id: str, turn_id: str, parent_turn_id: str | None) -> None:
        if parent_turn_id is None:
            return
        if parent_turn_id == "":
            return
        if parent_turn_id == turn_id:
            raise ParentValidationError("parent_turn_id cannot equal turn_id")
        rows = self._conn.execute(
            "SELECT turn_id, parent_turn_id FROM events WHERE thread_id = ? ORDER BY idx ASC",
            (thread_id,),
        ).fetchall()
        parent_map: dict[str, str | None] = {}
        for row in rows:
            parent_map[str(row["turn_id"])] = (
                None if row["parent_turn_id"] is None else str(row["parent_turn_id"])
            )
        if parent_turn_id not in parent_map:
            raise ParentValidationError("parent_turn_id missing")
        visited = {turn_id}
        current = parent_turn_id
        while current is not None:
            if current in visited:
                raise ParentValidationError("parent_turn_id introduces cycle")
            visited.add(current)
            current = parent_map.get(current)

    def _require_preceding_decision(
        self, thread_id: str, turn_id: str, correlation_id: str
    ) -> None:
        """I-ORDER-1: For each turn, t(DECISION) < t(EXECUTION)."""
        row = self._conn.execute(
            "SELECT 1 FROM events WHERE kind = 'DECISION' AND thread_id = ? AND turn_id = ? LIMIT 1",
            (thread_id, turn_id),
        ).fetchone()
        if row is None:
            raise OrderViolationError(
                f"I-ORDER-1: no DECISION precedes EXECUTION for turn_id={turn_id!r}, "
                f"correlation_id={correlation_id!r}"
            )

    def snapshot(
        self,
        *,
        limit: int,
        offset: int,
        stream_id: str | None = None,
        lane: str | None = None,
    ) -> Snapshot:
        self._conn.execute("BEGIN")
        try:
            events = self._fetch_events(limit=limit, offset=offset, stream_id=stream_id, lane=lane)
            length = self._count_events()
            v_digest_value, _ = self._get_v_state()
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return {
            "length": length,
            "offset": offset,
            "limit": limit,
            "v_digest": v_digest_value,
            "events": events,
        }

    def _fetch_events(
        self,
        *,
        limit: int,
        offset: int,
        stream_id: str | None,
        lane: str | None,
    ) -> list[EventRecord]:
        columns = [
            "idx",
            "kind",
            "lane",
            "thread_id",
            "turn_id",
            "parent_turn_id",
            "actor",
            "intent_type",
            "stream_id",
            "correlation_id",
            "payload_json",
            "digest",
            "canon_len",
        ]
        query = f"SELECT {', '.join(columns)} FROM events"
        params: list[Any] = []
        filters: list[str] = []
        if stream_id:
            filters.append("stream_id = ?")
            params.append(stream_id)
        if lane:
            filters.append("lane = ?")
            params.append(lane)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY idx ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(query, params).fetchall()
        events: list[EventRecord] = []
        for row in rows:
            payload_json = row["payload_json"]
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError as exc:
                prefix = str(payload_json)[:200]
                raise PayloadDecodeError(
                    idx=int(row["idx"]),
                    kind=str(row["kind"]),
                    correlation_id=str(row["correlation_id"]),
                    payload_prefix=prefix,
                    error=exc,
                ) from exc
            events.append(
                {
                    "index": max(0, int(row["idx"]) - 1),
                    "kind": str(row["kind"]),
                    "lane": str(row["lane"]),
                    "thread_id": str(row["thread_id"]),
                    "turn_id": str(row["turn_id"]),
                    "parent_turn_id": row["parent_turn_id"] if row["parent_turn_id"] is None else str(row["parent_turn_id"]),
                    "actor": str(row["actor"]),
                    "intent_type": str(row["intent_type"]),
                    "stream_id": str(row["stream_id"]),
                    "correlation_id": str(row["correlation_id"]),
                    "payload": payload,
                    "digest": str(row["digest"]),
                    "canon_len": int(row["canon_len"]),
                    "is_authoritative": str(row["kind"]) == "DECISION",
                }
            )
        return events

    def _count_events(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0]) if row else 0

    def _ensure_v_state(self) -> None:
        row = self._conn.execute("SELECT v_digest, last_index FROM v_state WHERE id = ?", ("current",)).fetchone()
        if row:
            return
        rows = self._conn.execute("SELECT idx, digest FROM events ORDER BY idx ASC").fetchall()
        indexed = [(max(0, int(idx) - 1), str(digest)) for idx, digest in rows]
        digest = v_digest(indexed)
        last_index = indexed[-1][0] if indexed else -1
        self._conn.execute(
            "INSERT INTO v_state (id, v_digest, last_index) VALUES (?, ?, ?)",
            ("current", digest, last_index),
        )

    def _get_v_state(self) -> tuple[str, int]:
        row = self._conn.execute(
            "SELECT v_digest, last_index FROM v_state WHERE id = ?", ("current",)
        ).fetchone()
        if not row:
            return v_digest([]), -1
        return str(row[0]), int(row[1])

    def recompute_v_digest(self) -> str:
        rows = self._conn.execute("SELECT idx, digest FROM events ORDER BY idx ASC").fetchall()
        indexed = [(max(0, int(idx) - 1), str(digest)) for idx, digest in rows]
        return v_digest(indexed)
