from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..digest import v_digest, v_digest_step
from ..event_builder import make_event

from ..models import EventRecord, Snapshot


class SQLiteStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
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
            self._ensure_column("events", "actor", "TEXT NOT NULL DEFAULT 'unknown'")
            self._ensure_column("events", "intent_type", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "stream_id", "TEXT NOT NULL DEFAULT 'default'")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_stream_id ON events(stream_id)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_lane ON events(lane)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS events_kind ON events(kind)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS events_correlation_id ON events(correlation_id)"
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
        lane: str,
        actor: str,
        intent_type: str,
        stream_id: str,
        correlation_id: str,
        payload: dict[str, object],
    ) -> EventRecord:
        event = make_event(
            kind=kind,
            lane=lane,
            actor=actor,
            intent_type=intent_type,
            stream_id=stream_id,
            correlation_id=correlation_id,
            payload=payload,
        )
        payload_json = json.dumps(
            payload,
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
                    actor,
                    intent_type,
                    stream_id,
                    correlation_id,
                    payload_json,
                    digest,
                    canon_len,
                    created_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kind,
                    lane,
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
        query = (
            "SELECT idx, kind, lane, actor, intent_type, stream_id, correlation_id, "
            "payload_json, digest, canon_len FROM events"
        )
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
            payload = json.loads(row[7])
            events.append(
                {
                    "index": max(0, int(row[0]) - 1),
                    "kind": str(row[1]),
                    "lane": str(row[2]),
                    "actor": str(row[3]),
                    "intent_type": str(row[4]),
                    "stream_id": str(row[5]),
                    "correlation_id": str(row[6]),
                    "payload": payload,
                    "digest": str(row[8]),
                    "canon_len": int(row[9]),
                    "is_authoritative": str(row[1]) == "DECISION",
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
