from __future__ import annotations

import os
from pathlib import Path

from .base import TrailStore
from .postgres import TrailStorePostgres
from .sqlite import TrailStoreConfig, TrailStoreSQLite


def create_store(*, db_path: Path | None = None) -> TrailStore:
    backend = os.getenv("DBL_GATEWAY_STORE", "sqlite").strip().lower()
    if backend == "sqlite" or backend == "":
        db_path_value = db_path or Path(os.getenv("DBL_GATEWAY_DB", ".\\data\\trail.sqlite"))
        mode = os.getenv("DBL_GATEWAY_MODE", "leader").strip().lower()
        lock_enabled = os.getenv("DBL_GATEWAY_LEADER_LOCK", "1").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        lock_path = Path(
            os.getenv(
                "DBL_GATEWAY_LEADER_LOCK_PATH",
                str(db_path_value.parent / "trail.leader.lock"),
            )
        )
        return TrailStoreSQLite(
            TrailStoreConfig(
                db_path=db_path_value,
                lock_path=lock_path,
                mode=mode,
                lock_enabled=lock_enabled,
            )
        )
    if backend == "postgres":
        db_url = os.getenv("DBL_GATEWAY_DB_URL", "").strip()
        if not db_url:
            raise ValueError("DBL_GATEWAY_DB_URL required for postgres backend")
        return TrailStorePostgres(db_url=db_url)
    raise ValueError(f"unsupported store backend: {backend}")
