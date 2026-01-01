from __future__ import annotations

import os
from pathlib import Path

from ..adapters.store_adapter_sqlite import SQLiteStoreAdapter
from ..ports.store_port import StorePort


def create_store(db_path: Path | None = None) -> StorePort:
    path = db_path or Path(os.getenv("DBL_GATEWAY_DB", ".\\data\\trail.sqlite"))
    return SQLiteStoreAdapter.from_path(path)
