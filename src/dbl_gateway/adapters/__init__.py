from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .execution_adapter_kl import KlExecutionAdapter
    from .policy_adapter_dbl_policy import DblPolicyAdapter
    from .store_adapter_sqlite import SQLiteStoreAdapter

__all__ = [
    "DblPolicyAdapter",
    "KlExecutionAdapter",
    "SQLiteStoreAdapter",
]


def __getattr__(name: str) -> Any:
    if name == "DblPolicyAdapter":
        return import_module(".policy_adapter_dbl_policy", __name__).DblPolicyAdapter
    if name == "KlExecutionAdapter":
        return import_module(".execution_adapter_kl", __name__).KlExecutionAdapter
    if name == "SQLiteStoreAdapter":
        return import_module(".store_adapter_sqlite", __name__).SQLiteStoreAdapter
    raise AttributeError(name)
