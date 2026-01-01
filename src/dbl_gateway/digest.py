from __future__ import annotations

from typing import Any

from dbl_core import DblEvent, DblEventKind
from dbl_core.events.canonical import canonicalize_value, digest_bytes, json_dumps

__all__ = ["event_digest", "v_digest"]


def event_digest(kind: str, correlation_id: str, payload: dict[str, Any]) -> tuple[str, int]:
    event_kind = DblEventKind(kind)
    event_payload = _strip_obs(payload)
    event = DblEvent(event_kind=event_kind, correlation_id=correlation_id, data=event_payload)
    canonical_json = event.to_json(include_observational=False)
    return event.digest(), len(canonical_json)


def v_digest(indexed: list[tuple[int, str]]) -> str:
    items = [{"index": idx, "digest": digest} for idx, digest in indexed]
    canonical = canonicalize_value(items)
    canonical_json = json_dumps(canonical)
    return digest_bytes(canonical_json)


def _strip_obs(payload: dict[str, Any]) -> dict[str, Any]:
    if "_obs" not in payload:
        return payload
    sanitized = dict(payload)
    sanitized.pop("_obs", None)
    return sanitized
