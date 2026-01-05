from __future__ import annotations

from typing import Any

from dbl_core import DblEvent, DblEventKind
from dbl_core.events.canonical import canonicalize_value, digest_bytes, json_dumps

__all__ = ["event_digest", "v_digest", "v_digest_step"]


def event_digest(kind: str, correlation_id: str, payload: dict[str, Any]) -> tuple[str, int]:
    event_kind = DblEventKind(kind)
    event_payload = _strip_obs(payload)
    event = DblEvent(event_kind=event_kind, correlation_id=correlation_id, data=event_payload)
    canonical_json = event.to_json(include_observational=False)
    digest = event.digest()
    if not digest.startswith("sha256:"):
        digest = f"sha256:{digest}"
    return digest, len(canonical_json)


def v_digest(indexed: list[tuple[int, str]]) -> str:
    current = _v_seed()
    for idx, digest in indexed:
        current = v_digest_step(current, idx, digest)
    return current


def v_digest_step(prev: str, idx: int, digest: str) -> str:
    item = {"prev": prev, "index": idx, "digest": digest}
    canonical = canonicalize_value(item)
    canonical_json = json_dumps(canonical)
    return digest_bytes(canonical_json)


def _v_seed() -> str:
    return "sha256:" + ("0" * 64)


def _strip_obs(payload: dict[str, Any]) -> dict[str, Any]:
    if "_obs" not in payload:
        return payload
    sanitized = dict(payload)
    sanitized.pop("_obs", None)
    return sanitized
