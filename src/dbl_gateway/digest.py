from __future__ import annotations

from typing import Any, Mapping
from hashlib import sha256

from dbl_core import DblEvent, DblEventKind
from dbl_core.events.canonical import canonicalize_value
from .contracts import (
    DecisionNormative,
    _normalize_decision,
    _strip_obs,
    canonical_json_bytes,
    decision_digest as _decision_digest,
    normalize_sha256_hex,
)

__all__ = ["event_digest", "v_digest", "v_digest_step", "compute_release_digest"]


def event_digest(kind: str, correlation_id: str, payload: dict[str, Any]) -> tuple[str, int]:
    if kind == "DECISION":
        normative = _normalize_decision(_strip_obs(payload))
        canonical_json = canonical_json_bytes(normative)
        digest = _decision_digest(normative)
        return digest, len(canonical_json)
    event_kind = DblEventKind(kind)
    event_payload = _strip_obs(payload)
    event = DblEvent(event_kind=event_kind, correlation_id=correlation_id, data=event_payload)
    canonical_json = canonical_json_bytes(event.to_dict(include_observational=False))
    digest = normalize_sha256_hex(_sha256_hex(canonical_json))
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
    canonical_bytes = canonical_json_bytes(canonicalize_value(item))
    return _sha256_hex(canonical_bytes)


def _v_seed() -> str:
    return "sha256:" + ("0" * 64)


def compute_release_digest(release_obj: dict[str, Any]) -> str:
    """Compute SHA256 digest over the full provider release payload (canonical JSON)."""
    canonical_bytes = canonical_json_bytes(canonicalize_value(release_obj))
    return f"sha256:{sha256(canonical_bytes).hexdigest()}"


def _sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()
