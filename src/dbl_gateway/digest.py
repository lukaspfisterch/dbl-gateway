from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Mapping


def sanitize_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    sanitized.pop("_obs", None)
    return sanitized


def canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"non-canonical payload: {exc}") from exc
    return text.encode("utf-8")


def event_digest(kind: str, correlation_id: str, payload: Mapping[str, Any]) -> tuple[str, int]:
    payload_det = sanitize_payload(payload)
    event_data = {
        "kind": kind,
        "deterministic_fields": {
            "correlation_id": correlation_id,
            "payload": payload_det,
        },
    }
    canon = canonical_bytes(event_data)
    digest_bytes = hashlib.sha256(canon).digest()
    digest_ref = f"sha256:{digest_bytes.hex()}"
    return digest_ref, len(canon)


def digest_ref_to_bytes(digest_ref: str) -> bytes:
    if ":" not in digest_ref:
        raise ValueError("digest-ref must be sha256:<64 hex>")
    algo, hex_value = digest_ref.split(":", 1)
    if algo != "sha256" or len(hex_value) != 64:
        raise ValueError("digest-ref must be sha256:<64 hex>")
    try:
        return bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValueError("digest-ref must be sha256:<64 hex>") from exc


def v_digest(indexed_digests: list[tuple[int, str]]) -> str:
    hasher = hashlib.sha256()
    for idx, digest_ref in indexed_digests:
        hasher.update(struct.pack(">Q", idx))
        hasher.update(digest_ref_to_bytes(digest_ref))
    return f"sha256:{hasher.hexdigest()}"
