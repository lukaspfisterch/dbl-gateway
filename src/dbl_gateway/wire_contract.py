from __future__ import annotations

from typing import Any, Mapping, TypedDict

INTERFACE_VERSION = 1


class StackFingerprint(TypedDict):
    main_version: str
    policy_pack_digest: str
    boundary_config_hash: str


class WireEventSummary(TypedDict):
    index: int
    kind: str
    correlation_id: str
    digest: str
    canon_len: int
    payload: dict[str, Any]


class WireStreamSnapshot(TypedDict):
    interface_version: int
    v_digest: str
    length: int
    stack_fingerprint: StackFingerprint
    events: list[WireEventSummary]


def validate_interface_version(interface_version: int) -> None:
    if interface_version != INTERFACE_VERSION:
        raise ValueError(
            f"unsupported interface_version: {interface_version} (expected {INTERFACE_VERSION})"
        )


def validate_wire_snapshot(snapshot: object) -> WireStreamSnapshot:
    if not isinstance(snapshot, Mapping):
        raise ValueError("snapshot must be a mapping")
    interface_version = _require_int(snapshot, "interface_version")
    validate_interface_version(interface_version)
    v_digest = _require_str(snapshot, "v_digest")
    validate_digest_ref(v_digest, "v_digest")
    length = _require_int(snapshot, "length")
    stack_fingerprint_map = _require_mapping(snapshot, "stack_fingerprint")
    stack_fingerprint: StackFingerprint = {
        "main_version": _require_str(stack_fingerprint_map, "main_version"),
        "policy_pack_digest": _require_non_empty_str(stack_fingerprint_map, "policy_pack_digest"),
        "boundary_config_hash": _require_non_empty_str(stack_fingerprint_map, "boundary_config_hash"),
    }
    validate_unknown_or_digest_ref(stack_fingerprint["policy_pack_digest"], "policy_pack_digest")
    validate_unknown_or_opaque(stack_fingerprint["boundary_config_hash"], "boundary_config_hash")
    events = snapshot.get("events")
    if not isinstance(events, list):
        raise ValueError("events must be a list")
    validated_events = [validate_wire_event(event) for event in events]
    if length < len(validated_events):
        raise ValueError("length must be >= number of events")
    prev_index = None
    for event in validated_events:
        idx = event["index"]
        if idx < 0 or idx >= length:
            raise ValueError("event index must be within [0, length)")
        if prev_index is not None and idx <= prev_index:
            raise ValueError("event indices must be strictly increasing")
        prev_index = idx
    return {
        "interface_version": interface_version,
        "v_digest": v_digest,
        "length": length,
        "stack_fingerprint": stack_fingerprint,
        "events": validated_events,
    }


def validate_wire_event(event: object) -> WireEventSummary:
    if not isinstance(event, Mapping):
        raise ValueError("event must be a mapping")
    index = _require_int(event, "index")
    kind = _require_str(event, "kind")
    correlation_id = _require_str(event, "correlation_id")
    digest = _require_str(event, "digest")
    validate_digest_ref(digest, "digest")
    canon_len = _require_int(event, "canon_len")
    if canon_len < 0:
        raise ValueError("canon_len must be >= 0")
    payload_map = _require_mapping(event, "payload")
    payload: dict[str, Any] = dict(payload_map)
    return {
        "index": index,
        "kind": kind,
        "correlation_id": correlation_id,
        "digest": digest,
        "canon_len": canon_len,
        "payload": payload,
    }


def _require_str(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _require_non_empty_str(mapping: Mapping[str, object], key: str) -> str:
    value = _require_str(mapping, key)
    if value.strip() == "":
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _require_int(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int):
        raise ValueError(f"{key} must be an int")
    return value


def _require_mapping(mapping: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = mapping.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"{key} must be a mapping")
    return value


def validate_digest_ref(value: str, name: str) -> None:
    if ":" not in value:
        raise ValueError(f"{name} must be sha256:<64 hex>")
    algo, hex_value = value.split(":", 1)
    if algo != "sha256":
        raise ValueError(f"{name} must be sha256:<64 hex>")
    if len(hex_value) != 64:
        raise ValueError(f"{name} must be sha256:<64 hex>")
    try:
        bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be sha256:<64 hex>") from exc


def validate_unknown_or_digest_ref(value: str, name: str) -> None:
    if value == "unknown":
        return
    validate_digest_ref(value, name)


def validate_unknown_or_opaque(value: str, name: str) -> None:
    if value == "unknown":
        return
    if value.strip() == "":
        raise ValueError(f"{name} must be non-empty or unknown")
