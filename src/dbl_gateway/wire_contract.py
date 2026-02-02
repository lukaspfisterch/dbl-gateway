from __future__ import annotations

from typing import Any, Mapping, TypedDict


INTERFACE_VERSION = 2


class IntentPayload(TypedDict, total=False):
    stream_id: str
    lane: str
    actor: str
    intent_type: str
    thread_id: str
    turn_id: str
    parent_turn_id: str | None
    payload: dict[str, Any]
    requested_model_id: str | None
    inputs: dict[str, Any] | None
    declared_refs: list[dict[str, Any]] | None  # NEW: Context refs


class IntentEnvelope(TypedDict):
    interface_version: int
    correlation_id: str
    payload: IntentPayload


class DecisionPayload(TypedDict, total=False):
    policy: dict[str, Any]
    assembly_digest: str | None
    context_digest: str | None
    result: str
    reasons: list[dict[str, Any]]
    transforms: list[dict[str, Any]]
    decision: str
    reason_codes: list[str]
    error_ref: str
    requested_model_id: str
    resolved_model_id: str
    provider: str
    policy_id: str
    policy_version: str
    _obs: dict[str, Any]


class ExecutionPayload(TypedDict, total=False):
    provider: str
    model_id: str
    requested_model_id: str
    resolved_model_id: str
    output_text: str
    error: dict[str, Any]
    trace: dict[str, Any]
    trace_digest: str
    context_digest: str
    _obs: dict[str, Any]


class EventRecord(TypedDict):
    index: int
    kind: str
    thread_id: str
    turn_id: str
    parent_turn_id: str | None
    lane: str
    actor: str
    intent_type: str
    stream_id: str
    correlation_id: str
    payload: dict[str, Any]
    digest: str
    canon_len: int
    is_authoritative: bool


class SnapshotResponse(TypedDict):
    length: int
    offset: int
    limit: int
    v_digest: str
    events: list[EventRecord]


class SnapshotQuery(TypedDict, total=False):
    limit: int
    offset: int
    stream_id: str
    lane: str


class TailQuery(TypedDict, total=False):
    since: int
    stream_id: str
    lanes: str


def parse_intent_envelope(body: Mapping[str, Any]) -> IntentEnvelope:
    interface_version = body.get("interface_version")
    if not isinstance(interface_version, int):
        raise ValueError("interface_version must be an int")
    if interface_version != INTERFACE_VERSION:
        raise ValueError("unsupported interface_version")
    correlation_id = body.get("correlation_id")
    if not isinstance(correlation_id, str) or correlation_id.strip() == "":
        raise ValueError("correlation_id must be a non-empty string")
    payload = body.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be an object")
    stream_id = payload.get("stream_id")
    lane = payload.get("lane")
    actor = payload.get("actor")
    intent_type = payload.get("intent_type")
    thread_id = payload.get("thread_id")
    turn_id = payload.get("turn_id")
    parent_turn_id = payload.get("parent_turn_id")
    inner_payload = payload.get("payload")
    inputs = payload.get("inputs")
    if not isinstance(stream_id, str) or stream_id.strip() == "":
        raise ValueError("payload.stream_id must be a non-empty string")
    if not isinstance(lane, str) or lane.strip() == "":
        raise ValueError("payload.lane must be a non-empty string")
    if not isinstance(actor, str) or actor.strip() == "":
        raise ValueError("payload.actor must be a non-empty string")
    if not isinstance(intent_type, str) or intent_type.strip() == "":
        raise ValueError("payload.intent_type must be a non-empty string")
    if not isinstance(thread_id, str) or thread_id.strip() == "":
        raise ValueError("payload.thread_id must be a non-empty string")
    if not isinstance(turn_id, str) or turn_id.strip() == "":
        raise ValueError("payload.turn_id must be a non-empty string")
    if parent_turn_id is not None and not isinstance(parent_turn_id, str):
        raise ValueError("payload.parent_turn_id must be a string")
    if not isinstance(inner_payload, Mapping):
        raise ValueError("payload.payload must be an object")
    requested_model_id = payload.get("requested_model_id")
    if inputs is not None and not isinstance(inputs, Mapping):
        raise ValueError("payload.inputs must be an object")
    if requested_model_id is not None and not isinstance(requested_model_id, str):
        raise ValueError("payload.requested_model_id must be a string")
    declared_refs = _parse_declared_refs(payload.get("declared_refs"))
    return {
        "interface_version": interface_version,
        "correlation_id": correlation_id.strip(),
        "payload": {
            "stream_id": stream_id.strip(),
            "lane": lane.strip(),
            "actor": actor.strip(),
            "intent_type": intent_type.strip(),
            "thread_id": thread_id.strip(),
            "turn_id": turn_id.strip(),
            "parent_turn_id": parent_turn_id.strip() if isinstance(parent_turn_id, str) else None,
            "payload": dict(inner_payload),
            "requested_model_id": requested_model_id.strip() if isinstance(requested_model_id, str) else None,
            "inputs": dict(inputs) if isinstance(inputs, Mapping) else None,
            "declared_refs": declared_refs,
        },
    }


def _parse_declared_refs(raw: Any) -> list[dict[str, Any]] | None:
    """Parse and validate declared_refs from payload."""
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("payload.declared_refs must be a list")
    
    parsed: list[dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"declared_refs[{i}] must be an object")
        ref_type = item.get("ref_type")
        ref_id = item.get("ref_id")
        if not isinstance(ref_type, str) or not ref_type.strip():
            raise ValueError(f"declared_refs[{i}].ref_type must be a non-empty string")
        if not isinstance(ref_id, str) or not ref_id.strip():
            raise ValueError(f"declared_refs[{i}].ref_id must be a non-empty string")
        ref: dict[str, Any] = {
            "ref_type": ref_type.strip(),
            "ref_id": ref_id.strip(),
        }
        version = item.get("version")
        if version is not None:
            ref["version"] = str(version)
        parsed.append(ref)
    return parsed
