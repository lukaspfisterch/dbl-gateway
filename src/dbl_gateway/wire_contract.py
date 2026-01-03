from __future__ import annotations

from typing import Any, Mapping, TypedDict


INTERFACE_VERSION = 1


class IntentPayload(TypedDict):
    stream_id: str
    lane: str
    actor: str
    intent_type: str
    payload: dict[str, Any]
    requested_model_id: str | None
    inputs: dict[str, Any] | None


class IntentEnvelope(TypedDict):
    interface_version: int
    correlation_id: str
    payload: IntentPayload


class DecisionPayload(TypedDict, total=False):
    decision: str
    reason_codes: list[str]
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


class EventRecord(TypedDict):
    index: int
    kind: str
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
    if not isinstance(inner_payload, Mapping):
        raise ValueError("payload.payload must be an object")
    requested_model_id = payload.get("requested_model_id")
    if inputs is not None and not isinstance(inputs, Mapping):
        raise ValueError("payload.inputs must be an object")
    if requested_model_id is not None and not isinstance(requested_model_id, str):
        raise ValueError("payload.requested_model_id must be a string")
    return {
        "interface_version": interface_version,
        "correlation_id": correlation_id.strip(),
        "payload": {
            "stream_id": stream_id.strip(),
            "lane": lane.strip(),
            "actor": actor.strip(),
            "intent_type": intent_type.strip(),
            "payload": dict(inner_payload),
            "requested_model_id": requested_model_id.strip() if isinstance(requested_model_id, str) else None,
            "inputs": dict(inputs) if isinstance(inputs, Mapping) else None,
        },
    }
