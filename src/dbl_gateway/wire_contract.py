from __future__ import annotations

import re
from typing import Any, Mapping, TypedDict


INTERFACE_VERSION = 3

CAPABILITIES_INTENT_TYPES = ("chat.message", "artifact.handle")
SUPPORTED_TOOL_SCOPE = ("strict", "advisory")

MAX_DECLARED_TOOLS = 20
TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_.]{0,63}$"

BUDGET_FIELDS = ("max_tokens", "max_duration_ms")
BUDGET_LIMITS = {
    "max_tokens": {"min": 1, "max": 1_000_000},
    "max_duration_ms": {"min": 1000, "max": 300_000},
}


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
    declared_tools: list[str] | None
    tool_scope: str | None
    budget: dict[str, int] | None


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
    actor_id: str
    trust_class: str
    identity_issuer: str
    identity_verified: bool
    identity_source: str
    claims_digest: str
    request_class: str
    budget_class: str
    request_semantic_reason: str
    request_constraints_applied: list[str]
    budget_policy_reason: str
    slot_class: str
    cost_class: str
    reservation_required: bool
    economic_policy_reason: str
    declared_tool_families: list[str]
    allowed_tool_families: list[str]
    permitted_tool_families: list[str]
    denied_tool_families: list[str]
    permitted_tools: list[str]
    tool_scope_enforced: str
    tools_denied: list[str]
    tools_denied_reason: str
    enforced_budget: dict[str, Any]
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
    tool_calls: list[dict[str, Any]]
    tool_blocked: list[dict[str, Any]]
    usage: dict[str, Any]
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
    correlation_id_value = correlation_id.strip()
    payload = body.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be an object")
    stream_id = _default_string(payload.get("stream_id"), "default", "payload.stream_id")
    lane = _default_string(payload.get("lane"), "user_chat", "payload.lane")
    actor = _default_string(payload.get("actor"), "user", "payload.actor")
    intent_type = payload.get("intent_type")
    thread_id = _default_string(payload.get("thread_id"), correlation_id_value, "payload.thread_id")
    turn_id = _default_string(payload.get("turn_id"), correlation_id_value, "payload.turn_id")
    parent_turn_id = payload.get("parent_turn_id")
    inner_payload = payload.get("payload")
    inputs = payload.get("inputs")
    if not isinstance(intent_type, str) or intent_type.strip() == "":
        raise ValueError("payload.intent_type must be a non-empty string")
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
    declared_tools = _parse_declared_tools(payload.get("declared_tools"))
    tool_scope = _parse_tool_scope(payload.get("tool_scope"))
    budget = _parse_budget(payload.get("budget"))
    normalized_payload = dict(inner_payload)
    normalized_payload.setdefault("thread_id", thread_id)
    normalized_payload.setdefault("turn_id", turn_id)
    normalized_payload.setdefault("parent_turn_id", parent_turn_id.strip() if isinstance(parent_turn_id, str) else None)
    return {
        "interface_version": interface_version,
        "correlation_id": correlation_id_value,
        "payload": {
            "stream_id": stream_id,
            "lane": lane,
            "actor": actor,
            "intent_type": intent_type.strip(),
            "thread_id": thread_id,
            "turn_id": turn_id,
            "parent_turn_id": parent_turn_id.strip() if isinstance(parent_turn_id, str) else None,
            "payload": normalized_payload,
            "requested_model_id": requested_model_id.strip() if isinstance(requested_model_id, str) else None,
            "inputs": dict(inputs) if isinstance(inputs, Mapping) else None,
            "declared_refs": declared_refs,
            "declared_tools": declared_tools,
            "tool_scope": tool_scope,
            "budget": budget,
        },
    }


def _default_string(value: Any, default: str, field_name: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


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


_TOOL_NAME_RE = re.compile(TOOL_NAME_PATTERN)
_MAX_DECLARED_TOOLS = MAX_DECLARED_TOOLS


def _parse_declared_tools(raw: Any) -> list[str] | None:
    """Parse and validate declared_tools from payload."""
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("payload.declared_tools must be a list")
    if len(raw) > _MAX_DECLARED_TOOLS:
        raise ValueError(f"payload.declared_tools exceeds maximum of {_MAX_DECLARED_TOOLS}")
    parsed: list[str] = []
    for i, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"declared_tools[{i}] must be a non-empty string")
        name = item.strip()
        if not _TOOL_NAME_RE.match(name):
            raise ValueError(
                f"declared_tools[{i}] '{name}' does not match pattern {_TOOL_NAME_RE.pattern}"
            )
        parsed.append(name)
    return parsed


def _parse_tool_scope(raw: Any) -> str | None:
    """Parse and validate tool_scope from payload."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("payload.tool_scope must be a string")
    value = raw.strip()
    if value not in SUPPORTED_TOOL_SCOPE:
        raise ValueError("payload.tool_scope must be 'strict' or 'advisory'")
    return value


def _parse_budget(raw: Any) -> dict[str, int] | None:
    """Parse and validate budget from payload."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("payload.budget must be an object")
    budget: dict[str, int] = {}
    max_tokens = raw.get("max_tokens")
    if max_tokens is not None:
        if isinstance(max_tokens, float):
            raise ValueError("budget.max_tokens must be an integer, not float")
        if not isinstance(max_tokens, int):
            raise ValueError("budget.max_tokens must be an integer")
        min_tokens = BUDGET_LIMITS["max_tokens"]["min"]
        max_tokens_limit = BUDGET_LIMITS["max_tokens"]["max"]
        if max_tokens < min_tokens or max_tokens > max_tokens_limit:
            raise ValueError("budget.max_tokens must be between 1 and 1000000")
        budget["max_tokens"] = max_tokens
    max_duration_ms = raw.get("max_duration_ms")
    if max_duration_ms is not None:
        if isinstance(max_duration_ms, float):
            raise ValueError("budget.max_duration_ms must be an integer, not float")
        if not isinstance(max_duration_ms, int):
            raise ValueError("budget.max_duration_ms must be an integer")
        min_duration = BUDGET_LIMITS["max_duration_ms"]["min"]
        max_duration = BUDGET_LIMITS["max_duration_ms"]["max"]
        if max_duration_ms < min_duration or max_duration_ms > max_duration:
            raise ValueError("budget.max_duration_ms must be between 1000 and 300000")
        budget["max_duration_ms"] = max_duration_ms
    if not budget:
        raise ValueError("budget must contain at least one of max_tokens, max_duration_ms")
    return budget
