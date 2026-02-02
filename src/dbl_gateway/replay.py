from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .adapters.policy_adapter_dbl_policy import DblPolicyAdapter
from .contracts import context_digest, decision_digest
from .decision_builder import build_normative_decision
from .models import EventRecord
from .ports.policy_port import DecisionResult, PolicyPort
from .ports.store_port import StorePort


class DecisionReplayError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class DecisionReplayResult:
    assembly_digest: str
    context_digest: str | None
    recomputed_decision_digest: str
    stored_decision_digest: str
    decision_event: EventRecord
    intent_event: EventRecord


def replay_decision_for_turn(
    store: StorePort,
    *,
    thread_id: str,
    turn_id: str,
    policy: PolicyPort | None = None,
) -> DecisionReplayResult:
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise DecisionReplayError("input.invalid", "thread_id is required")
    if not isinstance(turn_id, str) or not turn_id.strip():
        raise DecisionReplayError("input.invalid", "turn_id is required")

    snapshot = store.snapshot(limit=5000, offset=0)
    events = snapshot.get("events", [])
    matching = [event for event in events if _event_matches_turn(event, thread_id, turn_id)]
    decision_event = _latest_of_kind(matching, "DECISION")
    if decision_event is None:
        raise DecisionReplayError("decision.not_found", "no DECISION event for turn")
    intent_event = _latest_of_kind(matching, "INTENT")
    if intent_event is None:
        raise DecisionReplayError("intent.not_found", "no INTENT event for turn")

    decision_payload = decision_event.get("payload")
    if not isinstance(decision_payload, Mapping):
        raise DecisionReplayError("decision.payload_invalid", "decision payload must be an object")
    context_spec = decision_payload.get("context_spec")
    assembled_context = decision_payload.get("assembled_context")
    if not isinstance(context_spec, Mapping) or not isinstance(assembled_context, Mapping):
        raise DecisionReplayError("context.missing", "context_spec and assembled_context are required for replay")
    try:
        computed_context_digest = context_digest(context_spec, assembled_context)
    except Exception as exc:
        raise DecisionReplayError("context.invalid", str(exc)) from exc
    stored_assembly_digest = decision_payload.get("assembly_digest")
    if stored_assembly_digest is None:
        raise DecisionReplayError("assembly_digest.missing", "assembly_digest missing from decision payload")
    if not isinstance(stored_assembly_digest, str):
        raise DecisionReplayError("assembly_digest.invalid", "assembly_digest must be a string")
    if computed_context_digest != stored_assembly_digest:
        raise DecisionReplayError(
            "assembly_digest.mismatch",
            "assembly_digest does not match recomputed value from stored context artifacts",
        )

    stored_context_digest = decision_payload.get("context_digest")

    stored_policy = _policy_from_payload(decision_payload)
    transforms = decision_payload.get("transforms")
    transform_list: Sequence[Mapping[str, Any]] | None = transforms if isinstance(transforms, list) else []
    correlation_id = str(decision_event.get("correlation_id") or intent_event.get("correlation_id") or "")
    authoritative = _authoritative_from_event(intent_event, correlation_id)

    policy_adapter = policy or DblPolicyAdapter()
    try:
        policy_result = policy_adapter.decide(authoritative)
    except Exception as exc:
        raise DecisionReplayError("policy.failed", f"policy evaluation failed: {exc}") from exc

    decision_for_digest = DecisionResult(
        decision=policy_result.decision,
        reason_codes=policy_result.reason_codes,
        policy_id=stored_policy.get("policy_id") or policy_result.policy_id,
        policy_version=stored_policy.get("policy_version") or policy_result.policy_version,
        gate_event=policy_result.gate_event,
    )
    context_digest_value = computed_context_digest if decision_for_digest.decision == "ALLOW" else None
    if decision_for_digest.decision == "ALLOW":
        if not isinstance(stored_context_digest, str):
            raise DecisionReplayError(
                "context_digest.missing",
                "context_digest missing from ALLOW decision payload",
            )
        if stored_context_digest != computed_context_digest:
            raise DecisionReplayError(
                "context_digest.mismatch",
                "context_digest does not match recomputed value from stored context artifacts",
            )
    normative = build_normative_decision(
        decision_for_digest,
        assembly_digest=computed_context_digest,
        context_digest=context_digest_value,
        transforms=transform_list,
    )
    recomputed_decision_digest = decision_digest(normative)
    stored_decision_digest = decision_event.get("digest") if isinstance(decision_event.get("digest"), str) else ""

    return DecisionReplayResult(
        assembly_digest=computed_context_digest,
        context_digest=context_digest_value,
        recomputed_decision_digest=recomputed_decision_digest,
        stored_decision_digest=stored_decision_digest,
        decision_event=decision_event,
        intent_event=intent_event,
    )


def _event_matches_turn(event: Mapping[str, Any], thread_id: str, turn_id: str) -> bool:
    return event.get("thread_id") == thread_id and event.get("turn_id") == turn_id


def _latest_of_kind(events: Sequence[Mapping[str, Any]], kind: str) -> EventRecord | None:
    filtered = [event for event in events if event.get("kind") == kind]
    if not filtered:
        return None
    return max(filtered, key=lambda e: e.get("index", -1))


def _policy_from_payload(decision_payload: Mapping[str, Any]) -> Mapping[str, str]:
    policy = decision_payload.get("policy")
    if isinstance(policy, Mapping):
        policy_id = policy.get("policy_id")
        policy_version = policy.get("policy_version")
        out: dict[str, str] = {}
        if isinstance(policy_id, str):
            out["policy_id"] = policy_id
        if isinstance(policy_version, str):
            out["policy_version"] = policy_version
        return out
    return {}


def _authoritative_from_event(intent_event: Mapping[str, Any], correlation_id: str) -> dict[str, Any]:
    payload = intent_event.get("payload")
    return {
        "stream_id": intent_event.get("stream_id"),
        "lane": intent_event.get("lane"),
        "actor": intent_event.get("actor"),
        "intent_type": intent_event.get("intent_type"),
        "correlation_id": correlation_id,
        "payload": payload,
    }
