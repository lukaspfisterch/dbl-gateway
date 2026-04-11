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

    # Reconstruct gateway-enriched fields from stored decision payload.
    # The gateway computes permitted_tools, enforced_budget, and
    # policy_config_digest after policy.decide() — these are part of the
    # normative digest and must be restored for replay equivalence.
    stored_permitted_tools = decision_payload.get("permitted_tools")
    stored_enforced_budget = decision_payload.get("enforced_budget")
    stored_actor_id = decision_payload.get("actor_id")
    stored_trust_class = decision_payload.get("trust_class")
    stored_identity_issuer = decision_payload.get("identity_issuer")
    stored_identity_verified = decision_payload.get("identity_verified")
    stored_identity_source = decision_payload.get("identity_source")
    stored_claims_digest = decision_payload.get("claims_digest")
    stored_request_class = decision_payload.get("request_class")
    stored_budget_class = decision_payload.get("budget_class")
    stored_request_semantic_reason = decision_payload.get("request_semantic_reason")
    stored_request_constraints_applied = decision_payload.get("request_constraints_applied")
    stored_budget_policy_reason = decision_payload.get("budget_policy_reason")
    stored_slot_class = decision_payload.get("slot_class")
    stored_cost_class = decision_payload.get("cost_class")
    stored_reservation_required = decision_payload.get("reservation_required")
    stored_economic_policy_reason = decision_payload.get("economic_policy_reason")
    stored_declared_tool_families = decision_payload.get("declared_tool_families")
    stored_allowed_tool_families = decision_payload.get("allowed_tool_families")
    stored_permitted_tool_families = decision_payload.get("permitted_tool_families")
    stored_denied_tool_families = decision_payload.get("denied_tool_families")
    stored_policy_config_digest = stored_policy.get("policy_config_digest")

    decision_for_digest = DecisionResult(
        decision=policy_result.decision,
        reason_codes=policy_result.reason_codes,
        policy_id=stored_policy.get("policy_id") or policy_result.policy_id,
        policy_version=stored_policy.get("policy_version") or policy_result.policy_version,
        gate_event=policy_result.gate_event,
        actor_id=stored_actor_id if isinstance(stored_actor_id, str) else None,
        trust_class=stored_trust_class if isinstance(stored_trust_class, str) else None,
        identity_issuer=stored_identity_issuer if isinstance(stored_identity_issuer, str) else None,
        identity_verified=stored_identity_verified if isinstance(stored_identity_verified, bool) else None,
        identity_source=stored_identity_source if isinstance(stored_identity_source, str) else None,
        claims_digest=stored_claims_digest if isinstance(stored_claims_digest, str) else None,
        request_class=stored_request_class if isinstance(stored_request_class, str) else None,
        budget_class=stored_budget_class if isinstance(stored_budget_class, str) else None,
        request_semantic_reason=(
            stored_request_semantic_reason if isinstance(stored_request_semantic_reason, str) else None
        ),
        request_constraints_applied=(
            stored_request_constraints_applied if isinstance(stored_request_constraints_applied, list) else None
        ),
        budget_policy_reason=(
            stored_budget_policy_reason if isinstance(stored_budget_policy_reason, str) else None
        ),
        slot_class=stored_slot_class if isinstance(stored_slot_class, str) else None,
        cost_class=stored_cost_class if isinstance(stored_cost_class, str) else None,
        reservation_required=stored_reservation_required if isinstance(stored_reservation_required, bool) else None,
        economic_policy_reason=(
            stored_economic_policy_reason if isinstance(stored_economic_policy_reason, str) else None
        ),
        declared_tool_families=(
            stored_declared_tool_families if isinstance(stored_declared_tool_families, list) else None
        ),
        allowed_tool_families=(
            stored_allowed_tool_families if isinstance(stored_allowed_tool_families, list) else None
        ),
        permitted_tool_families=(
            stored_permitted_tool_families if isinstance(stored_permitted_tool_families, list) else None
        ),
        denied_tool_families=(
            stored_denied_tool_families if isinstance(stored_denied_tool_families, list) else None
        ),
        permitted_tools=stored_permitted_tools if isinstance(stored_permitted_tools, list) else None,
        enforced_budget=stored_enforced_budget if isinstance(stored_enforced_budget, dict) else None,
        policy_config_digest=stored_policy_config_digest if isinstance(stored_policy_config_digest, str) else None,
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
        intent_index=_as_int(decision_payload.get("intent_index")),
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


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


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
