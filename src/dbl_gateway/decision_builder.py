from __future__ import annotations

from typing import Mapping, Sequence

from .ports.policy_port import DecisionResult

__all__ = ["build_normative_decision"]


def build_normative_decision(
    decision: DecisionResult,
    *,
    assembly_digest: str | None,
    context_digest: str | None,
    transforms: Sequence[Mapping[str, object]] | None = None,
    intent_index: int | None = None,
) -> dict[str, object]:
    """Construct the normative decision payload used for digesting."""
    policy_id = decision.policy_id or "unknown"
    policy_version = decision.policy_version or "unknown"
    reasons = [{"code": code} for code in (decision.reason_codes or [])]
    norm_transforms = [dict(t) for t in (transforms or [])]
    normative: dict[str, object] = {
        "policy": {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_config_digest": decision.policy_config_digest,
        },
        "assembly_digest": assembly_digest,
        "context_digest": context_digest,
        "result": decision.decision,
        "reasons": reasons,
        "transforms": norm_transforms,
        "actor_id": decision.actor_id,
        "trust_class": decision.trust_class,
        "identity_issuer": decision.identity_issuer,
        "identity_verified": decision.identity_verified,
        "identity_source": decision.identity_source,
        "claims_digest": decision.claims_digest,
        "request_class": decision.request_class,
        "budget_class": decision.budget_class,
        "request_semantic_reason": decision.request_semantic_reason,
        "request_constraints_applied": decision.request_constraints_applied,
        "budget_policy_reason": decision.budget_policy_reason,
        "slot_class": decision.slot_class,
        "cost_class": decision.cost_class,
        "reservation_required": decision.reservation_required,
        "economic_policy_reason": decision.economic_policy_reason,
        "declared_tool_families": decision.declared_tool_families,
        "allowed_tool_families": decision.allowed_tool_families,
        "permitted_tool_families": decision.permitted_tool_families,
        "denied_tool_families": decision.denied_tool_families,
        "permitted_tools": decision.permitted_tools,
        "enforced_budget": decision.enforced_budget,
    }
    if intent_index is not None:
        normative["intent_index"] = intent_index
    return normative
