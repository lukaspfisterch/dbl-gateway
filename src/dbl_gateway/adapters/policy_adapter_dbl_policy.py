from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Mapping, get_type_hints

from dbl_policy import Policy, PolicyContext, PolicyDecision, decision_to_dbl_event

from ..ports.policy_port import DecisionResult, PolicyPort


ALLOWED_CONTEXT_KEYS = {
    "stream_id",
    "lane",
    "actor",
    "intent_type",
    "correlation_id",
    "payload",
}


@dataclass(frozen=True)
class DblPolicyAdapter(PolicyPort):
    def decide(self, authoritative_input: Mapping[str, Any]) -> DecisionResult:
        context = _build_policy_context(authoritative_input)
        decision = _evaluate_policy(context)
        gate_event = decision_to_dbl_event(decision, authoritative_input["correlation_id"])
        policy_version = _policy_version_as_int(decision.policy_version.value)
        return DecisionResult(
            decision=decision.outcome.value,
            reason_codes=[decision.reason_code],
            policy_id=decision.policy_id.value,
            policy_version=policy_version,
            gate_event=gate_event,
        )


def _build_policy_context(authoritative_input: Mapping[str, Any]) -> PolicyContext:
    filtered = {key: authoritative_input.get(key) for key in ALLOWED_CONTEXT_KEYS}
    tenant = authoritative_input.get("tenant_id", "unknown")
    tenant_type = _tenant_id_type()
    try:
        tenant_value = tenant_type(str(tenant))
    except Exception as exc:
        raise RuntimeError("invalid tenant_id") from exc
    return PolicyContext(tenant_id=tenant_value, inputs=filtered)


def _evaluate_policy(context: PolicyContext) -> PolicyDecision:
    policy = _load_policy()
    return policy.evaluate(context)


def _load_policy() -> Policy:
    module_path = _get_env("DBL_GATEWAY_POLICY_MODULE")
    obj_name = _get_env("DBL_GATEWAY_POLICY_OBJECT", "policy")
    module = import_module(module_path)
    obj = getattr(module, obj_name, None)
    if obj is None:
        raise RuntimeError("policy object not found")
    if callable(obj) and not hasattr(obj, "evaluate"):
        return obj()  # type: ignore[return-value]
    return obj  # type: ignore[return-value]


def _get_env(name: str, default: str | None = None) -> str:
    import os

    value = os.getenv(name, "")
    if value:
        return value
    if default is None:
        raise RuntimeError(f"{name} is required")
    return default


def _tenant_id_type() -> type:
    hints = get_type_hints(PolicyContext)
    tenant_type = hints.get("tenant_id")
    if not isinstance(tenant_type, type):
        raise RuntimeError("PolicyContext.tenant_id type missing")
    return tenant_type


def _policy_version_as_int(value: object) -> int:
    try:
        if isinstance(value, str):
            text = value.strip()
            if text == "":
                raise ValueError("empty")
            if "." in text:
                text = text.split(".", 1)[0]
            return int(text)
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("policy_version must be int") from exc
