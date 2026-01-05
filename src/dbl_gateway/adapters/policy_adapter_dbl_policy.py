from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Mapping, get_type_hints

from dbl_policy import Policy, PolicyContext, PolicyDecision, decision_to_dbl_event
from dbl_policy.model import ALLOWED_CONTEXT_KEYS as POLICY_ALLOWED_CONTEXT_KEYS

from ..ports.policy_port import DecisionResult, PolicyPort


ALLOWED_CONTEXT_KEYS = set(POLICY_ALLOWED_CONTEXT_KEYS)


@dataclass(frozen=True)
class DblPolicyAdapter(PolicyPort):
    policy: Policy | None = None

    def decide(self, authoritative_input: Mapping[str, Any]) -> DecisionResult:
        try:
            context = _build_policy_context(authoritative_input)
        except ContextShapeError:
            return DecisionResult(decision="DENY", reason_codes=["context.invalid_shape"])
        policy = self.policy or _load_policy()
        decision = policy.evaluate(context)
        gate_event = decision_to_dbl_event(decision, authoritative_input["correlation_id"])
        policy_version = _policy_version_as_str(decision.policy_version.value)
        return DecisionResult(
            decision=decision.outcome.value,
            reason_codes=[decision.reason_code],
            policy_id=decision.policy_id.value,
            policy_version=policy_version,
            gate_event=gate_event,
        )


def _build_policy_context(authoritative_input: Mapping[str, Any]) -> PolicyContext:
    payload = authoritative_input.get("payload")
    inputs_source = payload
    if isinstance(payload, Mapping):
        maybe_inputs = payload.get("inputs")
        if isinstance(maybe_inputs, Mapping):
            inputs_source = maybe_inputs
    if isinstance(inputs_source, Mapping):
        filtered = {key: inputs_source[key] for key in ALLOWED_CONTEXT_KEYS if key in inputs_source}
        _assert_scalar_inputs(filtered)
    else:
        filtered = {}
    tenant = authoritative_input.get("tenant_id", "unknown")
    tenant_type = _tenant_id_type()
    try:
        tenant_value = tenant_type(str(tenant))
    except Exception as exc:
        raise RuntimeError("invalid tenant_id") from exc
    return PolicyContext(tenant_id=tenant_value, inputs=filtered)


class ContextShapeError(ValueError):
    pass


def _assert_scalar_inputs(inputs: Mapping[str, Any]) -> None:
    for key, value in inputs.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            continue
        raise ContextShapeError(f"context key {key} must be scalar")


def _load_policy() -> Policy:
    module_path = _get_env("DBL_GATEWAY_POLICY_MODULE")
    obj_name = _get_env("DBL_GATEWAY_POLICY_OBJECT", "POLICY")
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


def _policy_version_as_str(value: object) -> str:
    try:
        if isinstance(value, str):
            text = value.strip()
            if text == "":
                raise ValueError("empty")
            return text
        return str(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("policy_version must be str") from exc
