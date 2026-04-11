from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Mapping, get_type_hints

from dbl_policy import decide_safe
from dbl_policy.bridge import decision_to_dbl_event
from dbl_policy.model import ALLOWED_CONTEXT_KEYS as POLICY_ALLOWED_CONTEXT_KEYS
from dbl_policy.model import (
    DecisionOutcome,
    Policy,
    PolicyContext,
    PolicyDecision,
    PolicyId,
    PolicyVersion,
)

from ..ports.policy_port import DecisionResult, PolicyPort


ALLOWED_CONTEXT_KEYS = set(POLICY_ALLOWED_CONTEXT_KEYS)


class ObserverPolicy:
    """Policy that always denies in Observer Mode."""
    policy_id = PolicyId("observer")
    policy_version = PolicyVersion("1")

    def evaluate(self, context: Any) -> PolicyDecision:
        return PolicyDecision(
            outcome=DecisionOutcome.DENY,
            reason_code="gateway.observer_mode",
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            tenant_id=context.tenant_id,
        )


@dataclass(frozen=True)
class DblPolicyAdapter(PolicyPort):
    policy: Policy | None = None

    # Intent types that are metadata-only and bypass full policy evaluation.
    _METADATA_ONLY_INTENTS: frozenset[str] = frozenset({"artifact.handle"})

    def decide(self, authoritative_input: Mapping[str, Any]) -> DecisionResult:
        # Metadata-only intents get a deterministic ALLOW without full evaluation.
        intent_type = authoritative_input.get("intent_type", "")
        if intent_type in self._METADATA_ONLY_INTENTS:
            return DecisionResult(
                decision="ALLOW",
                reason_codes=["HANDLE_METADATA_ONLY"],
                policy_id="builtin",
                policy_version="1",
                tenant_id=_tenant_id_value(authoritative_input),
            )

        policy = self.policy or _load_policy()
        decision = decide_safe(
            policy,
            tenant_id=_tenant_id_value(authoritative_input),
            inputs=_extract_policy_inputs(authoritative_input),
        )
        gate_event = decision_to_dbl_event(decision, authoritative_input["correlation_id"])
        policy_version = _policy_version_as_str(decision.policy_version.value)
        return DecisionResult(
            decision=decision.outcome.value,
            reason_codes=[decision.reason_code],
            policy_id=decision.policy_id.value,
            policy_version=policy_version,
            gate_event=gate_event,
            tenant_id=_tenant_id_value(authoritative_input),
        )


def _build_policy_context(authoritative_input: Mapping[str, Any]) -> PolicyContext:
    filtered = _extract_policy_inputs(authoritative_input)
    tenant_type = _tenant_id_type()
    try:
        tenant_value = tenant_type(_tenant_id_value(authoritative_input))
    except Exception as exc:
        raise RuntimeError("invalid tenant_id") from exc
    return PolicyContext(tenant_id=tenant_value, inputs=filtered)


def _extract_policy_inputs(authoritative_input: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = authoritative_input.get("payload")
    inputs_source = payload
    if isinstance(payload, Mapping):
        maybe_inputs = payload.get("inputs")
        if isinstance(maybe_inputs, Mapping):
            inputs_source = maybe_inputs
    if not isinstance(inputs_source, Mapping):
        return {}
    return {key: inputs_source[key] for key in ALLOWED_CONTEXT_KEYS if key in inputs_source}


def _tenant_id_value(authoritative_input: Mapping[str, Any]) -> str:
    return str(authoritative_input.get("tenant_id", "unknown"))


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
