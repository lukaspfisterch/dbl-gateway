from __future__ import annotations

from .adapters.policy_adapter_dbl_policy import (
    ALLOWED_CONTEXT_KEYS,
    DblPolicyAdapter,
    _build_policy_context,
)
from .ports.policy_port import DecisionResult

__all__ = [
    "ALLOWED_CONTEXT_KEYS",
    "DecisionResult",
    "DblPolicyAdapter",
    "_build_policy_context",
    "decide_for_intent",
]


def decide_for_intent(authoritative_input):
    return DblPolicyAdapter().decide(authoritative_input)
