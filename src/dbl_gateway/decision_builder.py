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
) -> dict[str, object]:
    """Construct the normative decision payload used for digesting."""
    policy_id = decision.policy_id or "unknown"
    policy_version = decision.policy_version or "unknown"
    reasons = [{"code": code} for code in (decision.reason_codes or [])]
    norm_transforms = [dict(t) for t in (transforms or [])]
    return {
        "policy": {
            "policy_id": policy_id,
            "policy_version": policy_version,
        },
        "assembly_digest": assembly_digest,
        "context_digest": context_digest,
        "result": decision.decision,
        "reasons": reasons,
        "transforms": norm_transforms,
    }
