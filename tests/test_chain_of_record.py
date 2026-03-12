"""Tests for Axis 4: Chain-of-Record / Observability.

Covers:
- policy_config_digest in normative DECISION payload
- intent_index (decision lineage) in DECISION payload
- compute_release_digest determinism
- release_digest in EXECUTION payload
"""
import json
import pytest
from typing import Any

from dbl_gateway.contracts import canonical_json_bytes
from dbl_gateway.decision_builder import build_normative_decision
from dbl_gateway.digest import compute_release_digest
from dbl_gateway.ports.policy_port import DecisionResult


# ---------------------------------------------------------------------------
# policy_config_digest
# ---------------------------------------------------------------------------

class TestPolicyConfigDigest:
    """policy_config_digest appears in normative DECISION payload."""

    def test_policy_config_digest_in_normative(self) -> None:
        dr = DecisionResult(
            decision="ALLOW",
            reason_codes=["ok"],
            policy_id="p1",
            policy_version="1",
            policy_config_digest="sha256:abc123",
        )
        norm = build_normative_decision(
            dr, assembly_digest=None, context_digest=None,
        )
        assert norm["policy"]["policy_config_digest"] == "sha256:abc123"

    def test_policy_config_digest_none_when_absent(self) -> None:
        dr = DecisionResult(
            decision="ALLOW",
            reason_codes=["ok"],
            policy_id="p1",
            policy_version="1",
        )
        norm = build_normative_decision(
            dr, assembly_digest=None, context_digest=None,
        )
        assert norm["policy"]["policy_config_digest"] is None

    def test_policy_config_digest_included_in_digest_scope(self) -> None:
        """Two decisions differing only in policy_config_digest produce different normative dicts."""
        base = dict(decision="ALLOW", reason_codes=["ok"], policy_id="p1", policy_version="1")
        dr_a = DecisionResult(**base, policy_config_digest="sha256:aaa")
        dr_b = DecisionResult(**base, policy_config_digest="sha256:bbb")
        norm_a = build_normative_decision(dr_a, assembly_digest=None, context_digest=None)
        norm_b = build_normative_decision(dr_b, assembly_digest=None, context_digest=None)
        assert canonical_json_bytes(norm_a) != canonical_json_bytes(norm_b)


# ---------------------------------------------------------------------------
# intent_index (decision lineage)
# ---------------------------------------------------------------------------

class TestIntentIndex:
    """DECISION.payload.intent_index links back to INTENT.index."""

    def test_intent_index_present_when_supplied(self) -> None:
        dr = DecisionResult(decision="ALLOW", reason_codes=["ok"], policy_id="p1", policy_version="1")
        norm = build_normative_decision(
            dr, assembly_digest=None, context_digest=None, intent_index=42,
        )
        assert norm["intent_index"] == 42

    def test_intent_index_absent_when_none(self) -> None:
        dr = DecisionResult(decision="ALLOW", reason_codes=["ok"], policy_id="p1", policy_version="1")
        norm = build_normative_decision(
            dr, assembly_digest=None, context_digest=None, intent_index=None,
        )
        assert "intent_index" not in norm

    def test_intent_index_zero_is_valid(self) -> None:
        dr = DecisionResult(decision="ALLOW", reason_codes=["ok"], policy_id="p1", policy_version="1")
        norm = build_normative_decision(
            dr, assembly_digest=None, context_digest=None, intent_index=0,
        )
        assert norm["intent_index"] == 0


# ---------------------------------------------------------------------------
# compute_release_digest
# ---------------------------------------------------------------------------

class TestComputeReleaseDigest:
    """Release digest is deterministic over the full provider payload."""

    def test_deterministic(self) -> None:
        obj = {"messages": [{"role": "user", "content": "hi"}], "model_id": "m1", "provider": "openai"}
        d1 = compute_release_digest(obj)
        d2 = compute_release_digest(obj)
        assert d1 == d2
        assert d1.startswith("sha256:")

    def test_different_messages_produce_different_digest(self) -> None:
        obj_a = {"messages": [{"role": "user", "content": "hello"}], "model_id": "m1", "provider": "p"}
        obj_b = {"messages": [{"role": "user", "content": "world"}], "model_id": "m1", "provider": "p"}
        assert compute_release_digest(obj_a) != compute_release_digest(obj_b)

    def test_key_order_irrelevant(self) -> None:
        """Canonical JSON sorts keys, so insertion order must not matter."""
        obj_a = {"model_id": "m1", "messages": [], "provider": "p"}
        obj_b = {"provider": "p", "messages": [], "model_id": "m1"}
        assert compute_release_digest(obj_a) == compute_release_digest(obj_b)

    def test_includes_tools_and_budget(self) -> None:
        """Adding permitted_tools or enforced_budget changes the digest."""
        base = {"messages": [], "model_id": "m1", "provider": "p"}
        with_tools = {**base, "permitted_tools": ["tool_a"]}
        with_budget = {**base, "enforced_budget": {"max_tokens": 100}}
        d_base = compute_release_digest(base)
        d_tools = compute_release_digest(with_tools)
        d_budget = compute_release_digest(with_budget)
        assert d_base != d_tools
        assert d_base != d_budget
        assert d_tools != d_budget

    def test_empty_release(self) -> None:
        """Even empty release objects produce a valid digest."""
        d = compute_release_digest({"messages": [], "model_id": "", "provider": ""})
        assert d.startswith("sha256:")
        assert len(d) == 71  # "sha256:" + 64 hex chars
