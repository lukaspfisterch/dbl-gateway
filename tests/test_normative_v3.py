"""Tests for normative decision surface including v0.6.0 fields."""
import pytest
from dbl_gateway.ports.policy_port import DecisionResult
from dbl_gateway.decision_builder import build_normative_decision
from dbl_gateway.contracts import _normalize_decision


class TestNormativeDecisionV3:
    def test_permitted_tools_in_normative(self):
        """permitted_tools appears in normative dict."""
        decision = DecisionResult(
            decision="ALLOW",
            reason_codes=[],
            permitted_tools=["web.search", "code.execute"],
        )
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["permitted_tools"] == ["web.search", "code.execute"]

    def test_enforced_budget_in_normative(self):
        """enforced_budget appears in normative dict."""
        decision = DecisionResult(
            decision="ALLOW",
            reason_codes=[],
            enforced_budget={"max_tokens": 4096, "max_duration_ms": 30000, "source": "intent_exact"},
        )
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["enforced_budget"]["max_tokens"] == 4096

    def test_null_tools_and_budget_in_normative(self):
        """None values propagate as None."""
        decision = DecisionResult(decision="ALLOW", reason_codes=[])
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["permitted_tools"] is None
        assert normative["enforced_budget"] is None

    def test_permitted_tools_sorted_in_digest(self):
        """Normalization sorts permitted_tools for stable digest."""
        norm = _normalize_decision({
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "permitted_tools": ["z_tool", "a_tool"],
            "enforced_budget": None,
        })
        assert norm["permitted_tools"] == ["a_tool", "z_tool"]

    def test_digest_changes_with_tools(self):
        """Different permitted_tools produce different digests."""
        base = {
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "enforced_budget": None,
        }
        norm_a = _normalize_decision({**base, "permitted_tools": ["tool_a"]})
        norm_b = _normalize_decision({**base, "permitted_tools": ["tool_b"]})
        assert norm_a != norm_b

    def test_digest_changes_with_budget(self):
        """Different enforced_budget produce different digests."""
        base = {
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "permitted_tools": None,
        }
        norm_a = _normalize_decision({**base, "enforced_budget": {"max_tokens": 100}})
        norm_b = _normalize_decision({**base, "enforced_budget": {"max_tokens": 200}})
        assert norm_a != norm_b
