"""Tests for normative decision surface including v0.6.0 fields."""
import pytest
from dbl_gateway.ports.policy_port import DecisionResult
from dbl_gateway.decision_builder import build_normative_decision
from dbl_gateway.contracts import _normalize_decision


class TestNormativeDecisionV3:
    def test_request_policy_fields_in_normative(self):
        """Request-policy governance fields appear in normative dict."""
        decision = DecisionResult(
            decision="ALLOW",
            reason_codes=[],
            request_class="execution_light",
            budget_class="light",
            request_semantic_reason="request.semantic.bounded_execution",
            request_constraints_applied=["budget.light_or_none"],
            budget_policy_reason="request.budget_clamped",
        )
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["request_class"] == "execution_light"
        assert normative["budget_class"] == "light"
        assert normative["request_semantic_reason"] == "request.semantic.bounded_execution"
        assert normative["request_constraints_applied"] == ["budget.light_or_none"]
        assert normative["budget_policy_reason"] == "request.budget_clamped"

    def test_economic_policy_fields_in_normative(self):
        """Economic policy fields appear in normative dict."""
        decision = DecisionResult(
            decision="ALLOW",
            reason_codes=[],
            slot_class="reserved",
            cost_class="capped",
            reservation_required=True,
            economic_policy_reason="economic.reserved.capped.reservation_required",
        )
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["slot_class"] == "reserved"
        assert normative["cost_class"] == "capped"
        assert normative["reservation_required"] is True
        assert normative["economic_policy_reason"] == "economic.reserved.capped.reservation_required"

    def test_tool_families_in_normative(self):
        """Tool-family governance fields appear in normative dict."""
        decision = DecisionResult(
            decision="ALLOW",
            reason_codes=[],
            declared_tool_families=["web_read", "exec_like"],
            allowed_tool_families=["web_read"],
            permitted_tool_families=["web_read"],
            denied_tool_families=["exec_like"],
        )
        normative = build_normative_decision(
            decision, assembly_digest=None, context_digest=None,
        )
        assert normative["declared_tool_families"] == ["web_read", "exec_like"]
        assert normative["allowed_tool_families"] == ["web_read"]
        assert normative["permitted_tool_families"] == ["web_read"]
        assert normative["denied_tool_families"] == ["exec_like"]

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
            enforced_budget={"max_tokens": 4096, "max_duration_ms": 30000, "source": "client"},
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
            "request_class": "execution_light",
            "budget_class": "light",
            "request_semantic_reason": "request.semantic.bounded_execution",
            "request_constraints_applied": ["budget.light_or_none"],
            "budget_policy_reason": "request.budget_clamped",
            "slot_class": "shared",
            "cost_class": "bounded",
            "reservation_required": False,
            "economic_policy_reason": "economic.shared.bounded",
            "declared_tool_families": ["web_read", "exec_like"],
            "allowed_tool_families": ["web_read"],
            "permitted_tool_families": ["web_read"],
            "denied_tool_families": ["exec_like"],
            "permitted_tools": ["z_tool", "a_tool"],
            "enforced_budget": None,
        })
        assert norm["permitted_tools"] == ["a_tool", "z_tool"]
        assert norm["slot_class"] == "shared"
        assert norm["cost_class"] == "bounded"
        assert norm["reservation_required"] is False

    def test_tool_families_sorted_in_digest(self):
        """Normalization sorts tool-family fields for stable digest."""
        norm = _normalize_decision({
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "request_class": None,
            "budget_class": None,
            "request_semantic_reason": None,
            "request_constraints_applied": None,
            "budget_policy_reason": None,
            "declared_tool_families": ["web_read", "exec_like"],
            "allowed_tool_families": ["web_read", "data_access"],
            "permitted_tool_families": ["web_read", "data_access"],
            "denied_tool_families": ["exec_like"],
            "permitted_tools": None,
            "enforced_budget": None,
        })
        assert norm["declared_tool_families"] == ["exec_like", "web_read"]
        assert norm["allowed_tool_families"] == ["data_access", "web_read"]
        assert norm["denied_tool_families"] == ["exec_like"]

    def test_digest_changes_with_tools(self):
        """Different permitted_tools produce different digests."""
        base = {
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "request_class": None,
            "budget_class": None,
            "request_semantic_reason": None,
            "request_constraints_applied": None,
            "budget_policy_reason": None,
            "declared_tool_families": ["web_read"],
            "allowed_tool_families": ["web_read"],
            "permitted_tool_families": ["web_read"],
            "denied_tool_families": [],
            "enforced_budget": None,
        }
        norm_a = _normalize_decision({**base, "permitted_tools": ["tool_a"]})
        norm_b = _normalize_decision({**base, "permitted_tools": ["tool_b"]})
        assert norm_a != norm_b

    def test_digest_changes_with_tool_families(self):
        """Different permitted_tool_families produce different digests."""
        base = {
            "policy": {"policy_id": "p1", "policy_version": "v1"},
            "assembly_digest": None,
            "context_digest": None,
            "transforms": [],
            "result": "ALLOW",
            "reasons": [],
            "request_class": None,
            "budget_class": None,
            "request_semantic_reason": None,
            "request_constraints_applied": None,
            "budget_policy_reason": None,
            "permitted_tools": None,
            "denied_tool_families": None,
            "enforced_budget": None,
        }
        norm_a = _normalize_decision({**base, "permitted_tool_families": ["web_read"]})
        norm_b = _normalize_decision({**base, "permitted_tool_families": ["data_access"]})
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
            "request_class": None,
            "budget_class": None,
            "request_semantic_reason": None,
            "request_constraints_applied": None,
            "budget_policy_reason": None,
            "declared_tool_families": ["web_read"],
            "allowed_tool_families": ["web_read"],
            "permitted_tool_families": ["web_read"],
            "denied_tool_families": [],
            "permitted_tools": None,
        }
        norm_a = _normalize_decision({**base, "enforced_budget": {"max_tokens": 100}})
        norm_b = _normalize_decision({**base, "enforced_budget": {"max_tokens": 200}})
        assert norm_a != norm_b
