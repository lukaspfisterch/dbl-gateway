"""Tests for budget constraint computation."""
import pytest
from dbl_gateway.app import _compute_enforced_budget


class TestComputeEnforcedBudget:
    def test_no_budget(self):
        """No budget returns None."""
        result, constraints = _compute_enforced_budget(None, 60)
        assert result is None
        assert constraints == []

    def test_empty_budget(self):
        """Empty budget returns None."""
        result, constraints = _compute_enforced_budget({}, 60)
        assert result is None
        assert constraints == []

    def test_tokens_only(self):
        """max_tokens only passed through."""
        result, constraints = _compute_enforced_budget({"max_tokens": 4096}, 60, budget_source="client")
        assert result["max_tokens"] == 4096
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "client"
        assert constraints == ["runtime_default.max_duration_ms"]

    def test_duration_under_runtime(self):
        """Client duration under runtime limit keeps client source."""
        result, constraints = _compute_enforced_budget({"max_duration_ms": 30000}, 60, budget_source="client")
        assert result["max_duration_ms"] == 30000
        assert result["source"] == "client"
        assert constraints == []

    def test_duration_over_runtime_clamped(self):
        """Runtime clamp is tracked separately from the boundary/client source."""
        result, constraints = _compute_enforced_budget(
            {"max_duration_ms": 120000},
            60,
            budget_source="boundary_cap",
        )
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "boundary_cap"
        assert constraints == ["runtime_cap.max_duration_ms"]

    def test_duration_equal_runtime(self):
        """Client duration equal to runtime keeps client source."""
        result, constraints = _compute_enforced_budget({"max_duration_ms": 60000}, 60, budget_source="client")
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "client"
        assert constraints == []

    def test_full_budget(self):
        """Both max_tokens and max_duration_ms."""
        result, constraints = _compute_enforced_budget(
            {"max_tokens": 2048, "max_duration_ms": 15000},
            60,
            budget_source="boundary_default",
        )
        assert result["max_tokens"] == 2048
        assert result["max_duration_ms"] == 15000
        assert result["source"] == "boundary_default"
        assert constraints == []

    def test_effective_timeout_min_rule(self):
        """effective_timeout = min(runtime_ms, client_ms)."""
        result, constraints = _compute_enforced_budget(
            {"max_duration_ms": 45000},
            30,
            budget_source="client",
        )
        assert result["max_duration_ms"] == 30000
        assert constraints == ["runtime_cap.max_duration_ms"]

    def test_invalid_max_tokens_ignored(self):
        """Non-positive max_tokens ignored."""
        result, _ = _compute_enforced_budget(
            {"max_tokens": 0, "max_duration_ms": 10000},
            60,
            budget_source="client",
        )
        assert "max_tokens" not in result
        assert result["max_duration_ms"] == 10000

    def test_budget_integer_only(self):
        """Budget values are expected to be integers (validated at wire_contract)."""
        result, _ = _compute_enforced_budget({"max_duration_ms": 10000}, 60, budget_source="client")
        assert isinstance(result["max_duration_ms"], int)
