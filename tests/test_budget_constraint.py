"""Tests for budget constraint computation."""
import pytest
from dbl_gateway.app import _compute_enforced_budget


class TestComputeEnforcedBudget:
    def test_no_budget(self):
        """No budget returns None."""
        assert _compute_enforced_budget(None, 60) is None

    def test_empty_budget(self):
        """Empty budget returns None."""
        assert _compute_enforced_budget({}, 60) is None

    def test_tokens_only(self):
        """max_tokens only passed through."""
        result = _compute_enforced_budget({"max_tokens": 4096}, 60)
        assert result["max_tokens"] == 4096
        # duration defaults to runtime
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "policy_default"

    def test_duration_under_runtime(self):
        """Client duration under runtime limit: intent_exact."""
        result = _compute_enforced_budget({"max_duration_ms": 30000}, 60)
        assert result["max_duration_ms"] == 30000
        assert result["source"] == "intent_exact"

    def test_duration_over_runtime_clamped(self):
        """Client duration over runtime limit: clamped to runtime."""
        result = _compute_enforced_budget({"max_duration_ms": 120000}, 60)
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "intent_clamped"

    def test_duration_equal_runtime(self):
        """Client duration equal to runtime: intent_exact (min picks equal)."""
        result = _compute_enforced_budget({"max_duration_ms": 60000}, 60)
        assert result["max_duration_ms"] == 60000
        assert result["source"] == "intent_exact"

    def test_full_budget(self):
        """Both max_tokens and max_duration_ms."""
        result = _compute_enforced_budget(
            {"max_tokens": 2048, "max_duration_ms": 15000}, 60
        )
        assert result["max_tokens"] == 2048
        assert result["max_duration_ms"] == 15000
        assert result["source"] == "intent_exact"

    def test_effective_timeout_min_rule(self):
        """effective_timeout = min(runtime_ms, client_ms)."""
        # runtime = 30s = 30000ms, client = 45000ms -> clamped to 30000
        result = _compute_enforced_budget({"max_duration_ms": 45000}, 30)
        assert result["max_duration_ms"] == 30000

    def test_invalid_max_tokens_ignored(self):
        """Non-positive max_tokens ignored."""
        result = _compute_enforced_budget({"max_tokens": 0, "max_duration_ms": 10000}, 60)
        assert "max_tokens" not in result
        assert result["max_duration_ms"] == 10000

    def test_budget_integer_only(self):
        """Budget values are expected to be integers (validated at wire_contract)."""
        # If a float leaks through, it should still work at the math level
        result = _compute_enforced_budget({"max_duration_ms": 10000}, 60)
        assert isinstance(result["max_duration_ms"], int)
