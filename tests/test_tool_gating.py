"""Tests for tool gating computation and enforcement."""
from pathlib import Path

import pytest
from dbl_gateway.app import _compute_permitted_tools
from dbl_gateway.config import load_boundary_config
from dbl_gateway.ports.policy_port import DecisionResult


def _allow(**kwargs) -> DecisionResult:
    return DecisionResult(decision="ALLOW", reason_codes=[], **kwargs)


def _deny(**kwargs) -> DecisionResult:
    return DecisionResult(decision="DENY", reason_codes=["test"], **kwargs)


def _boundary(name: str):
    return load_boundary_config(Path(__file__).resolve().parents[1] / "config" / name)


# --- _compute_permitted_tools ---

class TestComputePermittedTools:
    def test_no_tools_declared(self):
        """No declared_tools or tool_scope returns all None."""
        result = _compute_permitted_tools(None, None, _allow())
        assert result == (None, None, None, None)

    def test_mixed_exec_like_and_read_tools_apply_no_mix_rule(self):
        """Exec-like tools are denied when mixed with other families."""
        tools = ["web.search", "code.execute"]
        permitted, scope, denied, reason = _compute_permitted_tools(
            tools,
            "strict",
            _allow(),
            boundary_config=_boundary("boundary.demo.json"),
        )
        assert permitted == ["web.search"]
        assert scope == "strict"
        assert denied == ["code.execute"]
        assert reason == "tool.no_mix.exec_like"

    def test_default_scope_strict(self):
        """tool_scope defaults to 'strict' when tools are declared."""
        tools = ["web.search"]
        _, scope, _, _ = _compute_permitted_tools(tools, None, _allow())
        assert scope == "strict"

    def test_advisory_scope(self):
        """Advisory scope passes through."""
        tools = ["web.search"]
        _, scope, _, _ = _compute_permitted_tools(tools, "advisory", _allow())
        assert scope == "advisory"

    def test_deny_returns_none(self):
        """DENY decision returns all None regardless of tools."""
        tools = ["web.search"]
        result = _compute_permitted_tools(tools, "strict", _deny())
        assert result == (None, None, None, None)

    def test_empty_tools_with_scope(self):
        """Empty declared_tools with scope set."""
        permitted, scope, denied, reason = _compute_permitted_tools([], "strict", _allow())
        assert permitted == []
        assert scope == "strict"

    def test_only_scope_no_tools(self):
        """tool_scope without declared_tools still triggers computation."""
        permitted, scope, denied, reason = _compute_permitted_tools(None, "advisory", _allow())
        assert permitted == []
        assert scope == "advisory"

    def test_exec_like_only_is_allowed(self):
        """Pure exec-like declarations remain allowed only in permissive demo boundary."""
        tools = ["code.execute", "shell.execute"]
        permitted, scope, denied, reason = _compute_permitted_tools(
            tools,
            "strict",
            _allow(),
            boundary_config=_boundary("boundary.demo.json"),
        )
        assert permitted == ["code.execute", "shell.execute"]
        assert denied == []
        assert reason is None

    def test_operator_boundary_denies_exec_like_family(self):
        """Operator boundary excludes exec-like families entirely."""
        tools = ["code.execute"]
        permitted, scope, denied, reason = _compute_permitted_tools(
            tools,
            "strict",
            _allow(),
            boundary_config=_boundary("boundary.operator.json"),
        )
        assert permitted == []
        assert scope == "strict"
        assert denied == ["code.execute"]
        assert reason == "tool.family_not_allowed"
