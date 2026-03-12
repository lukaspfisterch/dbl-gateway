"""Tests for wire_contract v3: tool gating and budget fields."""
import json
from pathlib import Path

import pytest
from dbl_gateway.wire_contract import (
    parse_intent_envelope,
    INTERFACE_VERSION,
    _parse_declared_tools,
    _parse_tool_scope,
    _parse_budget,
    _TOOL_NAME_RE,
    _MAX_DECLARED_TOOLS,
)


def _envelope(*, outer_overrides: dict | None = None, version: int = 3) -> dict:
    """Build a minimal valid IntentEnvelope."""
    payload = {
        "stream_id": "default",
        "lane": "user",
        "actor": "test@example.com",
        "intent_type": "chat.message",
        "thread_id": "t-1",
        "turn_id": "u-1",
        "payload": {"message": "hello", "thread_id": "t-1", "turn_id": "u-1"},
    }
    if outer_overrides:
        payload.update(outer_overrides)
    return {"interface_version": version, "correlation_id": "c-1", "payload": payload}


# --- Interface version ---

def test_interface_version_is_3():
    assert INTERFACE_VERSION == 3


def test_reject_v2_envelope():
    with pytest.raises(ValueError, match="unsupported interface_version"):
        parse_intent_envelope(_envelope(version=2))


# --- _parse_declared_tools ---

def test_parse_declared_tools_valid():
    assert _parse_declared_tools(["web.search", "code.execute"]) == ["web.search", "code.execute"]


def test_parse_declared_tools_none():
    assert _parse_declared_tools(None) is None


def test_parse_declared_tools_empty_list():
    """Empty list is valid (no tools declared)."""
    result = _parse_declared_tools([])
    assert result == []


def test_parse_declared_tools_not_list():
    """Non-list raises ValueError."""
    with pytest.raises(ValueError, match="must be a list"):
        _parse_declared_tools("web.search")


def test_parse_declared_tools_invalid_name():
    """Names not matching regex raise ValueError."""
    with pytest.raises(ValueError, match="does not match pattern"):
        _parse_declared_tools(["valid_tool", "INVALID"])


def test_parse_declared_tools_max_exceeded():
    """More than MAX tools raises ValueError."""
    tools = [f"tool_{i}" for i in range(_MAX_DECLARED_TOOLS + 1)]
    with pytest.raises(ValueError, match="exceeds maximum"):
        _parse_declared_tools(tools)


def test_tool_name_regex():
    assert _TOOL_NAME_RE.match("web.search")
    assert _TOOL_NAME_RE.match("a")
    assert _TOOL_NAME_RE.match("code_execute.v2")
    assert not _TOOL_NAME_RE.match("")
    assert not _TOOL_NAME_RE.match("9starts_with_digit")
    assert not _TOOL_NAME_RE.match("UPPERCASE")
    assert not _TOOL_NAME_RE.match("has-dash")


# --- _parse_tool_scope ---

def test_parse_tool_scope_strict():
    assert _parse_tool_scope("strict") == "strict"


def test_parse_tool_scope_advisory():
    assert _parse_tool_scope("advisory") == "advisory"


def test_parse_tool_scope_invalid():
    with pytest.raises(ValueError, match="must be 'strict' or 'advisory'"):
        _parse_tool_scope("relaxed")


def test_parse_tool_scope_none():
    assert _parse_tool_scope(None) is None


def test_parse_tool_scope_not_string():
    with pytest.raises(ValueError, match="must be a string"):
        _parse_tool_scope(42)


# --- _parse_budget ---

def test_parse_budget_valid_full():
    result = _parse_budget({"max_tokens": 4096, "max_duration_ms": 30000})
    assert result == {"max_tokens": 4096, "max_duration_ms": 30000}


def test_parse_budget_tokens_only():
    result = _parse_budget({"max_tokens": 1000})
    assert result == {"max_tokens": 1000}


def test_parse_budget_duration_only():
    result = _parse_budget({"max_duration_ms": 10000})
    assert result == {"max_duration_ms": 10000}


def test_parse_budget_none():
    assert _parse_budget(None) is None


def test_parse_budget_empty_dict():
    with pytest.raises(ValueError, match="must contain at least one"):
        _parse_budget({})


def test_parse_budget_not_dict():
    with pytest.raises(ValueError, match="must be an object"):
        _parse_budget("budget")


def test_parse_budget_float_rejected():
    """Float values must be rejected (integer-only)."""
    with pytest.raises(ValueError, match="must be an integer, not float"):
        _parse_budget({"max_tokens": 4096.5})


def test_parse_budget_tokens_out_of_range():
    """max_tokens outside 1-1000000 rejected."""
    with pytest.raises(ValueError, match="must be between 1 and 1000000"):
        _parse_budget({"max_tokens": 0})
    with pytest.raises(ValueError, match="must be between 1 and 1000000"):
        _parse_budget({"max_tokens": 1000001})


def test_parse_budget_duration_out_of_range():
    """max_duration_ms outside 1000-300000 rejected."""
    with pytest.raises(ValueError, match="must be between 1000 and 300000"):
        _parse_budget({"max_duration_ms": 999})
    with pytest.raises(ValueError, match="must be between 1000 and 300000"):
        _parse_budget({"max_duration_ms": 300001})


# --- parse_intent_envelope integration ---

def test_envelope_with_tools_and_budget():
    env = _envelope(outer_overrides={
        "declared_tools": ["web.search"],
        "tool_scope": "strict",
        "budget": {"max_tokens": 2048},
    })
    result = parse_intent_envelope(env)
    assert result["payload"]["declared_tools"] == ["web.search"]
    assert result["payload"]["tool_scope"] == "strict"
    assert result["payload"]["budget"] == {"max_tokens": 2048}


def test_envelope_without_new_fields():
    env = _envelope()
    result = parse_intent_envelope(env)
    assert result["payload"]["declared_tools"] is None
    assert result["payload"]["tool_scope"] is None
    assert result["payload"]["budget"] is None


def test_capabilities_doc_matches_interface_version():
    docs_path = Path(__file__).resolve().parents[1] / "docs" / f"capabilities.gateway.v{INTERFACE_VERSION}.json"
    data = json.loads(docs_path.read_text(encoding="utf-8"))

    assert data["interface_version"] == INTERFACE_VERSION
    assert data["schema_version"] == "gateway.capabilities.v1"
