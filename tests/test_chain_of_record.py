"""Tests for Axis 4: Chain-of-Record / Observability.

Covers:
- policy_config_digest in normative DECISION payload
- intent_index (decision lineage) in DECISION payload
- compute_release_digest determinism
- release_digest in EXECUTION payload
- I-STREAM-1: append-only event stream
- I-ORDER-1: decision precedes execution
- I-GOV-INPUT-1: observational non-interference
"""
import json
import sqlite3
import tempfile
import pytest
from pathlib import Path
from typing import Any

from dbl_gateway.contracts import canonical_json_bytes
from dbl_gateway.digest import v_digest
from dbl_gateway.decision_builder import build_normative_decision
from dbl_gateway.digest import compute_release_digest
from dbl_gateway.ports.policy_port import DecisionResult
from dbl_core.normalize.trace import sanitize_trace
from dbl_core.events.trace_digest import trace_digest as compute_trace_digest
from dbl_gateway.store.sqlite import SQLiteStore, OrderViolationError


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


# ---------------------------------------------------------------------------
# Substrate Invariants (A1, A3, A5)
# ---------------------------------------------------------------------------

def _make_store() -> SQLiteStore:
    """Create an ephemeral SQLiteStore for testing."""
    tmp = tempfile.mkdtemp()
    return SQLiteStore(Path(tmp) / "test.db")


def _append_event(store: SQLiteStore, kind: str, **overrides: Any) -> Any:
    payload: dict[str, Any] = {"test": True}
    if kind == "EXECUTION":
        raw_trace = {"trace_id": "t1", "lane": "default", "intent_type": "test.intent"}
        trace = sanitize_trace(raw_trace)
        payload = {"trace_digest": compute_trace_digest(trace), "trace": trace}
    defaults = dict(
        kind=kind,
        thread_id="t1",
        turn_id="turn1",
        parent_turn_id=None,
        lane="default",
        actor="test",
        intent_type="test.intent",
        stream_id="s1",
        correlation_id="c1",
        payload=payload,
    )
    defaults.update(overrides)
    return store.append(**defaults)


class TestStreamAppendOnly:
    """I-STREAM-1: Events are immutable once appended (A1)."""

    def test_update_blocked(self) -> None:
        store = _make_store()
        _append_event(store, "INTENT")
        with pytest.raises(sqlite3.IntegrityError, match="I-STREAM-1"):
            store._conn.execute("UPDATE events SET kind = 'DECISION' WHERE idx = 1")

    def test_delete_blocked(self) -> None:
        store = _make_store()
        _append_event(store, "INTENT")
        with pytest.raises(sqlite3.IntegrityError, match="I-STREAM-1"):
            store._conn.execute("DELETE FROM events WHERE idx = 1")

    def test_append_still_works(self) -> None:
        store = _make_store()
        e = _append_event(store, "INTENT")
        assert e["kind"] == "INTENT"
        assert isinstance(e["index"], int)

    def test_prev_event_digest_links_chain(self) -> None:
        store = _make_store()
        first = _append_event(store, "INTENT", correlation_id="c1", turn_id="turn1")
        second = _append_event(store, "DECISION", correlation_id="c1", turn_id="turn1", payload={
            "policy": {"policy_id": "p1", "policy_version": "1", "policy_config_digest": None},
            "assembly_digest": None,
            "context_digest": None,
            "result": "ALLOW",
            "reasons": [],
            "transforms": [],
            "permitted_tools": None,
            "enforced_budget": None,
            "_obs": {"trace_id": "t1"},
        })
        assert first["prev_event_digest"] == v_digest([])
        assert second["prev_event_digest"] == first["digest"]
        assert store.verify_event_chain() == []

    def test_verify_event_chain_detects_corruption(self) -> None:
        store = _make_store()
        _append_event(store, "INTENT", correlation_id="c1", turn_id="turn1")
        _append_event(store, "DECISION", correlation_id="c1", turn_id="turn1", payload={
            "policy": {"policy_id": "p1", "policy_version": "1", "policy_config_digest": None},
            "assembly_digest": None,
            "context_digest": None,
            "result": "ALLOW",
            "reasons": [],
            "transforms": [],
            "permitted_tools": None,
            "enforced_budget": None,
            "_obs": {"trace_id": "t1"},
        })
        with store._conn:
            store._conn.execute("DROP TRIGGER IF EXISTS events_no_update")
            store._conn.execute(
                "UPDATE events SET prev_event_digest = ? WHERE idx = 2",
                ("sha256:broken",),
            )
            store._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'I-STREAM-1: events are immutable once appended');
                END
                """
            )
        issues = store.verify_event_chain()
        assert len(issues) == 1
        assert issues[0]["index"] == 1
        assert issues[0]["actual_prev_event_digest"] == "sha256:broken"


class TestDecisionPrecedesExecution:
    """I-ORDER-1: EXECUTION requires a preceding DECISION in the same turn (A5)."""

    def test_execution_without_decision_raises(self) -> None:
        store = _make_store()
        _append_event(store, "INTENT")
        with pytest.raises(OrderViolationError, match="I-ORDER-1"):
            _append_event(store, "EXECUTION")

    def test_execution_after_decision_succeeds(self) -> None:
        store = _make_store()
        _append_event(store, "INTENT")
        decision_payload = {
            "policy": {"policy_id": "p1", "policy_version": "1", "policy_config_digest": None},
            "assembly_digest": None,
            "context_digest": None,
            "result": "ALLOW",
            "reasons": [],
            "transforms": [],
            "permitted_tools": None,
            "enforced_budget": None,
            "_obs": {"trace_id": "t1"},
        }
        _append_event(store, "DECISION", payload=decision_payload)
        e = _append_event(store, "EXECUTION")
        assert e["kind"] == "EXECUTION"

    def test_proof_does_not_require_decision(self) -> None:
        """PROOF events are not subject to I-ORDER-1."""
        store = _make_store()
        _append_event(store, "INTENT")
        e = _append_event(store, "PROOF")
        assert e["kind"] == "PROOF"


class TestGovernanceInputIsolation:
    """I-GOV-INPUT-1: Governance input contains only I_L keys (A3/A4)."""

    def test_clean_input_passes(self) -> None:
        from dbl_gateway.app import _assert_governance_input
        authoritative = {
            "stream_id": "s1",
            "lane": "default",
            "actor": "agent",
            "intent_type": "test",
            "correlation_id": "c1",
            "payload": {"user_input": "hello"},
        }
        _assert_governance_input(authoritative)  # should not raise

    def test_observational_key_rejected(self) -> None:
        from dbl_gateway.app import _assert_governance_input, GovernanceInputViolation
        contaminated = {
            "stream_id": "s1",
            "lane": "default",
            "actor": "agent",
            "intent_type": "test",
            "correlation_id": "c1",
            "payload": {},
            "provider_response": {"output": "leaked"},  # O_obs
        }
        with pytest.raises(GovernanceInputViolation, match="I-GOV-INPUT-1"):
            _assert_governance_input(contaminated)

    def test_execution_result_rejected(self) -> None:
        from dbl_gateway.app import _assert_governance_input, GovernanceInputViolation
        contaminated = {
            "stream_id": "s1",
            "lane": "default",
            "actor": "agent",
            "intent_type": "test",
            "correlation_id": "c1",
            "payload": {},
            "execution_result": {"text": "leaked"},
            "trace": {"id": "t1"},
        }
        with pytest.raises(GovernanceInputViolation, match="I-GOV-INPUT-1"):
            _assert_governance_input(contaminated)
