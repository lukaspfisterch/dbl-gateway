from __future__ import annotations

import sys
from pathlib import Path

import pytest

from dbl_gateway.adapters.policy_adapter_dbl_policy import DblPolicyAdapter
from dbl_gateway.app import _decision_payload
from dbl_gateway.context_builder import build_context
from dbl_gateway.replay import DecisionReplayError, replay_decision_for_turn
from dbl_gateway.store.sqlite import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def _policy_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_POLICY_MODULE", "policy_stub")
    monkeypatch.setenv("DBL_GATEWAY_POLICY_OBJECT", "policy")


def _authoritative_payload(message: str) -> dict[str, object]:
    return {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "correlation_id": "c-1",
        "payload": {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "parent_turn_id": None,
            "message": message,
        },
    }


def test_decision_replay_matches_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "trail.sqlite"
    monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
    authoritative = _authoritative_payload("hello")
    context_artifacts = build_context(authoritative["payload"], intent_type=str(authoritative["intent_type"]))
    adapter = DblPolicyAdapter()
    decision = adapter.decide(authoritative)
    decision_event_payload = _decision_payload(
        decision,
        "trace-1",
        requested_model_id=None,
        resolved_model_id=None,
        provider=None,
        assembly_digest=context_artifacts.context_digest,
        context_digest=context_artifacts.context_digest,
        boundary={
            "context_digest": context_artifacts.context_digest,
            "context_spec": context_artifacts.context_spec,
            "assembled_context": context_artifacts.assembled_context,
            "admitted_model_messages": context_artifacts.assembled_context.get("model_messages", []),
            "meta": context_artifacts.boundary_meta,
        },
        transforms=context_artifacts.transforms,
        context_spec=context_artifacts.context_spec,
        assembled_context=context_artifacts.assembled_context,
    )

    store = SQLiteStore(db_path)
    store.append(
        kind="INTENT",
        thread_id="thread-1",
        turn_id="turn-1",
        parent_turn_id=None,
        lane="user_chat",
        actor="user",
        intent_type="chat.message",
        stream_id="default",
        correlation_id="c-1",
        payload=authoritative["payload"],
    )
    decision_event = store.append(
        kind="DECISION",
        thread_id="thread-1",
        turn_id="turn-1",
        parent_turn_id=None,
        lane="user_chat",
        actor="policy",
        intent_type="chat.message",
        stream_id="default",
        correlation_id="c-1",
        payload=decision_event_payload,
    )

    replay = replay_decision_for_turn(store, thread_id="thread-1", turn_id="turn-1")
    assert replay.recomputed_decision_digest == replay.stored_decision_digest
    assert replay.stored_decision_digest == decision_event["digest"]
    store.close()


def test_replay_fails_when_context_artifacts_missing(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "trail.sqlite")
    intent_payload = {"thread_id": "t-1", "turn_id": "turn-1", "parent_turn_id": None, "message": "hi"}
    store.append(
        kind="INTENT",
        thread_id="t-1",
        turn_id="turn-1",
        parent_turn_id=None,
        lane="default",
        actor="user",
        intent_type="chat.message",
        stream_id="default",
        correlation_id="c-missing",
        payload=intent_payload,
    )
    store.append(
        kind="DECISION",
        thread_id="t-1",
        turn_id="turn-1",
        parent_turn_id=None,
        lane="default",
        actor="policy",
        intent_type="chat.message",
        stream_id="default",
        correlation_id="c-missing",
        payload={
            "decision": "ALLOW",
            "result": "ALLOW",
            "reason_codes": [],
            "reasons": [],
            "transforms": [],
            "policy": {"policy_id": "p.test", "policy_version": "1"},
            "policy_id": "p.test",
            "policy_version": "1",
            "assembly_digest": "sha256:" + ("1" * 64),
            "context_digest": "sha256:" + ("1" * 64),
        },
    )
    with pytest.raises(DecisionReplayError) as excinfo:
        replay_decision_for_turn(store, thread_id="t-1", turn_id="turn-1")
    assert excinfo.value.reason == "context.missing"
    store.close()
