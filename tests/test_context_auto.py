import pytest
from dataclasses import replace

from dbl_gateway.context_builder import build_context_with_refs, RefResolutionError
from dbl_gateway.config import ContextConfig

@pytest.fixture
def mock_config(tmp_path):
    # Minimal config
    return ContextConfig(
        max_refs=50,
        empty_refs_policy="DENY",
        expand_last_n=10,  # Required by constructor
        canonical_sort="event_index_asc",
        enforce_scope_bound=True,
        allow_execution_refs_for_prompt=True,
        config_digest="sha256:mock",
        schema_version="1",
        normalization_rules=("SORT",), # Tuple
        expand_thread_history_enabled=False,
        _raw={} # Required
    )

def test_auto_context_expansion_first_plus_last_n(mock_config):
    # Simulate a conversation
    events = []
    
    # 0: Turn 1 (First)
    events.append({
        "turn_id": "t1", "correlation_id": "c1", "kind": "INTENT", "thread_id": "th1", "index": 0,
        "payload": {"message": "User 1"}
    })
    events.append({
        "turn_id": "t1", "correlation_id": "c1", "kind": "EXECUTION", "thread_id": "th1", "index": 1,
        "payload": {"output_text": "AI 1"}
    })
    
    # 1: Turn 2 (Middle - should be skipped if we ask for last 1)
    events.append({
        "turn_id": "t2", "correlation_id": "c2", "kind": "INTENT", "thread_id": "th1", "index": 2,
        "payload": {"message": "User 2"}
    })
    events.append({
        "turn_id": "t2", "correlation_id": "c2", "kind": "EXECUTION", "thread_id": "th1", "index": 3,
        "payload": {"output_text": "AI 2"}
    })

    # 2: Turn 3 (Last)
    events.append({
        "turn_id": "t3", "correlation_id": "c3", "kind": "INTENT", "thread_id": "th1", "index": 4,
        "payload": {"message": "User 3"}
    })
    events.append({
        "turn_id": "t3", "correlation_id": "c3", "kind": "EXECUTION", "thread_id": "th1", "index": 5,
        "payload": {"output_text": "AI 3"}
    })
    
    # Run build_context_with_refs with context_mode='first_plus_last_n' and n=1
    payload = {
        "context_mode": "first_plus_last_n",
        "context_n": 1,
        "thread_id": "th1",
        "turn_id": "t4",
        "message": "User 4"
    }
    
    cfg = replace(mock_config, expand_thread_history_enabled=True)
    artifacts = build_context_with_refs(
        payload=payload,
        intent_type="chat.message",
        thread_events=events,
        config=cfg
    )
    
    resolved = artifacts.context_spec["retrieval"]["resolved_refs"]
    
    # Expect: Turn 1 (First) + Turn 3 (Last 1)
    # Turn 2 is skipped.
    assert len(resolved) == 4
    
    # Check contents
    contents = [r["content"] for r in resolved]
    assert "User 1" in contents
    assert "AI 1" in contents
    assert "User 3" in contents
    assert "AI 3" in contents
    assert "User 2" not in contents
    
def test_empty_refs_allowed_for_chat_message_when_auto_disabled(mock_config):
    
    events = [{
        "turn_id": "t1", "correlation_id": "c1", "kind": "INTENT", "thread_id": "th1", "index": 0,
        "payload": {"message": "U1"}
    }]
    
    payload = {
        "thread_id": "th1",
        "turn_id": "t2",
        "message": "U2"
        # No context params
    }
    
    artifacts = build_context_with_refs(
        payload=payload,
        intent_type="chat.message",
        thread_events=events,
        config=mock_config
    )
    assert artifacts.context_spec["retrieval"]["declared_refs"] == []


def test_empty_refs_denied_for_non_chat_when_auto_disabled(mock_config):
    events = [{
        "turn_id": "t1", "correlation_id": "c1", "kind": "INTENT", "thread_id": "th1", "index": 0,
        "payload": {"message": "U1"}
    }]

    payload = {
        "thread_id": "th1",
        "turn_id": "t2",
        "message": "U2"
    }

    with pytest.raises(RefResolutionError) as exc:
        build_context_with_refs(
            payload=payload,
            intent_type="tool.invoke",
            thread_events=events,
            config=mock_config
        )
    assert exc.value.code == "EMPTY_REFS_DENIED"
