import pytest
import json
from dbl_gateway.context_builder import build_context_with_refs, ContextArtifacts
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
    
    artifacts = build_context_with_refs(
        payload=payload,
        intent_type="chat.message",
        thread_events=events,
        config=mock_config
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
    
    # Check transform record
    norms = artifacts.context_spec["retrieval"]["normalization"]
    transforms = norms.get("transformations", [])
    auto_ops = [n for n in transforms if n.get("op") == "AUTO_DECLARE_REFS"]
    assert len(auto_ops) == 1
    assert auto_ops[0]["params"]["count"] == 4

def test_auto_context_defaults(mock_config):
    # If context_mode not provided, but no declared_refs, default to nothing? 
    # Or strict? DBL usually strict.
    # But user said "Default... mode = payload.get(..., 'first_plus_last_n')"
    # This implies defaulting to ON.
    
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
    
    # Should default to first_plus_last_n=10
    resolved = artifacts.context_spec["retrieval"]["resolved_refs"]
    assert len(resolved) > 0
    assert resolved[0]["content"] == "U1"
    
    # Check normalization indicates auto
    norms = artifacts.context_spec["retrieval"]["normalization"]
    transforms = norms.get("transformations", [])
    ops = [n.get("op") for n in transforms]
    assert "AUTO_DECLARE_REFS" in ops
