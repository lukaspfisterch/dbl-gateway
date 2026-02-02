"""Tests for declared_refs resolution (Step 2)."""
import json
import pytest
from pathlib import Path
from typing import Any

from dbl_gateway.config import load_context_config, ContextConfig
from dbl_gateway.context_builder import build_context_with_refs, ContextArtifacts
from dbl_gateway.ref_resolver import (
    RefNotFoundError,
    CrossThreadRefError,
    MaxRefsExceededError,
    resolve_declared_refs,
)
from dbl_gateway.models import EventRecord


@pytest.fixture
def sample_config(tmp_path: Path) -> ContextConfig:
    """Create a sample config for testing."""
    config = {
        "schema_version": "1",
        "context": {
            "max_refs": 5,
            "empty_refs_policy": "DENY",
            "expand_last_n": 10,
            "allow_execution_refs_for_prompt": True,
            "canonical_sort": "event_index_asc",
            "enforce_scope_bound": True,
        },
        "normalization": {
            "rules": ["FILTER_INTENT_ONLY", "SCOPE_BOUND", "SORT_CANONICAL"],
        },
    }
    path = tmp_path / "context.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return load_context_config(path)


def make_event(
    index: int,
    kind: str,
    thread_id: str,
    turn_id: str,
    correlation_id: str,
    digest: str = "sha256:test",
) -> EventRecord:
    """Create a minimal EventRecord for testing."""
    return {
        "index": index,
        "kind": kind,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "parent_turn_id": None,
        "lane": "user",
        "actor": "test",
        "intent_type": "chat.message",
        "stream_id": "default",
        "correlation_id": correlation_id,
        "payload": {"message": "test"},
        "digest": digest,
        "canon_len": 100,
        "is_authoritative": kind == "DECISION",
    }


class TestRefResolver:
    """Tests for the resolve_declared_refs function."""

    def test_valid_ref_resolved(self, sample_config: ContextConfig) -> None:
        """Valid declared_refs are resolved with event metadata."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-1", "corr-1", "sha256:abc"),
        ]
        declared_refs = [{"ref_type": "event", "ref_id": "corr-1"}]
        
        result = resolve_declared_refs(
            declared_refs=declared_refs,
            thread_id="thread-1",
            thread_events=events,
            config=sample_config,
        )
        
        assert len(result.resolved_refs) == 1
        assert result.resolved_refs[0]["ref_id"] == "corr-1"
        assert result.resolved_refs[0]["event_index"] == 0
        assert result.resolved_refs[0]["event_digest"] == "sha256:abc"
        assert result.resolved_refs[0]["admitted_for"] == "governance"

    def test_ref_not_found_raises(self, sample_config: ContextConfig) -> None:
        """Missing ref raises RefNotFoundError."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-1", "corr-1"),
        ]
        declared_refs = [{"ref_type": "event", "ref_id": "nonexistent"}]
        
        with pytest.raises(RefNotFoundError) as exc:
            resolve_declared_refs(
                declared_refs=declared_refs,
                thread_id="thread-1",
                thread_events=events,
                config=sample_config,
            )
        
        assert exc.value.code == "REF_NOT_FOUND"
        assert exc.value.ref_id == "nonexistent"

    def test_cross_thread_ref_rejected(self, sample_config: ContextConfig) -> None:
        """Refs from different thread raise CrossThreadRefError."""
        events = [
            make_event(0, "INTENT", "thread-A", "turn-1", "corr-1"),  # Different thread!
        ]
        declared_refs = [{"ref_type": "event", "ref_id": "corr-1"}]
        
        with pytest.raises(CrossThreadRefError) as exc:
            resolve_declared_refs(
                declared_refs=declared_refs,
                thread_id="thread-B",  # Requesting from thread-B
                thread_events=events,
                config=sample_config,
            )
        
        assert exc.value.code == "CROSS_THREAD_REF"
        assert exc.value.expected_thread == "thread-B"
        assert exc.value.actual_thread == "thread-A"

    def test_max_refs_exceeded_raises(self, sample_config: ContextConfig) -> None:
        """Too many refs raise MaxRefsExceededError."""
        events = [make_event(i, "INTENT", "t", f"turn-{i}", f"corr-{i}") for i in range(10)]
        declared_refs = [{"ref_type": "event", "ref_id": f"corr-{i}"} for i in range(10)]
        
        with pytest.raises(MaxRefsExceededError) as exc:
            resolve_declared_refs(
                declared_refs=declared_refs,
                thread_id="t",
                thread_events=events,
                config=sample_config,  # max_refs=5
            )
        
        assert exc.value.code == "MAX_REFS_EXCEEDED"
        assert exc.value.count == 10
        assert exc.value.max_refs == 5

    def test_canonical_order_deterministic(self, sample_config: ContextConfig) -> None:
        """Refs are sorted by event_index regardless of input order."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-1", "corr-1"),
            make_event(1, "INTENT", "thread-1", "turn-2", "corr-2"),
        ]
        # Reversed order in request
        declared_refs_rev = [
            {"ref_type": "event", "ref_id": "corr-2"},
            {"ref_type": "event", "ref_id": "corr-1"},
        ]
        declared_refs_ord = [
            {"ref_type": "event", "ref_id": "corr-1"},
            {"ref_type": "event", "ref_id": "corr-2"},
        ]
        
        result_rev = resolve_declared_refs(
            declared_refs=declared_refs_rev,
            thread_id="thread-1",
            thread_events=events,
            config=sample_config,
        )
        result_ord = resolve_declared_refs(
            declared_refs=declared_refs_ord,
            thread_id="thread-1",
            thread_events=events,
            config=sample_config,
        )
        
        # Both should produce same canonical order
        assert result_rev.resolved_refs == result_ord.resolved_refs
        assert result_rev.resolved_refs[0]["event_index"] == 0
        assert result_rev.resolved_refs[1]["event_index"] == 1

    def test_execution_ref_admitted_for_execution_only(self, sample_config: ContextConfig) -> None:
        """EXECUTION refs are classified as execution_only."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-1", "corr-1"),
            make_event(1, "EXECUTION", "thread-1", "turn-1", "exec-1"),
        ]
        declared_refs = [
            {"ref_type": "event", "ref_id": "corr-1"},
            {"ref_type": "event", "ref_id": "exec-1"},
        ]
        
        result = resolve_declared_refs(
            declared_refs=declared_refs,
            thread_id="thread-1",
            thread_events=events,
            config=sample_config,
        )
        
        assert len(result.resolved_refs) == 2
        assert result.resolved_refs[0]["admitted_for"] == "governance"
        assert result.resolved_refs[1]["admitted_for"] == "execution_only"
        
        # Only INTENT in normative_refs
        assert len(result.normative_refs) == 1
        assert result.normative_refs[0]["ref_id"] == "corr-1"

    def test_execution_excluded_from_normative_digests(self, sample_config: ContextConfig) -> None:
        """EXECUTION ref digests are not in normative_input_digests."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-1", "corr-1", "sha256:intent1"),
            make_event(1, "EXECUTION", "thread-1", "turn-1", "exec-1", "sha256:exec1"),
        ]
        declared_refs = [
            {"ref_type": "event", "ref_id": "corr-1"},
            {"ref_type": "event", "ref_id": "exec-1"},
        ]
        
        result = resolve_declared_refs(
            declared_refs=declared_refs,
            thread_id="thread-1",
            thread_events=events,
            config=sample_config,
        )
        
        # Only INTENT digest in normative
        assert result.normative_input_digests == ("sha256:intent1",)


class TestBuildContextWithRefs:
    """Tests for build_context_with_refs function."""

    def test_resolved_refs_materialized(self, sample_config: ContextConfig) -> None:
        """Resolved refs are materialized in context_spec."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-0", "corr-0", "sha256:prev"),
        ]
        payload = {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "message": "Hello",
            "declared_refs": [{"ref_type": "event", "ref_id": "corr-0"}],
        }
        
        artifacts = build_context_with_refs(
            payload,
            intent_type="chat.message",
            thread_events=events,
            config=sample_config,
        )
        
        assert len(artifacts.context_spec["retrieval"]["resolved_refs"]) == 1
        assert artifacts.context_spec["retrieval"]["resolved_refs"][0]["ref_id"] == "corr-0"
        assert artifacts.context_spec["retrieval"]["resolved_refs"][0]["event_digest"] == "sha256:prev"

    def test_context_digest_includes_resolved_refs(self, sample_config: ContextConfig) -> None:
        """context_digest changes when resolved_refs change (Variante A)."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-0", "corr-0", "sha256:a"),
            make_event(1, "INTENT", "thread-1", "turn-1", "corr-1", "sha256:b"),
        ]
        payload_base = {
            "thread_id": "thread-1",
            "turn_id": "turn-2",
            "message": "Hello",
        }
        
        # No refs
        payload_no_refs = {**payload_base, "declared_refs": []}
        # One ref
        payload_one_ref = {**payload_base, "declared_refs": [{"ref_type": "event", "ref_id": "corr-0"}]}
        # Two refs
        payload_two_refs = {**payload_base, "declared_refs": [
            {"ref_type": "event", "ref_id": "corr-0"},
            {"ref_type": "event", "ref_id": "corr-1"},
        ]}
        
        a0 = build_context_with_refs(payload_no_refs, intent_type="chat.message", thread_events=events, config=sample_config)
        a1 = build_context_with_refs(payload_one_ref, intent_type="chat.message", thread_events=events, config=sample_config)
        a2 = build_context_with_refs(payload_two_refs, intent_type="chat.message", thread_events=events, config=sample_config)
        
        # All should have different context_digests
        assert a0.context_digest != a1.context_digest
        assert a1.context_digest != a2.context_digest
        assert a0.context_digest != a2.context_digest

    def test_empty_refs_produces_empty_resolved(self, sample_config: ContextConfig) -> None:
        """Empty declared_refs produces empty resolved_refs."""
        payload = {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "message": "Hello",
            "declared_refs": [],
        }
        
        artifacts = build_context_with_refs(
            payload,
            intent_type="chat.message",
            thread_events=[],
            config=sample_config,
        )
        
        assert artifacts.context_spec["retrieval"]["resolved_refs"] == []
        assert artifacts.assembled_context["normative_input_digests"] == []

    def test_ref_not_found_propagates(self, sample_config: ContextConfig) -> None:
        """RefNotFoundError propagates from resolver."""
        payload = {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "message": "Hello",
            "declared_refs": [{"ref_type": "event", "ref_id": "nonexistent"}],
        }
        
        with pytest.raises(RefNotFoundError):
            build_context_with_refs(
                payload,
                intent_type="chat.message",
                thread_events=[],
                config=sample_config,
            )

    def test_assembled_from_matches_resolved(self, sample_config: ContextConfig) -> None:
        """assembled_context.assembled_from matches resolved_refs."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-0", "corr-0"),
        ]
        payload = {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "message": "Hello",
            "declared_refs": [{"ref_type": "event", "ref_id": "corr-0"}],
        }
        
        artifacts = build_context_with_refs(
            payload,
            intent_type="chat.message",
            thread_events=events,
            config=sample_config,
        )
        
        assert artifacts.assembled_context["assembled_from"] == artifacts.context_spec["retrieval"]["resolved_refs"]

    def test_lookup_by_turn_id(self, sample_config: ContextConfig) -> None:
        """Refs can be looked up by turn_id as well as correlation_id."""
        events = [
            make_event(0, "INTENT", "thread-1", "turn-abc", "corr-xyz"),
        ]
        payload = {
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "message": "Hello",
            "declared_refs": [{"ref_type": "event", "ref_id": "turn-abc"}],  # Using turn_id
        }
        
        artifacts = build_context_with_refs(
            payload,
            intent_type="chat.message",
            thread_events=events,
            config=sample_config,
        )
        
        assert len(artifacts.context_spec["retrieval"]["resolved_refs"]) == 1
        assert artifacts.context_spec["retrieval"]["resolved_refs"][0]["ref_id"] == "turn-abc"
