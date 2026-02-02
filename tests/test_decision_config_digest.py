"""Tests for DECISION payload context_config_digest materialization (Step 3)."""
import json
import pytest
from pathlib import Path
from typing import Any

from dbl_gateway.config import load_context_config, ContextConfig, reset_config_cache
from dbl_gateway.context_builder import build_context, ContextArtifacts
from dbl_gateway.decision_builder import build_normative_decision
from dbl_gateway.ports.policy_port import DecisionResult


@pytest.fixture
def sample_config(tmp_path: Path) -> ContextConfig:
    """Create a sample config for testing."""
    config = {
        "schema_version": "1",
        "context": {
            "max_refs": 50,
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
    reset_config_cache()
    return load_context_config(path)


@pytest.fixture
def valid_payload() -> dict[str, Any]:
    """Valid payload for context building."""
    return {
        "thread_id": "thread-1",
        "turn_id": "turn-1",
        "parent_turn_id": None,
        "message": "Hello, world!",
    }


def make_decision_payload(
    artifacts: ContextArtifacts,
    decision: DecisionResult,
    context_config_digest: str | None = None,
) -> dict[str, Any]:
    """Build a DECISION payload mimicking what app.py does."""
    normative = build_normative_decision(
        decision,
        assembly_digest=artifacts.context_digest,
        context_digest=artifacts.context_digest if decision.decision == "ALLOW" else None,
        transforms=artifacts.transforms,
    )
    payload: dict[str, Any] = {
        "decision": decision.decision,
        "reason_codes": decision.reason_codes or [],
        **normative,
    }
    if artifacts.context_spec is not None:
        payload["context_spec"] = artifacts.context_spec
    if artifacts.assembled_context is not None:
        payload["assembled_context"] = artifacts.assembled_context
    # NEW: Boundary block with config_digest
    if context_config_digest:
        payload["boundary"] = {
            "context_config_digest": context_config_digest,
            "boundary_version": "1",
        }
    return payload


class TestDecisionPayloadConfigDigest:
    """Tests for context_config_digest in DECISION payload."""

    def test_config_digest_materialized_in_decision(
        self, sample_config: ContextConfig, valid_payload: dict[str, Any]
    ) -> None:
        """DECISION payload contains context_config_digest from artifacts."""
        artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
        decision = DecisionResult(decision="ALLOW", reason_codes=["policy.allow"])
        
        payload = make_decision_payload(
            artifacts,
            decision,
            context_config_digest=artifacts.config_digest,
        )
        
        assert "boundary" in payload
        assert payload["boundary"]["context_config_digest"] == sample_config.config_digest
        assert payload["boundary"]["context_config_digest"].startswith("sha256:")

    def test_config_digest_matches_context_spec_normalization(
        self, sample_config: ContextConfig, valid_payload: dict[str, Any]
    ) -> None:
        """DECISION boundary.context_config_digest matches context_spec.normalization.config_digest."""
        artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
        decision = DecisionResult(decision="ALLOW", reason_codes=[])
        
        payload = make_decision_payload(
            artifacts,
            decision,
            context_config_digest=artifacts.config_digest,
        )
        
        # Both should be identical
        normalization_digest = artifacts.context_spec["retrieval"]["normalization"]["config_digest"]
        boundary_digest = payload["boundary"]["context_config_digest"]
        
        assert normalization_digest == boundary_digest
        assert normalization_digest == sample_config.config_digest

    def test_config_drift_detected(self, tmp_path: Path, valid_payload: dict[str, Any]) -> None:
        """Different configs produce different digests, detectable at replay."""
        # Config A
        config_a = {
            "schema_version": "1",
            "context": {
                "max_refs": 50,
                "empty_refs_policy": "DENY",
                "canonical_sort": "event_index_asc",
                "enforce_scope_bound": True,
            },
            "normalization": {"rules": ["A"]},
        }
        path_a = tmp_path / "a.json"
        path_a.write_text(json.dumps(config_a), encoding="utf-8")
        cfg_a = load_context_config(path_a)
        
        # Config B (different rules)
        config_b = {
            "schema_version": "1",
            "context": {
                "max_refs": 50,
                "empty_refs_policy": "DENY",
                "canonical_sort": "event_index_asc",
                "enforce_scope_bound": True,
            },
            "normalization": {"rules": ["B"]},
        }
        path_b = tmp_path / "b.json"
        path_b.write_text(json.dumps(config_b), encoding="utf-8")
        cfg_b = load_context_config(path_b)
        
        # Build decisions with different configs
        artifacts_a = build_context(valid_payload, intent_type="chat.message", config=cfg_a)
        artifacts_b = build_context(valid_payload, intent_type="chat.message", config=cfg_b)
        
        decision = DecisionResult(decision="ALLOW", reason_codes=[])
        
        payload_a = make_decision_payload(artifacts_a, decision, context_config_digest=cfg_a.config_digest)
        payload_b = make_decision_payload(artifacts_b, decision, context_config_digest=cfg_b.config_digest)
        
        # Config digests must differ (drift detection)
        assert payload_a["boundary"]["context_config_digest"] != payload_b["boundary"]["context_config_digest"]
        
        # And context_digests must also differ (because normalization is in scope)
        assert artifacts_a.context_digest != artifacts_b.context_digest

    def test_replay_verification_possible(
        self, sample_config: ContextConfig, valid_payload: dict[str, Any]
    ) -> None:
        """Replay can verify config digest by recomputing from stored config."""
        artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
        decision = DecisionResult(decision="ALLOW", reason_codes=[])
        
        payload = make_decision_payload(
            artifacts,
            decision,
            context_config_digest=artifacts.config_digest,
        )
        
        # Simulate replay: reload config, compare digest
        stored_digest = payload["boundary"]["context_config_digest"]
        recomputed_digest = sample_config.config_digest
        
        assert stored_digest == recomputed_digest

    def test_no_observation_pollution_in_boundary(
        self, sample_config: ContextConfig, valid_payload: dict[str, Any]
    ) -> None:
        """Boundary block contains only normative fields, no observations."""
        artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
        decision = DecisionResult(decision="ALLOW", reason_codes=[])
        
        payload = make_decision_payload(
            artifacts,
            decision,
            context_config_digest=artifacts.config_digest,
        )
        
        boundary = payload["boundary"]
        
        # Only allowed fields in boundary (no execution outputs, no timestamps, etc.)
        allowed_fields = {"context_config_digest", "boundary_version"}
        actual_fields = set(boundary.keys())
        
        assert actual_fields <= allowed_fields, f"Unexpected fields in boundary: {actual_fields - allowed_fields}"

    def test_deny_decision_also_has_config_digest(
        self, sample_config: ContextConfig, valid_payload: dict[str, Any]
    ) -> None:
        """DENY decisions also have context_config_digest for audit."""
        artifacts = build_context(valid_payload, intent_type="chat.message", config=sample_config)
        decision = DecisionResult(decision="DENY", reason_codes=["policy.deny"])
        
        payload = make_decision_payload(
            artifacts,
            decision,
            context_config_digest=artifacts.config_digest,
        )
        
        assert "boundary" in payload
        assert payload["boundary"]["context_config_digest"] == sample_config.config_digest
        assert payload["decision"] == "DENY"
