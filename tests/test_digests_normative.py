from __future__ import annotations

import pytest

from dbl_gateway.contracts import context_digest, decision_digest
from dbl_gateway.event_builder import make_event


def _decision_base():
    return {
        "policy": {"policy_id": "p.core", "policy_version": "1.0.0"},
        "assembly_digest": "sha256:" + ("1" * 64),
        "context_digest": "sha256:" + ("1" * 64),
        "result": "ALLOW",
        "reasons": [{"code": "ALLOW.BASELINE"}],
        "transforms": [],
    }


def test_decision_digest_ignores_obs_and_legacy():
    base = _decision_base()
    d1 = decision_digest(base)
    payload_with_obs = dict(base)
    payload_with_obs["_obs"] = {"trace_id": "abc", "boundary_meta": {"note": "x"}}
    payload_with_obs["requested_model_id"] = "m1"
    payload_with_obs["provider"] = "prov"
    d2 = decision_digest(payload_with_obs)
    assert d1 == d2


def test_decision_digest_order_invariant_reasons_transforms():
    base = _decision_base()
    base["reasons"] = [{"code": "B"}, {"code": "A", "params": {"tier": "std"}}]
    base["transforms"] = [
        {"op": "DROP_MESSAGE", "target": "ctx[2]"},
        {"op": "CLAMP_LENGTH", "target": "ctx[1]", "params": {"max": 10}},
    ]
    shuffled = _decision_base()
    shuffled["reasons"] = list(reversed(base["reasons"]))
    shuffled["transforms"] = list(reversed(base["transforms"]))
    assert decision_digest(base) == decision_digest(shuffled)


def test_context_digest_orders_declared_refs_and_key_order():
    spec = {
        "identity": {"thread_id": "t", "turn_id": "u", "parent_turn_id": None},
        "intent": {"intent_type": "chat.completion", "user_input": "hello"},
        "retrieval": {
            "declared_refs": [
                {"ref_id": "b", "ref_type": "DOC", "version": "1"},
                {"ref_id": "a", "ref_type": "DOC"},
            ]
        },
        "assembly_rules": {"schema_version": "ctxspec.1", "ordering": "CANONICAL_V1"},
    }
    assembled = {
        "model_messages": [{"role": "user", "content": "hello"}],
        "assembled_from": list(reversed(spec["retrieval"]["declared_refs"])),
    }
    digest_a = context_digest(spec, assembled)
    # flip ordering and key order
    spec_b = {
        "assembly_rules": {"ordering": "CANONICAL_V1", "schema_version": "ctxspec.1"},
        "intent": {"user_input": "hello", "intent_type": "chat.completion"},
        "retrieval": {
            "declared_refs": list(reversed(spec["retrieval"]["declared_refs"])),
        },
        "identity": {"turn_id": "u", "thread_id": "t", "parent_turn_id": None},
    }
    assembled_b = {
        "assembled_from": spec["retrieval"]["declared_refs"],
        "model_messages": [{"content": "hello", "role": "user"}],
    }
    digest_b = context_digest(spec_b, assembled_b)
    assert digest_a == digest_b


def test_make_event_requires_anchors():
    with pytest.raises(ValueError):
        make_event(
            kind="INTENT",
            thread_id="",
            turn_id="u",
            parent_turn_id=None,
            lane="lane",
            actor="actor",
            intent_type="type",
            stream_id="stream",
            correlation_id="c",
            payload={},
        )
    with pytest.raises(ValueError):
        make_event(
            kind="INTENT",
            thread_id="t",
            turn_id="",
            parent_turn_id=None,
            lane="lane",
            actor="actor",
            intent_type="type",
            stream_id="stream",
            correlation_id="c",
            payload={},
        )
