from __future__ import annotations

from dbl_gateway.auth import Actor, identity_fields_for_actor, trust_class_for_actor


def test_trust_class_for_unverified_actor_is_anonymous() -> None:
    actor = Actor(
        actor_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        roles=("gateway.operator",),
        issuer="oidc",
        verified=False,
        raw_claims={},
    )
    assert trust_class_for_actor(actor) == "anonymous"


def test_trust_class_for_operator_role_is_operator() -> None:
    actor = Actor(
        actor_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        roles=("gateway.operator",),
        issuer="oidc",
        verified=True,
        raw_claims={},
    )
    assert trust_class_for_actor(actor) == "operator"


def test_identity_fields_for_actor_are_deterministic() -> None:
    actor = Actor(
        actor_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        roles=("gateway.snapshot.read",),
        issuer="https://issuer.example",
        verified=True,
        raw_claims={},
    )
    assert identity_fields_for_actor(actor) == {
        "actor_id": "user-1",
        "tenant_id": "tenant-1",
        "client_id": "client-1",
        "roles": ["gateway.snapshot.read"],
        "issuer": "https://issuer.example",
        "verified": True,
        "trust_class": "user",
    }


def test_identity_fields_for_synthetic_internal_actor() -> None:
    assert identity_fields_for_actor(None, trust_class="internal") == {
        "actor_id": "gateway",
        "tenant_id": "unknown",
        "client_id": "unknown",
        "roles": [],
        "issuer": "gateway",
        "verified": True,
        "trust_class": "internal",
    }
