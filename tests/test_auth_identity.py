from __future__ import annotations

import asyncio

import httpx
import pytest

from dbl_gateway import auth as auth_module
from dbl_gateway.auth import (
    Actor,
    AuthConfig,
    AuthError,
    _authorize_oidc_claims,
    _claims_digest,
    _get_jwks,
    identity_fields_for_actor,
    trust_class_for_actor,
)


def _oidc_config() -> AuthConfig:
    return AuthConfig(
        mode="oidc",
        issuers_allowed=("https://issuer.example",),
        audiences_allowed=("api://gateway",),
        jwks_url="https://issuer.example/keys",
        allowed_tenants=(),
        allow_all_tenants=True,
        tenant_claim="tid",
        actor_id_claims=("sub",),
        issuer_claim="iss",
        role_claims=("roles", "groups"),
        role_map={"group:admins": ["gateway.operator"]},
        dev_actor="dev-user",
        dev_roles=("gateway.snapshot.read",),
    )


def test_trust_class_for_unverified_actor_is_anonymous() -> None:
    actor = Actor(
        actor_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        roles=("gateway.operator",),
        issuer="oidc",
        verified=False,
        identity_source="oidc",
        claims_digest="sha256:test",
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
        identity_source="oidc",
        claims_digest="sha256:test",
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
        identity_source="oidc",
        claims_digest="sha256:claims",
        raw_claims={},
    )
    assert identity_fields_for_actor(actor) == {
        "actor_id": "user-1",
        "tenant_id": "tenant-1",
        "client_id": "client-1",
        "roles": ["gateway.snapshot.read"],
        "issuer": "https://issuer.example",
        "verified": True,
        "identity_source": "oidc",
        "claims_digest": "sha256:claims",
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
        "identity_source": "synthetic",
        "claims_digest": None,
        "trust_class": "internal",
    }


def test_authorize_oidc_claims_maps_roles_and_digest() -> None:
    claims = {
        "sub": "user-123",
        "tid": "tenant-123",
        "azp": "client-123",
        "iss": "https://issuer.example",
        "roles": ["group:admins"],
    }
    actor = _authorize_oidc_claims(claims, _oidc_config())
    assert actor.actor_id == "user-123"
    assert actor.tenant_id == "tenant-123"
    assert actor.client_id == "client-123"
    assert actor.roles == ("gateway.operator",)
    assert actor.issuer == "https://issuer.example"
    assert actor.verified is True
    assert actor.identity_source == "oidc"
    assert actor.claims_digest == _claims_digest(claims)
    assert trust_class_for_actor(actor) == "operator"


def test_authorize_oidc_claims_requires_allowed_issuer() -> None:
    claims = {
        "sub": "user-123",
        "tid": "tenant-123",
        "azp": "client-123",
        "iss": "https://other-issuer.example",
        "aud": "api://gateway",
    }
    with pytest.raises(AuthError, match="identity.issuer_not_allowed"):
        auth_module._validate_oidc_claims(claims, _oidc_config())


def test_authorize_oidc_claims_requires_allowed_audience() -> None:
    claims = {
        "sub": "user-123",
        "tid": "tenant-123",
        "azp": "client-123",
        "iss": "https://issuer.example",
        "aud": "api://other",
    }
    with pytest.raises(AuthError, match="identity.audience_mismatch"):
        auth_module._validate_oidc_claims(claims, _oidc_config())


def test_get_jwks_uses_stale_cache_on_refresh_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://issuer.example/keys"
    cached = {"keys": [{"kid": "cached"}]}
    auth_module._JWKS_BY_URL[url] = cached
    auth_module._JWKS_TS_BY_URL[url] = 0.0

    class FailingAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> "FailingAsyncClient":
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, _url: str):
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "AsyncClient", FailingAsyncClient)
    try:
        assert asyncio.run(_get_jwks(url)) == cached
    finally:
        auth_module._JWKS_BY_URL.clear()
        auth_module._JWKS_TS_BY_URL.clear()
