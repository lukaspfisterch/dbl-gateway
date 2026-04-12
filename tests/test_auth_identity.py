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
    _mapped_identity_digest,
    _get_jwks,
    identity_fields_for_actor,
    load_auth_config_with_identity_policy,
    require_tenant,
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
        tenant_fallback="tenant-default",
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
    assert actor.claims_digest == _mapped_identity_digest(
        actor_id="user-123",
        tenant_id="tenant-123",
        client_id="client-123",
        roles=("gateway.operator",),
        issuer="https://issuer.example",
    )
    assert trust_class_for_actor(actor) == "operator"


def test_authorize_oidc_claims_uses_tenant_fallback_when_claim_missing() -> None:
    claims = {
        "sub": "user-123",
        "azp": "client-123",
        "iss": "https://issuer.example",
        "roles": [],
    }
    actor = _authorize_oidc_claims(claims, _oidc_config())
    assert actor.tenant_id == "tenant-default"


def test_authorize_oidc_claims_digest_ignores_irrelevant_claims_and_claim_order() -> None:
    cfg = _oidc_config()
    base_claims = {
        "sub": "user-123",
        "tid": "tenant-123",
        "azp": "client-123",
        "iss": "https://issuer.example",
        "roles": ["group:admins"],
    }
    noisy_claims = {
        "roles": ["group:admins"],
        "iss": "https://issuer.example",
        "azp": "client-123",
        "sub": "user-123",
        "tid": "tenant-123",
        "nonce": "ignored",
        "name": "Ignored Name",
        "preferred_username": "ignored@example.com",
    }
    assert _authorize_oidc_claims(base_claims, cfg).claims_digest == _authorize_oidc_claims(
        noisy_claims,
        cfg,
    ).claims_digest


def test_mapped_identity_digest_sorts_roles_for_stability() -> None:
    digest_a = _mapped_identity_digest(
        actor_id="user-123",
        tenant_id="tenant-123",
        client_id="client-123",
        roles=("gateway.operator", "gateway.snapshot.read"),
        issuer="https://issuer.example",
    )
    digest_b = _mapped_identity_digest(
        actor_id="user-123",
        tenant_id="tenant-123",
        client_id="client-123",
        roles=("gateway.snapshot.read", "gateway.operator"),
        issuer="https://issuer.example",
    )
    assert digest_a == digest_b


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


def test_load_auth_config_uses_identity_policy_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
    cfg = load_auth_config_with_identity_policy(
        identity_policy={
            "mode": "oidc",
            "issuers_allowed": ["https://issuer.example"],
            "audiences_allowed": ["api://gateway"],
            "claim_mapping": {
                "actor_id": ["sub"],
                "issuer": "iss",
                "roles": ["groups"],
            },
            "tenant_mapping": {
                "claim": "tenant",
                "fallback": "tenant-default",
                "allowlist": ["tenant-a", "tenant-b"],
            },
            "role_map": {
                "group:admins": ["gateway.operator"],
            },
        }
    )
    assert cfg.mode == "oidc"
    assert cfg.issuers_allowed == ("https://issuer.example",)
    assert cfg.audiences_allowed == ("api://gateway",)
    assert cfg.allowed_tenants == ("tenant-a", "tenant-b")
    assert cfg.allow_all_tenants is False
    assert cfg.tenant_claim == "tenant"
    assert cfg.tenant_fallback == "tenant-default"
    assert cfg.actor_id_claims == ("sub",)
    assert cfg.issuer_claim == "iss"
    assert cfg.role_claims == ("groups",)
    assert cfg.role_map == {"group:admins": ["gateway.operator"]}


def test_require_tenant_rejects_unmapped_tenant() -> None:
    actor = Actor(
        actor_id="user-1",
        tenant_id="tenant-x",
        client_id="client-1",
        roles=("gateway.snapshot.read",),
        issuer="https://issuer.example",
        verified=True,
        identity_source="oidc",
        claims_digest="sha256:test",
        raw_claims={},
    )
    cfg = AuthConfig(
        mode="oidc",
        issuers_allowed=("https://issuer.example",),
        audiences_allowed=("api://gateway",),
        jwks_url="https://issuer.example/keys",
        allowed_tenants=("tenant-a",),
        allow_all_tenants=False,
        tenant_claim="tid",
        tenant_fallback="tenant-default",
        actor_id_claims=("sub",),
        issuer_claim="iss",
        role_claims=("roles",),
        role_map=None,
        dev_actor="dev-user",
        dev_roles=("gateway.snapshot.read",),
    )
    with pytest.raises(auth_module.ForbiddenError, match="identity.tenant_not_allowed"):
        require_tenant(actor, cfg)
