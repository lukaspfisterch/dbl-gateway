from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class AuthConfig:
    mode: str
    issuers_allowed: tuple[str, ...]
    audiences_allowed: tuple[str, ...]
    jwks_url: str
    allowed_tenants: tuple[str, ...]
    allow_all_tenants: bool
    tenant_claim: str
    actor_id_claims: tuple[str, ...]
    issuer_claim: str
    role_claims: tuple[str, ...]
    role_map: dict[str, list[str]] | None
    dev_actor: str
    dev_roles: tuple[str, ...]


@dataclass(frozen=True)
class Actor:
    actor_id: str
    tenant_id: str
    client_id: str
    roles: tuple[str, ...]
    issuer: str
    verified: bool
    identity_source: str
    claims_digest: str | None
    raw_claims: dict[str, Any]


TRUST_CLASSES: tuple[str, ...] = ("anonymous", "user", "operator", "internal")


class AuthError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class IdentityAdapter(Protocol):
    async def verify_and_map(self, headers: Mapping[str, str]) -> Actor:
        ...

    async def warm(self) -> None:
        ...


_JWKS_BY_URL: dict[str, dict[str, Any]] = {}
_JWKS_TS_BY_URL: dict[str, float] = {}
_JWKS_CACHE_TTL_S: float = 300.0


def identity_fields_for_actor(
    actor: Actor | None,
    *,
    trust_class: str | None = None,
    fallback_actor_id: str = "gateway",
    fallback_issuer: str = "gateway",
) -> dict[str, Any]:
    resolved_trust_class = trust_class or trust_class_for_actor(actor)
    if actor is None:
        verified = resolved_trust_class != "anonymous"
        return {
            "actor_id": fallback_actor_id if verified else "anonymous",
            "tenant_id": "unknown",
            "client_id": "unknown",
            "roles": [],
            "issuer": fallback_issuer if verified else "anonymous",
            "verified": verified,
            "identity_source": "synthetic",
            "claims_digest": None,
            "trust_class": resolved_trust_class,
        }
    return {
        "actor_id": actor.actor_id,
        "tenant_id": actor.tenant_id,
        "client_id": actor.client_id,
        "roles": list(actor.roles),
        "issuer": actor.issuer,
        "verified": actor.verified,
        "identity_source": actor.identity_source,
        "claims_digest": actor.claims_digest,
        "trust_class": resolved_trust_class,
    }


def load_auth_config() -> AuthConfig:
    mode = os.getenv("DBL_GATEWAY_AUTH_MODE", "dev").strip().lower()
    issuers_raw = (
        os.getenv("DBL_GATEWAY_OIDC_ISSUERS", "").strip()
        or os.getenv("DBL_GATEWAY_OIDC_ISSUER", "").strip()
    )
    audiences_raw = (
        os.getenv("DBL_GATEWAY_OIDC_AUDIENCES", "").strip()
        or os.getenv("DBL_GATEWAY_OIDC_AUDIENCE", "").strip()
    )
    jwks_url = os.getenv("DBL_GATEWAY_OIDC_JWKS_URL", "").strip()
    allowed_tenants_raw = os.getenv("DBL_GATEWAY_ALLOWED_TENANTS", "*").strip()
    tenant_claim = os.getenv("DBL_GATEWAY_TENANT_CLAIM", "tid").strip() or "tid"
    actor_id_claims_raw = os.getenv("DBL_GATEWAY_ACTOR_ID_CLAIMS", "oid,sub").strip()
    issuer_claim = os.getenv("DBL_GATEWAY_ISSUER_CLAIM", "iss").strip() or "iss"
    role_claims_raw = os.getenv("DBL_GATEWAY_ROLE_CLAIMS", "roles,groups").strip()
    role_map_raw = os.getenv("DBL_GATEWAY_ROLE_MAP", "").strip()

    dev_actor = os.getenv("DBL_GATEWAY_DEV_ACTOR", "dev-user").strip()
    dev_roles_raw = os.getenv(
        "DBL_GATEWAY_DEV_ROLES",
        "gateway.intent.write,gateway.decision.write,gateway.snapshot.read",
    ).strip()
    dev_roles = tuple([r.strip() for r in dev_roles_raw.split(",") if r.strip()])

    allow_all_tenants = allowed_tenants_raw == "*" or allowed_tenants_raw == ""
    allowed_tenants = tuple([t.strip() for t in allowed_tenants_raw.split(",") if t.strip()])
    issuers_allowed = tuple([i.strip() for i in issuers_raw.split(",") if i.strip()])
    audiences_allowed = tuple([a.strip() for a in audiences_raw.split(",") if a.strip()])
    actor_id_claims = tuple([c.strip() for c in actor_id_claims_raw.split(",") if c.strip()])
    role_claims = tuple([c.strip() for c in role_claims_raw.split(",") if c.strip()])
    role_map = _parse_role_map(role_map_raw)

    return AuthConfig(
        mode=mode,
        issuers_allowed=issuers_allowed,
        audiences_allowed=audiences_allowed,
        jwks_url=jwks_url,
        allowed_tenants=allowed_tenants,
        allow_all_tenants=allow_all_tenants,
        tenant_claim=tenant_claim,
        actor_id_claims=actor_id_claims,
        issuer_claim=issuer_claim,
        role_claims=role_claims,
        role_map=role_map,
        dev_actor=dev_actor,
        dev_roles=dev_roles,
    )


def require_roles(actor: Actor, required: Sequence[str]) -> None:
    missing = [r for r in required if r not in actor.roles]
    if missing:
        raise ForbiddenError(f"missing roles: {', '.join(missing)}")


def require_tenant(actor: Actor, cfg: AuthConfig | None = None) -> None:
    cfg = cfg or load_auth_config()
    if cfg.allow_all_tenants:
        return
    if actor.tenant_id in cfg.allowed_tenants:
        return
    raise ForbiddenError("tenant not allowed")


async def authenticate_request(headers: Mapping[str, str], cfg: AuthConfig | None = None) -> Actor:
    cfg = cfg or load_auth_config()
    adapter = identity_adapter_for_config(cfg)
    return await adapter.verify_and_map(headers)


async def warm_identity_adapter(cfg: AuthConfig | None = None) -> None:
    cfg = cfg or load_auth_config()
    adapter = identity_adapter_for_config(cfg)
    await adapter.warm()


def identity_adapter_for_config(cfg: AuthConfig) -> IdentityAdapter:
    if cfg.mode == "dev":
        return DevIdentityAdapter(cfg)
    if cfg.mode == "oidc":
        return OidcIdentityAdapter(cfg)
    raise AuthError(f"unsupported auth mode: {cfg.mode}")


@dataclass(frozen=True)
class DevIdentityAdapter:
    cfg: AuthConfig

    async def verify_and_map(self, headers: Mapping[str, str]) -> Actor:
        return _authenticate_dev(headers, self.cfg)

    async def warm(self) -> None:
        return None


@dataclass(frozen=True)
class OidcIdentityAdapter:
    cfg: AuthConfig

    async def verify_and_map(self, headers: Mapping[str, str]) -> Actor:
        claims = await _authenticate_oidc(headers, self.cfg)
        return _authorize_oidc_claims(claims, self.cfg)

    async def warm(self) -> None:
        if self.cfg.jwks_url:
            await _get_jwks(self.cfg.jwks_url)


def _authenticate_dev(headers: Mapping[str, str], cfg: AuthConfig) -> Actor:
    actor_id = headers.get("x-dev-actor", cfg.dev_actor).strip() or cfg.dev_actor
    roles_header = headers.get("x-dev-roles", "")
    roles = cfg.dev_roles
    if roles_header.strip():
        roles = tuple([r.strip() for r in roles_header.split(",") if r.strip()])

    return Actor(
        actor_id=actor_id,
        tenant_id=headers.get("x-dev-tenant", "dev-tenant").strip() or "dev-tenant",
        client_id=headers.get("x-dev-client", "dev-client").strip() or "dev-client",
        roles=roles,
        issuer="dev",
        verified=True,
        identity_source="dev",
        claims_digest=_claims_digest({"dev": True}),
        raw_claims={"dev": True},
    )


async def _authenticate_oidc(headers: Mapping[str, str], cfg: AuthConfig) -> dict[str, Any]:
    if not cfg.issuers_allowed or not cfg.audiences_allowed or not cfg.jwks_url:
        raise AuthError("OIDC config incomplete: issuers, audiences, jwks_url required")

    auth = headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise AuthError("missing bearer token")

    jwks = await _get_jwks(cfg.jwks_url)
    try:
        from jose import jwk, jwt
        from jose.exceptions import JWTError

        header = jwt.get_unverified_header(token)
        try:
            jwk_data = _select_jwk(header, jwks)
        except AuthError as exc:
            if str(exc) != "no matching JWKS key for kid":
                raise
            jwks = await _get_jwks(cfg.jwks_url, force=True)
            jwk_data = _select_jwk(header, jwks)
        key = jwk.construct(jwk_data)
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
            },
            leeway=60,
        )
    except ImportError as exc:
        raise AuthError("OIDC auth requires python-jose") from exc
    except JWTError as exc:
        raise AuthError(f"invalid token: {exc}") from exc

    _validate_oidc_claims(dict(claims), cfg)
    return dict(claims)


async def _get_jwks(jwks_url: str, *, force: bool = False) -> dict[str, Any]:
    global _JWKS_BY_URL, _JWKS_TS_BY_URL
    now = time.time()
    cached = _JWKS_BY_URL.get(jwks_url)
    if not force and jwks_url in _JWKS_BY_URL:
        ts = _JWKS_TS_BY_URL.get(jwks_url, 0.0)
        if (now - ts) < _JWKS_CACHE_TTL_S:
            return _JWKS_BY_URL[jwks_url]

    try:
        import httpx
    except ImportError as exc:
        raise AuthError("OIDC auth requires httpx") from exc

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(jwks_url)
            resp.raise_for_status()
            jwks = resp.json()
        except Exception as exc:
            if cached is not None:
                return cached
            raise AuthError(f"jwks fetch failed: {exc}") from exc

    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise AuthError("invalid JWKS payload")

    _JWKS_BY_URL[jwks_url] = jwks
    _JWKS_TS_BY_URL[jwks_url] = now
    return jwks


def _pick_first_str(claims: Mapping[str, Any], keys: list[str], default: str) -> str:
    for k in keys:
        v = claims.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return default


def _select_jwk(header: Mapping[str, Any], jwks: Mapping[str, Any]) -> Mapping[str, Any]:
    kid = header.get("kid")
    alg = header.get("alg")
    if alg != "RS256":
        raise AuthError("unsupported token algorithm")
    if not isinstance(kid, str) or not kid.strip():
        raise AuthError("token missing kid")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise AuthError("invalid JWKS payload")
    for key in keys:
        if isinstance(key, Mapping) and key.get("kid") == kid:
            return key
    raise AuthError("no matching JWKS key for kid")


def _authorize_oidc_claims(claims: Mapping[str, Any], cfg: AuthConfig) -> Actor:
    actor_id = _pick_first_str(claims, list(cfg.actor_id_claims), default="")
    if not actor_id:
        raise AuthError("token missing actor id claim")
    tenant_id = _pick_first_str(claims, [cfg.tenant_claim], default="unknown")
    client_id = _pick_first_str(claims, ["azp", "appid"], default="unknown")
    roles = _extract_roles(claims, cfg.role_claims)
    roles = _apply_role_map(roles, cfg.role_map)
    return Actor(
        actor_id=actor_id,
        tenant_id=tenant_id,
        client_id=client_id,
        roles=roles,
        issuer=_pick_first_str(claims, [cfg.issuer_claim], default="oidc"),
        verified=True,
        identity_source="oidc",
        claims_digest=_claims_digest(claims),
        raw_claims=dict(claims),
    )


def _validate_oidc_claims(claims: Mapping[str, Any], cfg: AuthConfig) -> None:
    issuer = _pick_first_str(claims, [cfg.issuer_claim], default="")
    if issuer not in cfg.issuers_allowed:
        raise AuthError("identity.issuer_not_allowed")
    aud_claim = claims.get("aud")
    audiences: set[str] = set()
    if isinstance(aud_claim, str) and aud_claim.strip():
        audiences.add(aud_claim.strip())
    elif isinstance(aud_claim, list):
        for item in aud_claim:
            if isinstance(item, str) and item.strip():
                audiences.add(item.strip())
    if not audiences:
        raise AuthError("identity.audience_missing")
    if not any(audience in audiences for audience in cfg.audiences_allowed):
        raise AuthError("identity.audience_mismatch")


def _claims_digest(claims: Mapping[str, Any]) -> str:
    canonical = json.dumps(claims, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _extract_roles(claims: Mapping[str, Any], claim_names: Sequence[str]) -> tuple[str, ...]:
    roles: list[str] = []
    for claim in claim_names:
        v = claims.get(claim)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    roles.append(item.strip())
        elif isinstance(v, str) and v.strip():
            for item in v.replace(",", " ").split():
                if item.strip():
                    roles.append(item.strip())
    seen: set[str] = set()
    unique: list[str] = []
    for r in roles:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return tuple(unique)


def _apply_role_map(roles: tuple[str, ...], role_map: dict[str, list[str]] | None) -> tuple[str, ...]:
    if role_map is None:
        return roles
    mapped: list[str] = []
    for role in roles:
        if role in role_map:
            mapped.extend(role_map[role])
        else:
            mapped.append(role)
    seen: set[str] = set()
    unique: list[str] = []
    for role in mapped:
        if role not in seen:
            seen.add(role)
            unique.append(role)
    return tuple(unique)


def _parse_role_map(role_map_raw: str) -> dict[str, list[str]] | None:
    if role_map_raw == "":
        return None
    try:
        parsed = json.loads(role_map_raw)
    except json.JSONDecodeError as exc:
        raise AuthError("DBL_GATEWAY_ROLE_MAP must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise AuthError("DBL_GATEWAY_ROLE_MAP must be a JSON object")
    role_map: dict[str, list[str]] = {}
    for key, value in parsed.items():
        if isinstance(value, str):
            role_map[str(key)] = [value]
        elif isinstance(value, list):
            mapped = [v for v in value if isinstance(v, str) and v.strip()]
            role_map[str(key)] = mapped
    return role_map


def trust_class_for_actor(actor: Actor | None) -> str:
    if actor is None or not actor.verified:
        return "anonymous"
    roles = set(actor.roles)
    if actor.raw_claims.get("dev") is True or "gateway.internal" in roles:
        return "internal"
    if roles & {"gateway.operator", "gateway.admin"}:
        return "operator"
    if actor.actor_id.strip():
        return "user"
    return "anonymous"
