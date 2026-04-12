# OIDC Integration

This is an OIDC token-to-decision seam, not an identity platform.

The gateway does not keep sessions, call Microsoft Graph, or resolve groups at request time.
Identity input must be fully contained in the presented token plus the configured boundary mapping.

## What The Gateway Does

Given a valid bearer token, the gateway:

1. verifies signature and token time against cached JWKS
2. enforces issuer and audience allowlists
3. maps claims into `actor_id`, `tenant_id`, `roles`, and `issuer`
4. derives `trust_class`
5. records the resulting identity line in `DECISION`

That is the whole seam.

## Entra Example Boundary Config

This is a concrete `identity_policy` example for Microsoft Entra ID.
It belongs in the active boundary artifact.

```json
{
  "identity_policy": {
    "mode": "oidc",
    "issuers_allowed": [
      "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
    ],
    "audiences_allowed": [
      "api://dbl-gateway"
    ],
    "claim_mapping": {
      "actor_id": ["oid", "sub"],
      "issuer": "iss",
      "roles": ["roles", "groups"]
    },
    "tenant_mapping": {
      "claim": "tid",
      "fallback": "entra-default",
      "allowlist": ["11111111-2222-3333-4444-555555555555"]
    },
    "role_map": {
      "Gateway.Operator": ["gateway.operator"],
      "Gateway.Internal": ["gateway.internal"],
      "group:admins": ["gateway.operator"]
    }
  }
}
```

The same shape works for other OIDC issuers.
Only issuer, audience, and claim names change.

## Runtime JWKS Setting

The boundary declares how claims are interpreted.
The JWKS URL stays a runtime setting:

```bash
export DBL_GATEWAY_OIDC_JWKS_URL="https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/discovery/v2.0/keys"
```

That keeps key-discovery plumbing outside the hashed boundary artifact while the identity mapping itself stays versioned.

## Minimal Token Flow

```text
Bearer token
  -> signature/time verification
  -> issuer/audience allowlists
  -> claim mapping
  -> tenant allowlist
  -> trust_class
  -> DECISION
```

## What Lands In DECISION

The normative identity line includes:

- `actor_id`
- `tenant_id`
- `trust_class`
- `identity_issuer`
- `identity_verified`
- `identity_source`
- `claims_digest`

`claims_digest` is computed from the mapped identity line, not the raw token payload.
Extra claims or reordered claim keys do not change it.

## What The Gateway Does Not Do

- no Graph lookups
- no online introspection dependency
- no server-side session store
- no gateway-owned user directory
- no dynamic role expansion outside the token and boundary mapping
