# Env Contract

This document captures the environment contract for a future appliance packaging.
It describes configuration only. It does not define deployment or build steps.

## Runtime
- `DBL_GATEWAY_MODE`: `leader` or `follower` (default `leader`)
- `DBL_GATEWAY_HOST`: optional host binding (runtime wrapper)
- `DBL_GATEWAY_PORT`: optional port binding (runtime wrapper)
- `DBL_GATEWAY_STRICT_READ_VERIFY`: `0` or `1` (default `0`)
- `DBL_GATEWAY_LEADER_LOCK`: `0` or `1` (default `1`)
- `DBL_GATEWAY_LEADER_LOCK_PATH`: optional lock file path override
- `DBL_GATEWAY_IDEMPOTENCY`: `0` or `1` (default `0`, enables Idempotency-Key handling)

## Store
- `DBL_GATEWAY_STORE`: `sqlite` or `postgres` (default `sqlite`)
- `DBL_GATEWAY_DB`: sqlite path (default `.\data\trail.sqlite`)
- `DBL_GATEWAY_DB_URL`: postgres connection URL (required when `DBL_GATEWAY_STORE=postgres`)

## Auth
- `DBL_GATEWAY_AUTH_MODE`: `dev` or `oidc` (default `dev`)
- `DBL_GATEWAY_DEV_ACTOR`: dev actor id (default `dev-user`)
- `DBL_GATEWAY_DEV_ROLES`: dev roles list (default `gateway.intent.write,gateway.decision.write,gateway.snapshot.read`)
- `DBL_GATEWAY_OIDC_ISSUER`: OIDC issuer URL
- `DBL_GATEWAY_OIDC_AUDIENCE`: OIDC audience
- `DBL_GATEWAY_OIDC_JWKS_URL`: OIDC JWKS URL
- `DBL_GATEWAY_ALLOWED_TENANTS`: comma list or `*` (default `*`)
- `DBL_GATEWAY_TENANT_CLAIM`: claim used for tenant id (default `tid`)
- `DBL_GATEWAY_ROLE_CLAIMS`: comma list of claim names for roles or scopes (default `roles`)
- `DBL_GATEWAY_ROLE_MAP`: JSON object mapping external roles to gateway roles

## Stack fingerprint
- `DBL_GATEWAY_POLICY_PACK_DIGEST`: digest-ref or `unknown` (default `unknown`)
- `DBL_GATEWAY_BOUNDARY_CONFIG_HASH`: opaque hash or `unknown` (default `unknown`)

## LLM call
- `GATEWAY_LLM_REQUIRED_ROLE`: policy role required for /llm/call (default `gateway.llm.call`)
- `GATEWAY_TENANT_ALLOWLIST`: CSV allow-list for tenants (empty means no check)
- `GATEWAY_LLM_MODEL_ALLOWLIST`: CSV allow-list for models (empty means no check)
- `GATEWAY_LLM_TEMP_MAX`: max temperature (default `1.0`)
- `GATEWAY_LLM_MAX_TOKENS_MAX`: max tokens cap (default `1024`)
- `GATEWAY_LLM_TOOLS_ALLOWED`: `true` or `false` (default `false`)
- `GATEWAY_POLICY_VERSION`: default policy_version for /llm/call (default `1`)
- `GATEWAY_LLM_EXEC_MODE`: `stub`, `http`, or `openai` (default `stub`)
- `GATEWAY_LLM_PROVIDER`: `generic_http`, `openai`, or `azure_openai` (default `generic_http`)
- `GATEWAY_LLM_API_KEY`: provider API key
- `GATEWAY_LLM_MODEL`: default model when caller omits parameters.model
- `GATEWAY_LLM_OUTPUT_MAX_CHARS`: output_text cap (default `8192`)
- `GATEWAY_LLM_HTTP_BASE_URL`: http base URL for provider adapters
- `GATEWAY_LLM_TIMEOUT_S`: timeout in seconds (default `30`)
- `GATEWAY_LLM_STORE_OUTPUT_TEXT`: `true` or `false` (default `true` for stub, otherwise `false`)

## Secrets scaffold
- `GATEWAY_SECRETS_PROVIDER`: `env`, `file`, or `vault` (default `env`)
- `GATEWAY_SECRETS_PATH`: path for file-backed secrets (unused unless provider is `file`)
- `GATEWAY_SECRETS_VAULT_ADDR`: vault address placeholder
- `GATEWAY_SECRETS_VAULT_TOKEN`: vault token placeholder

## Security expectations
- Use `leader` for any instance that accepts writes.
- Restrict `DBL_GATEWAY_ALLOWED_TENANTS` to a known allowlist in production.
- `DBL_GATEWAY_ROLE_MAP` should map external roles or scopes to gateway roles.
