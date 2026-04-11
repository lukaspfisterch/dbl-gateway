# Environment Contract

Gateway startup uses environment variables plus versioned JSON boundary/context artifacts.
Secrets never appear in event payloads.

## Runtime

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DBL_GATEWAY_DB` | yes | `./data/trail.sqlite` | SQLite path for the event trail |
| `DBL_GATEWAY_POLICY_MODULE` | yes | -- | Python module path for policy (e.g. `dbl_policy.allow_all`) |
| `DBL_GATEWAY_POLICY_OBJECT` | no | `POLICY` | Attribute name of the policy object in the module |
| `DBL_GATEWAY_BOUNDARY_CONFIG` | no | `config/boundary.json` | Path to the boundary config artifact controlling `exposure_mode`, surface rules, public admission limits, tool policy, and request/budget policy |
| `GATEWAY_EXEC_MODE` | no | `embedded` | `embedded` (in-process provider calls) or `external` (sidecar) |
| `GATEWAY_ENABLE_CONTEXT_RESOLUTION` | no | OFF | `true`/`1`/`yes` to enable declared_refs resolution and Workbench handle fetch. When OFF, refs are stored but not resolved; `artifact.handle` intents are rejected. |

## Auth And Identity

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DBL_GATEWAY_AUTH_MODE` | no | `dev` | Fallback only. The active auth mode should come from `boundary.identity_policy.mode`. |
| `DBL_GATEWAY_DEV_ACTOR` | no | `dev-user` | Default actor id in `dev` mode |
| `DBL_GATEWAY_DEV_ROLES` | no | `gateway.intent.write,gateway.decision.write,gateway.snapshot.read` | Default dev roles |
| `DBL_GATEWAY_OIDC_ISSUER` | `oidc` only | -- | Expected JWT issuer |
| `DBL_GATEWAY_OIDC_ISSUERS` | `oidc` only | -- | Comma-separated issuer allowlist. Preferred over singular issuer env. |
| `DBL_GATEWAY_OIDC_AUDIENCE` | `oidc` only | -- | Expected JWT audience |
| `DBL_GATEWAY_OIDC_AUDIENCES` | `oidc` only | -- | Comma-separated audience allowlist. Preferred over singular audience env. |
| `DBL_GATEWAY_OIDC_JWKS_URL` | `oidc` only | -- | JWKS endpoint used for signature validation |
| `DBL_GATEWAY_ALLOWED_TENANTS` | no | `*` | Allowed tenant ids or `*` |
| `DBL_GATEWAY_TENANT_CLAIM` | no | `tid` | Claim name used for tenant extraction |
| `DBL_GATEWAY_ACTOR_ID_CLAIMS` | no | `oid,sub` | Comma-separated claim names searched for actor id extraction |
| `DBL_GATEWAY_ISSUER_CLAIM` | no | `iss` | Claim name used for issuer extraction |
| `DBL_GATEWAY_ROLE_CLAIMS` | no | `roles,groups` | Comma-separated claim names searched for role extraction |
| `DBL_GATEWAY_ROLE_MAP` | no | -- | Optional JSON mapping from incoming roles to gateway roles |

Identity stays stateless inside the gateway. The request is verified, mapped into `gateway_auth`, and reduced to a deterministic `trust_class`. No session store or gateway-owned user database is required.
OIDC verification uses cached JWKS only. The gateway does not call online token introspection endpoints or maintain server-side sessions.

## Boundary Identity Policy

Each boundary artifact now contains `identity_policy`:
- `mode`
- `issuers_allowed`
- `audiences_allowed`
- `claim_mapping.actor_id`
- `claim_mapping.issuer`
- `claim_mapping.roles`
- `role_map`

This makes the effective identity mapping part of the hashed boundary contract instead of a hidden runtime detail.

## Boundary Profiles

Built-in boundary profiles live in `config/`:
- `boundary.json` — default `operator` profile
- `boundary.public.json` — minimized public surface
- `boundary.operator.json` — explicit operator surface profile
- `boundary.demo.json` — full demo/observer surface

`GATEWAY_DEMO_MODE=1` selects the demo boundary profile when no explicit boundary config path is set.

Each boundary artifact also contains `admission.public`:
- `allow_artifact_handle`
- `allow_declared_refs`
- `max_declared_tools`
- `max_budget.max_tokens`
- `max_budget.max_duration_ms`

Each boundary artifact also contains `tool_policy`:
- `families` — deterministic pattern buckets such as `exec_like`, `web_read`, `retrieval`, `llm_assist`
- `matrix.public`
- `matrix.operator`
- `matrix.demo`

The matrix defines the allowed tool families for each `(exposure_mode, trust_class)` pair and is published through `/capabilities`.

Each boundary artifact also contains `request_policy`:
- `classification.light_budget` — deterministic threshold for `execution_light` vs `execution_heavy`
- `matrix.public`
- `matrix.operator`
- `matrix.demo`

The request-policy matrix defines `allow|deny` plus optional budget ceilings for each `(exposure_mode, trust_class, request_class)` tuple and is published through `/capabilities`.

These limits are enforced deterministically from request content plus boundary config. They do not depend on queue depth, load, timing, or other runtime observations.

## Context High-Risk Fetch Mode

`config/context.json` contains `context.handle_content_fetch.high_risk_context_admit_mode`:
- `disabled` — handle content never enters model context
- `metadata_only` — handle refs stay resolvable/auditable, but fetched content does not enter model context
- `model_context` — fetched handle content may enter model context when the remaining fetch guards allow it

Default is `metadata_only`.

## Provider Credentials

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Enables OpenAI models |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible endpoint |
| `ANTHROPIC_API_KEY` | Enables Anthropic models |
| `OLLAMA_HOST` | Ollama server URL (default `http://localhost:11434`) |

At least one provider must be configured for execution mode.

## Model Lists

Comma-separated model identifiers. Models are exposed through `/capabilities`.

| Variable | Provider | Notes |
|----------|----------|-------|
| `OPENAI_CHAT_MODEL_IDS` | OpenAI | Chat completions API |
| `OPENAI_RESPONSES_MODEL_IDS` | OpenAI | Responses API |
| `OPENAI_MODEL_IDS` | OpenAI | Fallback if chat/responses lists are absent |
| `ANTHROPIC_MODEL_IDS` | Anthropic | Messages API |
| `OLLAMA_MODEL_IDS` | Ollama | Local/remote models |

## Job Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `DBL_JOB_QUEUE_MAX` | 100 | Max queued jobs per type |
| `DBL_JOB_CONCURRENCY_INGEST` | 2 | Concurrent `case.ingest` jobs |
| `DBL_JOB_CONCURRENCY_EMBED` | 1 | Concurrent `case.embed` jobs |
| `DBL_JOB_CONCURRENCY_INDEX` | 1 | Concurrent `case.index` jobs |
| `DBL_JOB_CONCURRENCY_LLM` | 1 | Concurrent `chat.message` provider calls |
| `DBL_LLM_WALL_CLOCK_S` | 60 | LLM call wall-clock timeout (seconds) |

## Workbench Handle Fetch

Only relevant when `GATEWAY_ENABLE_CONTEXT_RESOLUTION=true`.

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOW_HANDLE_CONTENT_FETCH` | false | Enable content fetch for `artifact.handle` refs |
| `WORKBENCH_RESOLVER_URL` | -- | Base URL for content fetch (must be http/https) |
| `WORKBENCH_AUTH_BEARER_TOKEN` | -- | Optional bearer token |
| `WORKBENCH_FETCH_TIMEOUT_MS` | 1500 | Fetch timeout |
| `WORKBENCH_MAX_BYTES` | 512000 | Max content size |
| `WORKBENCH_ADMIT_KINDS` | `extracted_text,summary` | Allowed artifact kinds |

## Security Expectations

- Secrets are never stored in event payloads.
- `/ingress/intent` is the canonical write surface.
- `/execution/event` is an optional write surface when `GATEWAY_EXEC_MODE=external`.
- AuthN/AuthZ and tenant gating are enforced at request entry.
