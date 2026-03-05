# LLM Call Contract

Status: planned. The gateway does not currently expose `/llm/call`.
Use `/ingress/intent` with embedded execution instead.

## Purpose and non-goals
- Purpose: define the authoritative LLM call intake, governance decision, and event ordering for the gateway domainrunner.
- Non-goals: define model execution providers, tool execution, or any UI behavior.
 - /llm/call is a domain runner surface and is not a generic wire envelope.

## Authoritative input schema (I_L)
- request_id: gateway-assigned string (from x-request-id or generated)
- tenant_id: string
- actor_id: string
- actor_roles: list of strings
- prompt: string
- parameters: object with allow-list keys only
  - model: string
  - temperature: number
  - max_tokens: integer
  - tools_enabled: boolean
- boundary_version: integer
- policy_version: integer

## Admission (L)
- Normalize: trim prompt, clamp parameters to allow-list keys only, coerce types.
- Reject without writing INTENT if required fields are missing or types invalid.
- Write INTENT when admission is valid, even if governance later denies.

## Governance (G)
- Pure function: DECISION = f(I_L, policy_version).
- Must use only admitted fields from I_L, no output data.
- Allow only if all conditions hold:
  - actor_roles contains GATEWAY_LLM_REQUIRED_ROLE.
  - tenant_id is in allow-list when configured.
  - model is in allow-list when configured.
  - temperature in [0, GATEWAY_LLM_TEMP_MAX].
  - max_tokens in [1, GATEWAY_LLM_MAX_TOKENS_MAX].
  - tools_enabled is true only if GATEWAY_LLM_TOOLS_ALLOWED=true.

## Event sequence
- INTENT contains I_L plus intent_digest and boundary_config_hash (from stack fingerprint, not request).
- DECISION is appended after INTENT and before EXECUTION.
- EXECUTION is appended only when DECISION is ALLOW.

## Boundary vs policy
- DBL_GATEWAY_ALLOWED_TENANTS is an auth boundary. Tenant rejection blocks /llm/call before INTENT.
- GATEWAY_TENANT_ALLOWLIST is policy. It can produce a DENY decision after INTENT.
- GATEWAY_LLM_REQUIRED_ROLE is policy. Missing role produces a DENY decision after INTENT.

## Determinism
- Normalization is deterministic for identical inputs.
- intent_digest is computed from canonical JSON of I_L.
- EXECUTION output is observational; it must not affect DECISION.

## Env knobs
- GATEWAY_LLM_REQUIRED_ROLE: default gateway.llm.call.
- GATEWAY_TENANT_ALLOWLIST: CSV, empty means no check.
- GATEWAY_LLM_MODEL_ALLOWLIST: CSV, empty means no check.
- GATEWAY_LLM_TEMP_MAX: float, default 1.0.
- GATEWAY_LLM_MAX_TOKENS_MAX: int, default 1024.
- GATEWAY_LLM_TOOLS_ALLOWED: bool, default false.
- GATEWAY_POLICY_VERSION: int default used when caller omits policy_version.
- GATEWAY_LLM_EXEC_MODE: stub, http, or openai, default stub.
- GATEWAY_LLM_OUTPUT_MAX_CHARS: int, default 8192.
- GATEWAY_LLM_PROVIDER: generic_http, openai, or azure_openai (default generic_http).
- GATEWAY_LLM_API_KEY: API key for provider modes.
- GATEWAY_LLM_MODEL: default model when caller omits parameters.model.
- GATEWAY_LLM_HTTP_BASE_URL: base URL for provider modes.
- GATEWAY_LLM_TIMEOUT_S: timeout in seconds (default 30).
- GATEWAY_LLM_STORE_OUTPUT_TEXT: true or false (default true for stub, otherwise false).

## Idempotency
- /llm/call does not apply Idempotency-Key dedupe. Retries produce new INTENT/DECISION/EXECUTION events.

## generic_http adapter
- Request: { "input": I_L }
- Response: { "output_text": "..." }

## Provider notes
- openai mode is a best-effort adapter and not a stable contract surface.
