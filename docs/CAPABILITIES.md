# Gateway Capabilities

Client-visible capabilities. Internal architecture is not described
unless it affects wire behavior.

## Stable vs Variable
- Stable: interface_version=3, ContextSpec schema ctxspec.2, ContextConfig schema v1, BoundaryConfig schema v1, endpoint paths, tool_scope semantics, budget field schema, event chain (INTENT -> DECISION -> PROOF -> EXECUTION).
- Variable: provider list, model list, defaults, limits, policy version, and some failure codes may change with config/env.

## API Endpoints
- `GET /healthz` — health check. Response `{status}`.
- `GET /capabilities` — providers, models, and surfaces. Response `CapabilitiesResponse` (schema_version, gateway_version, interface_version=3).
- `GET /surfaces` — explicit discovery catalog of callable surfaces with path/method/auth metadata.
- `GET /intent-template` — self-teaching example/template surface for valid intent envelopes.
- `POST /ingress/intent` — ingest `IntentEnvelope` (interface_version=3). Returns accepted/queued + correlation_id + index.
- `GET /snapshot` — event snapshot (limit/offset/stream_id/lane). Returns `SnapshotResponse`.
- `GET /threads/{thread_id}/timeline` — grouped by turn; optionally include payloads.
- `GET /tail` — SSE stream of `EventRecord` envelopes.
- `GET /status` — projected runner state `{phase, runner_status, t_index, note}`.
- `POST /execution/event` — submit external execution result (only if exec_mode=external).

## Boundary Exposure
- `GET /capabilities` includes the active boundary profile:
  - `boundary_version`
  - `boundary_config_digest`
  - `exposure_mode`
- `surface_catalog` and `GET /surfaces` are filtered by the active exposure mode.
- Intent discovery is filtered by the active boundary and current context-resolution runtime gate.
- Built-in profiles:
  - `public` — minimal ingress-oriented surface
  - `operator` — runtime and discovery surfaces without `/ui/*`
  - `demo` — full observer/demo surface
- Public ingress is additionally bounded by the active boundary artifact's deterministic admission limits for `artifact.handle`, `declared_refs`, and declared tool count.
- Boundary artifacts also declare `tool_policy`, which contains family patterns plus the allowed-family matrix per exposure mode and trust class.
- Boundary artifacts now also declare `request_policy`, which classifies requests (`probe`, `intent`, `execution_light`, `execution_heavy`) and publishes budget ceilings per `(exposure_mode, trust_class, request_class)`.
- Boundary artifacts now also declare `economic_policy`, which maps each `(exposure_mode, trust_class, request_class)` tuple to `slot_class`, `cost_class`, and `reservation_required`.
- Boundary artifacts now also declare `identity_policy`, which pins the active identity mode plus claim/role mapping in the same hashed contract.
- `GET /capabilities` now also publishes `auth.mode`, `auth.current_trust_class`, `auth.trust_classes`, and `auth.identity_sources`.
- In `oidc` mode it also publishes `auth.issuers_allowed` and `auth.audiences_allowed`.

## Observer UI Endpoints

These routes are available only in the `demo` boundary profile.
- `GET /ui/` — built-in single-file observer UI.
- `GET /ui/tail` — auth-free SSE stream for browser `EventSource`.
- `GET /ui/capabilities` — auth-free observer proxy for capabilities.
- `GET /ui/snapshot` — auth-free observer proxy for the latest `v_digest` and event count.
- `GET /ui/policy-structure` — auth-free observer proxy for the current policy inspector payload.
- `POST /ui/intent` — auth-free observer proxy for manual intent submission from the UI.
- `GET /ui/verify-chain` — auth-free full-chain `v_digest` recomputation and match/mismatch report.
- `GET /ui/replay?thread_id=...&turn_id=...` — auth-free decision replay for one turn.
- `GET /ui/demo/status` — auth-free status for the integrated demo controller.
- `POST /ui/demo/start` — auth-free start trigger for the integrated demo controller.

These `/ui/*` routes are read-only observer infrastructure. Verification logic
and demo orchestration remain server-side; the browser only consumes events and
returned observer status/results.

## Surface Discovery
- `surfaces` in `GET /capabilities` remains the compact compatibility view: booleans for major runtime surfaces.
- `surface_catalog` in `GET /capabilities` is the richer machine-readable discovery list for clients.
- `GET /surfaces` exposes the same catalog directly for agents that want discovery without the rest of the capability payload.
- `GET /intent-template` publishes valid example envelopes so clients can discover not just where ingress is, but how to speak to it correctly.
- Template payloads include `interface_version`, `intent_variant`, and `target_endpoint` so agents can bootstrap against the wire contract without guessing.
- `template_version` and `template_schema_digest` let clients detect when the teaching surface has changed.
- `intents.catalog` describes each currently visible intent with `risk_class`, `admitted`, and `requires_context_resolution`.
- High-risk context intents also expose `model_context_admit_mode`.
- `GET /intent-template` only emits example envelopes for intents currently admitted by the active boundary/runtime configuration.

## Intents
- `chat.message`: accepts `message` plus optional `inputs`, `declared_refs`, `context_mode/context_n`, `declared_tools`, `tool_scope`, `budget`.
- `artifact.handle`: metadata-only, does not trigger decision by default; content fetch is gated. Rejected when `GATEWAY_ENABLE_CONTEXT_RESOLUTION` is OFF.
- `artifact.handle` is treated as `high_risk_context` in discovery metadata and is not advertised in `public` mode by default.
- By default, high-risk handle content remains `metadata_only`; only explicit `model_context` mode allows fetched content into prompt context.

## Declared Refs & Admission Rules
- `declared_refs` must be a list of `{ref_type, ref_id, version?}`.
- Max refs: 50. Empty refs policy: DENY (default).
- Scope bound enforced by thread_id.
- In `public` exposure mode, non-empty `declared_refs` are denied unless the boundary artifact explicitly allows them.
- Content admission:
  - INTENT events -> governance (no content by default unless artifact.handle with allowed fetch).
  - EXECUTION refs -> execution_only if `allow_execution_refs_for_prompt=true`.
  - `artifact.handle` content fetch: only when enabled + kind allowlisted.

## Tool Gating
- `declared_tools`: list of tool name strings (max 20), validated against `^[a-z][a-z0-9_.]{0,63}$`.
- `tool_scope`: `"strict"` (block undeclared) or `"advisory"` (log and allow). Default `"strict"` when `declared_tools` present.
- In `public` exposure mode, declared tool count is additionally capped by the boundary artifact before admission.
- `tool_surface.semantic_families` publishes the gateway's deterministic tool-family buckets.
- `tool_surface.trust_class_current` publishes the trust class resolved for the current caller.
- `tool_surface.allowed_families_current` publishes the tool families currently allowed for the active `(exposure_mode, trust_class)`.
- `tool_surface.allowed_families_by_exposure` publishes the full boundary matrix as `exposure -> trust_class -> families`.
- `tool_surface.no_mix_rules` publishes semantic combinations the gateway will deny before execution shaping.
- Current rule: `tool.no_mix.exec_like` denies exec-like tools when mixed with any other tool family.
- Unknown tools that do not match any configured family are denied with `tool.unknown_family`.
- Tool-family allowlists deny tools with stable reason `tool.family_not_allowed` before no-mix shaping runs.
- DECISION records `declared_tool_families`, `allowed_tool_families`, `permitted_tool_families`, `denied_tool_families`, `permitted_tools`, `tool_scope_enforced`, `tools_denied`, and `tools_denied_reason`.
- EXECUTION records `tool_calls` (allowed) and `tool_blocked` (blocked with reason).

## Budget Constraint
- `budget.max_tokens`: integer 1-1000000, passed to provider call.
- `budget.max_duration_ms`: integer 1000-300000, enforces execution wall clock.
- `budget.request_classes` publishes the deterministic request taxonomy.
- `budget.visible_request_classes_current` publishes only the request classes that the current `(exposure_mode, trust_class)` pair can actually use right now.
- `budget.light_budget_classification` publishes the threshold used to separate `execution_light` from `execution_heavy`.
- `budget.current_request_policy` publishes the active `(exposure_mode, trust_class)` request-policy map.
- In `public`, `budget.current_request_policy` is filtered to the currently allowed classes so heavy deny-only rows are not advertised as ghost capability.
- `budget.request_policy_by_exposure` publishes the full `exposure -> trust_class -> request_class -> rule` matrix.
- Budget-heavy requests are no longer dropped as raw admission failures; they are classified and recorded in DECISION with `request_class`, `budget_class`, `request_semantic_reason`, `request_constraints_applied`, and `budget_policy_reason`.
- `effective_timeout = min(runtime_ms, client_ms)`.
- DECISION records `request_class`, `budget_class`, `request_semantic_reason`, `request_constraints_applied`, `budget_policy_reason`, and `enforced_budget`.
- `enforced_budget.source` is one of `client`, `boundary_default`, or `boundary_cap`.
- EXECUTION records `usage.duration_ms`.

## Economic Policy
- `economic.slot_classes` publishes the deterministic slot taxonomy: `none`, `shared`, `reserved`.
- `economic.cost_classes` publishes the deterministic cost taxonomy: `low`, `bounded`, `capped`.
- `economic.current_policy` publishes the active `(exposure_mode, trust_class)` economic policy, filtered to request classes currently visible for the caller.
- `economic.policy_by_exposure` publishes the full `exposure -> trust_class -> request_class -> economic rule` matrix.
- DECISION records `slot_class`, `cost_class`, `reservation_required`, and `economic_policy_reason`.
- These fields describe the required execution class only. They do not encode current queue depth, provider health, or real-time slot availability.

## Auth And Identity
- Identity stays a boundary input, not a gateway-owned user store.
- The gateway resolves a minimal identity line into `actor_id`, `tenant_id`, `client_id`, `roles`, `issuer`, `verified`, and `trust_class`.
- The OIDC adapter verifies signature/time plus issuer/audience allowlists before claims are mapped.
- `identity_policy.claim_mapping` controls which claims feed `actor_id`, `issuer`, and role extraction.
- `auth.mode` publishes the active auth lane (`dev` or `oidc` today).
- `auth.identity_sources` publishes the request source expected for that lane:
  - `dev_headers` for local/demo header-derived identity
  - `oidc_jwt` for generic OIDC bearer-token identity
- `auth.issuers_allowed` and `auth.audiences_allowed` publish the active OIDC allowlists.
- `auth.claim_mapping` publishes only the configured claim field names used for `actor_id`, `issuer`, and role extraction.
- `auth.role_mapping_summary` publishes a compact operator view of the active role-map shape (`mapped_sources`, `operator_sources`, `internal_sources`, `user_fallback`) without exposing raw tenant or group topology.
- `auth.current_trust_class` publishes the trust class currently derived for the caller.
- Trust classes remain stable: `anonymous`, `user`, `operator`, `internal`.
- In `public`, `auth.claim_mapping` and `auth.role_mapping_summary` are omitted entirely.
- The gateway injects this identity as `payload.inputs.extensions.gateway_auth` before policy evaluation.
- DECISION records `actor_id`, `trust_class`, `identity_issuer`, `identity_verified`, `identity_source`, and `claims_digest`.

## Context Resolution Gate
- Controlled by `GATEWAY_ENABLE_CONTEXT_RESOLUTION` env var (default OFF).
- When OFF: `declared_refs` stored but not resolved, `artifact.handle` rejected at ingress.
- DECISION records `context_config_digest: "CONTEXT_RESOLUTION_DISABLED"` sentinel.

## Chain-of-Record (v0.9.0)
- DECISION includes `policy_config_digest` (SHA-256 of the policy rules) and `intent_index` (link to originating INTENT).
- PROOF event emitted between DECISION and EXECUTION when `GATEWAY_ENABLE_RELEASE_GUARD` is ON (default). Contains `payload_digest` over the canonical JSON of the full provider release.
- EXECUTION includes `release_digest` matching the preceding PROOF's `payload_digest`.
- Chain: INTENT -> DECISION (intent_index, policy_config_digest) -> PROOF (payload_digest) -> EXECUTION (release_digest).

## Schemas
- `IntentEnvelope` (interface_version=3).
- `ContextSpec` schema `ctxspec.2`.
- `ContextConfig` schema `v1` (config/context.schema.json).
- `CapabilitiesResponse` (schema_version=`gateway.capabilities.v1`, gateway_version, interface_version=3).

## Providers & Models
- OpenAI: uses `OPENAI_CHAT_MODEL_IDS`/`OPENAI_MODEL_IDS`; responses via `OPENAI_RESPONSES_MODEL_IDS` (default `gpt-5.2`).
- Anthropic: `ANTHROPIC_MODEL_IDS` (default `claude-3-haiku-20240307`).
- Ollama: `OLLAMA_MODEL_IDS` or dynamic `/api/tags` from `OLLAMA_BASE_URL`/`OLLAMA_HOST`.

## Limits (Defaults)
- `max_refs=50`, `expand_last_n=10`, `empty_refs_policy=DENY`.
- `allow_execution_refs_for_prompt=true`, `canonical_sort=event_index_asc`, `enforce_scope_bound=true`.
- Handle content fetch: disabled by default; `workbench_max_bytes=512000`, `fetch_timeout_ms=1500`.
- High-risk handle content admit mode defaults to `metadata_only`.
- Queue max: 100. Concurrency ingest=2, embed=1, index=1, llm=1. LLM wall clock 60s.
- Max output tokens: openai/anthropic 8192, ollama 4096.

## Failure Codes / Reasons (observed literals)
- Queue: `queue.full`, `workers.stopped`.
- Ref resolution: `EMPTY_REFS_DENIED`, `REF_NOT_FOUND`, `CROSS_THREAD_REF`, `MAX_REFS_EXCEEDED`.
- Policy: `context.invalid_shape`, `gateway.observer_mode`, `evaluation_error`.
- Execution: `model_unavailable`, `provider.missing_credentials`, `model.unavailable`, `llm.timeout`, `input.invalid`.
- Handle fetch warnings: `HANDLE_CONTENT_FETCH_*` (disabled, kind_denied, too_large, timeout, http_error, content_type, parse_error).
- Admission errors use dbl_ingress constants (string values not defined in this repo).

## Diff Risk (Likely to Change)
- Provider/model lists and defaults (env-driven).
- Limits and queue settings (env/config).
- Policy versions and decision reason codes (policy implementation).
