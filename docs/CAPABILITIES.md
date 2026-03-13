# Gateway Capabilities

Client-visible capabilities. Internal architecture is not described
unless it affects wire behavior.

## Stable vs Variable
- Stable: interface_version=3, ContextSpec schema ctxspec.2, ContextConfig schema v1, endpoint paths, tool_scope semantics, budget field schema, event chain (INTENT -> DECISION -> PROOF -> EXECUTION).
- Variable: provider list, model list, defaults, limits, policy version, and some failure codes may change with config/env.

## API Endpoints
- `GET /healthz` — health check. Response `{status}`.
- `GET /capabilities` — providers, models, and surfaces. Response `CapabilitiesResponse` (schema_version, gateway_version, interface_version=3).
- `POST /ingress/intent` — ingest `IntentEnvelope` (interface_version=3). Returns accepted/queued + correlation_id + index.
- `GET /snapshot` — event snapshot (limit/offset/stream_id/lane). Returns `SnapshotResponse`.
- `GET /threads/{thread_id}/timeline` — grouped by turn; optionally include payloads.
- `GET /tail` — SSE stream of `EventRecord` envelopes.
- `GET /status` — projected runner state `{phase, runner_status, t_index, note}`.
- `POST /execution/event` — submit external execution result (only if exec_mode=external).

## Observer UI Endpoints
- `GET /ui/` — built-in single-file observer UI.
- `GET /ui/tail` — auth-free SSE stream for browser `EventSource`.
- `GET /ui/capabilities` — auth-free observer proxy for capabilities.
- `GET /ui/snapshot` — auth-free observer proxy for the latest `v_digest` and event count.
- `POST /ui/intent` — auth-free observer proxy for manual intent submission from the UI.
- `GET /ui/verify-chain` — auth-free full-chain `v_digest` recomputation and match/mismatch report.
- `GET /ui/replay?thread_id=...&turn_id=...` — auth-free decision replay for one turn.
- `GET /ui/demo/status` — auth-free status for the integrated demo controller.
- `POST /ui/demo/start` — auth-free start trigger for the integrated demo controller.

These `/ui/*` routes are read-only observer infrastructure. Verification logic
and demo orchestration remain server-side; the browser only consumes events and
returned observer status/results.

## Intents
- `chat.message`: accepts `message` plus optional `inputs`, `declared_refs`, `context_mode/context_n`, `declared_tools`, `tool_scope`, `budget`.
- `artifact.handle`: metadata-only, does not trigger decision by default; content fetch is gated. Rejected when `GATEWAY_ENABLE_CONTEXT_RESOLUTION` is OFF.

## Declared Refs & Admission Rules
- `declared_refs` must be a list of `{ref_type, ref_id, version?}`.
- Max refs: 50. Empty refs policy: DENY (default).
- Scope bound enforced by thread_id.
- Content admission:
  - INTENT events -> governance (no content by default unless artifact.handle with allowed fetch).
  - EXECUTION refs -> execution_only if `allow_execution_refs_for_prompt=true`.
  - `artifact.handle` content fetch: only when enabled + kind allowlisted.

## Tool Gating
- `declared_tools`: list of tool name strings (max 20), validated against `^[a-z][a-z0-9_.]{0,63}$`.
- `tool_scope`: `"strict"` (block undeclared) or `"advisory"` (log and allow). Default `"strict"` when `declared_tools` present.
- DECISION records `permitted_tools`, `tool_scope_enforced`.
- EXECUTION records `tool_calls` (allowed) and `tool_blocked` (blocked with reason).

## Budget Constraint
- `budget.max_tokens`: integer 1-1000000, passed to provider call.
- `budget.max_duration_ms`: integer 1000-300000, enforces execution wall clock.
- `effective_timeout = min(runtime_ms, client_ms)`.
- DECISION records `enforced_budget` with `source` indicating clamping.
- EXECUTION records `usage.duration_ms`.

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
