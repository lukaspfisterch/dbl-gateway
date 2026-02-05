# Gateway Capabilities

Generated: `2026-02-05T20:29:10.227156+00:00`

This document lists client-visible capabilities only. Internal architecture is not described unless it affects behavior.

## Stable vs Variable
- Stable: interface_version=2, ContextSpec schema ctxspec.2, ContextConfig schema v1, endpoint paths.
- Variable: provider list, model list, defaults, limits, policy version, and some failure codes may change with config/env.

## API Endpoints
- `GET /healthz` — health check. Response `{status}`.
- `GET /capabilities` — providers, models, and surfaces. Response `CapabilitiesResponse` (interface_version=2).
- `POST /ingress/intent` — ingest `IntentEnvelope` (interface_version=2). Returns accepted/queued + correlation_id + index.
- `GET /snapshot` — event snapshot (limit/offset/stream_id/lane). Returns `SnapshotResponse`.
- `GET /threads/{thread_id}/timeline` — grouped by turn; optionally include payloads.
- `GET /tail` — SSE stream of `EventRecord` envelopes.
- `GET /status` — projected runner state `{phase, runner_status, t_index, note}`.
- `POST /execution/event` — submit external execution result (only if exec_mode=external).

## Intents
- `chat.message`: accepts `message` plus optional `inputs`, `declared_refs`, `context_mode/context_n`.
- `artifact.handle`: metadata-only, does not trigger decision by default; content fetch is gated.

## Declared Refs & Admission Rules
- `declared_refs` must be a list of `{ref_type, ref_id, version?}`.
- Max refs: 50. Empty refs policy: DENY (default).
- Scope bound enforced by thread_id.
- Content admission:
  - INTENT events -> governance (no content by default unless artifact.handle with allowed fetch).
  - EXECUTION refs -> execution_only if `allow_execution_refs_for_prompt=true`.
  - `artifact.handle` content fetch: only when enabled + kind allowlisted.

## Schemas
- `IntentEnvelope` (interface_version=2).
- `ContextSpec` schema `ctxspec.2`.
- `ContextConfig` schema `v1` (config/context.schema.json).
- `CapabilitiesResponse` (interface_version=2).

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
