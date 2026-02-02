# Changelog

## Unreleased (local; will be cleaned before next push)
- **LLM Max Tokens**: Allow `OPENAI_MAX_TOKENS` and `ANTHROPIC_MAX_TOKENS` to override provider defaults.
- **OpenAI Param Routing**: Use responses API for `gpt-5*` and switch to `max_completion_tokens` for newer chat models that reject `max_tokens`.

## v0.5.0 — Controlled Multi-User Execution & Job-Oriented Runtime
- **Typed Jobs**: Internal job model for request execution with per-type queues and status reporting.
- **Concurrency Gates**: Per-job-type semaphores (ingest/embed/index/LLM) with strict LLM provider-call gating.
- **Fair LLM Scheduling**: Per-user round robin scheduling for `chat.message` workloads.
- **Timeouts & Backpressure**: LLM wall-clock limit and per-type queue max with 503 on overload.
- **Status Surface**: `/status` now includes queue sizes, active counts, and per-user LLM queue position.
- **Decision Digests**: `assembly_digest` is always recorded; `context_digest` is null on DENY; evaluation errors emit `error_ref` pointing to a PROOF artifact.

## v0.4.3 — Docker Config Fix
- **Docker Fix**: Set `DBL_GATEWAY_CONTEXT_CONFIG` environment variable in Dockerfile to resolve config path issue in containerized deployments.

## v0.4.2 — Observer Mode & UX
- **Observer Mode**: Gateway starts gracefully without policy/providers, logging instructions instead of crashing.
- **Improved UX**: Refined README with clearer Docker and environment variable sections.
- **Version Bump**: Prepared for PyPI and Docker Hub release.

## v0.4.1 — Context, Performance & Ollama
 
**Capabilities & Performance**
- **Non-blocking Capabilities**: `get_capabilities` is now async/threaded with TTL caching (60s), preventing event loop freeze during provider discovery.
- **Ollama Integration**: Full support for remote Ollama instances via `OLLAMA_HOST` (e.g., `http://10.x.x.x:11434`). Includes automatic discovery and model execution.
- **Resilient Discovery**: Timeout handling improved (cache + short network timeout) to ensure the gateway remains "snappy" even if providers are unreachable.
 
**Context Injection**
- **Declarative `context_mode`**: New parameter `context_mode="first_plus_last_n"` (default) automatically assembles thread history into `declared_refs`.
- **Deterministic Assembly**: Gateway expands context policies into explicit `declared_refs`, preserving the "Audit = Replay" invariant.
- **Model Messages**: Execution pipeline now passes structured `model_messages` (System + User + Context) to providers instead of flattening to string.
 
**Contract & Guards**
- **Transform Hardening**: Fixed a contract violation where `transform.target` could be empty. All transforms now enforce stable, non-empty targets.
- **Env Hygiene**: Consolidated Ollama configuration to `OLLAMA_HOST` (discovery) and strict audit logging.


## v0.4.0 — Safe Context

**Context System (DBL-compliant)**

- **declared_refs**: Clients can now explicitly declare event references as context via `IntentEnvelope.payload.declared_refs`.
- **Ref resolution**: Gateway validates and resolves refs against thread events with scope-bound, existence, and limit checks.
- **I_context / O_context split**: INTENT events are admitted for governance (`admitted_for: "governance"`), EXECUTION events are `execution_only` and excluded from policy input.
- **Normalization materialized**: Every boundary transformation is recorded in `context_spec.retrieval.normalization`.
- **Config as code**: Context behavior controlled by `config/context.json` with computed `config_digest`.
- **DECISION boundary block**: Every DECISION event now includes `boundary.context_config_digest` for replay verification.

**Wire Contract**

- Added `declared_refs` field to `IntentEnvelope.payload` (optional, list of `DeclaredRef`).
- New typed errors: `REF_NOT_FOUND`, `CROSS_THREAD_REF`, `MAX_REFS_EXCEEDED`.
- DECISION payload includes `boundary` block with `context_config_digest` and `boundary_version`.

**Invariants Guaranteed**

- Observation excluded from dom(G) (Claim 4)
- Canonical ordering (event_index ascending)
- Scope-bound refs (same thread_id)
- Replay recompute equality

**Explicit Non-Goals**

- No auto-expansion of thread history
- No LLM-based summarization
- No config hot reload

## v0.3.2
- Migrated reference dependency from `dbl-reference` to `ensdg`.
- Updated documentation and CI workflows to reflect `ensdg` branding.
- Bumped project version to synchronize dependencies.

## v0.3.1
- Added `dbl-chat-client` to repository landscape.
- Enabled CORS for local development (port 5173).
- Overhauled README for an infrastructure-focused tone and added project badges.
- Added minimal Dockerfile for service deployment.

## v0.3.0
- Identity anchors required on every INTENT (`thread_id`, `turn_id`, optional `parent_turn_id`).
- Deterministic context and decision digests recorded on events.
- Offline decision replay using stored context artifacts and policy identity.
- Thread timeline endpoint exposes turn ordering and digests.
- SQLite store hardened with explicit JSON handling and payload validation.
