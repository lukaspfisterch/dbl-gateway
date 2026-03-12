# Changelog

## v0.8.0 — Capabilities Self-Description

**Axis 3: `GET /capabilities` becomes self-describing.**
- Response now includes wire contract info: `intents`, `tool_surface`, `budget` alongside runtime `providers`/`surfaces`.
- Three version layers separated: `schema_version` (response shape), `interface_version` (wire contract), `gateway_version` (software release).
- `generate_capabilities.py` rewritten as pure runtime snapshot — zero own logic, calls `get_capabilities()` and strips dynamic fields.
- `docs/capabilities.gateway.v3.json` is now an exact snapshot of the runtime contract (minus providers).
- Single source of truth: a client can discover everything from one `GET /capabilities` call.

## v0.7.1 — Provider Contract Hardening

**Axis 2: Formal provider capabilities contract.**
- New `ProviderCapabilities` Pydantic schema with `ProviderFeatures`, `ProviderLimits`, and `ProviderProtocol`.
- Every provider (anthropic, openai, ollama) exports `get_capabilities()` — all fields required, no silent defaults.
- `execution_mode: Literal["http", "local", "rpc"]` declares transport for future provider diversity.
- `PROVIDER_MODULES` registry in `providers/__init__.py` — single source of truth for name-to-module mapping.
- `capabilities.py` refactored from owner to aggregator — reads from providers instead of hardcoding.
- `execution_adapter_kl.py` uses shared registry instead of duplicated mapping.
- Contract conformance tests: every registered provider validated against `ProviderCapabilities` schema.

## v0.7.0 — Policy Externalization

**Axis 1: Zero policy decision logic in gateway.**
- Moved `artifact.handle` metadata-only ALLOW rule from hardcoded bypass in `app.py` to `DblPolicyAdapter` in the policy layer.
- Gateway now delegates all decisions through `PolicyPort.decide()`, including metadata-only intents.
- `DblPolicyAdapter` defines `_METADATA_ONLY_INTENTS` for intent types that bypass full policy evaluation.
- Success criterion met: dbl-policy can be replaced without changing `app.py`.

## v0.6.0 — Tool Gating, Budget Constraints & Context Gate

**Breaking: Wire Contract v3**
- `interface_version` bumped from 2 to 3. v2 clients are rejected at ingress.

**Feature Gate: Context Resolution**
- Context resolution and Workbench handle fetch are gated behind `GATEWAY_ENABLE_CONTEXT_RESOLUTION` (default OFF).
- When OFF, `declared_refs` are stored in the INTENT event for audit but not resolved.
- DECISION records `context_config_digest: "CONTEXT_RESOLUTION_DISABLED"` sentinel.
- `artifact.handle` intents are rejected at ingress when gate is OFF.

**Tool Gating (Operation 2)**
- New INTENT fields: `declared_tools` (list of tool name strings), `tool_scope` (`"strict"` or `"advisory"`).
- Tool names validated against `^[a-z][a-z0-9_.]{0,63}$`, max 20 per request.
- DECISION records `permitted_tools`, `tool_scope_enforced`, `tools_denied`, `tools_denied_reason`.
- EXECUTION records `tool_calls` (allowed) and `tool_blocked` (with reason) for replay determinism.
- Strict scope blocks undeclared tools; advisory scope logs and allows.

**Budget Constraint (Operation 3)**
- New INTENT field: `budget` with `max_tokens` (1-1000000) and `max_duration_ms` (1000-300000), integer-only.
- `effective_timeout = min(runtime_wall_clock_ms, client_max_duration_ms)`.
- `max_tokens` passed through to provider call; `max_duration_ms` enforces full execution envelope.
- DECISION records `enforced_budget` with `max_tokens`, `max_duration_ms`, `source`.
- EXECUTION records `usage` with `duration_ms`.

**Provider Changes**
- All providers (OpenAI, Anthropic, Ollama) return `NormalizedResponse` (text + tool_calls).
- Provider-agnostic tool call format: `{"tool_name": str, "arguments": dict}`.
- `max_tokens` passed from enforced budget to provider call.

**Normative Decision**
- `DecisionNormative` extended with `permitted_tools` and `enforced_budget`.
- Decision digests cover tool and budget fields for replay verification.

## v0.5.2 — Capabilities Inventory
- Added client-facing capabilities inventory in `docs/capabilities.gateway.v1.json` and `docs/CAPABILITIES.md`.
- Documented stable vs variable capability surface and default limits.

## v0.5.1 — Consistency & Context Gating
- Gate auto-context expansion behind config flag (off by default).
- Align context digest semantics in docs (assembly digest).

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
