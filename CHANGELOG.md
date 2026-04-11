# Changelog

## v0.9.18 — Tool Trust Classes

**Boundary tool policy now resolves against `exposure_mode x trust_class`, not exposure alone.**
- Reshape `tool_policy` into versioned `families + matrix`, with deterministic trust classes `anonymous`, `user`, `operator`, and `internal`.
- Derive trust class from the existing actor/auth model, persist it in `payload.inputs.extensions.gateway_auth`, and feed it into policy-visible `gateway_tool_policy` metadata.
- Move family resolution onto the boundary artifact, reject unknown tools with stable reason `tool.unknown_family`, and keep `tool.no_mix.exec_like` as the structural invariant before trust-based family gating.
- Extend DECISION audit fields with `denied_tool_families`, expose `trust_class_current` and the full exposure/trust allow-matrix via `/capabilities`, and add focused regression coverage for the new trust-dependent behavior.

## v0.9.17 — Boundary Tool Families

**Tool-family governance now lives in the versioned boundary config and enters the decision line explicitly.**
- Add `tool_policy` to boundary config artifacts so `public`, `operator`, and `demo` each declare their allowed tool families as part of the hashed boundary contract.
- Compute deterministic `declared_tool_families`, `allowed_tool_families`, and `permitted_tool_families`, inject them into policy-visible `payload.inputs.extensions.gateway_tool_policy`, and record them in normative DECISION payloads.
- Apply family allowlists before no-mix shaping, surface stable denial reason `tool.family_not_allowed`, and keep `tool.no_mix.exec_like` as the structural invariant on the remaining tool set.
- Publish current and per-exposure tool-family allowlists through `GET /capabilities`, and add focused regression coverage for config parsing, policy input enrichment, decision payloads, and digest stability.

## v0.9.16 — Tool Semantics And Concise Startup Audit

**Tool gating now has a first semantic no-mix rule, and startup config audit is reduced to relevant runtime signals.**
- Add semantic tool families to capability discovery and publish the first deterministic `no_mix` rule: exec-like tools are denied when mixed with any other tool family.
- Keep the rule in boundary/runtime logic, not as a heuristic score, and surface stable denial reason `tool.no_mix.exec_like`.
- Replace the verbose startup env dump with a concise runtime summary covering policy, boundary mode, context-resolution state, exec mode, auth mode, DB status, and active providers.
- Add focused regression tests for semantic tool gating, capability metadata, and the concise config-audit summary.

## v0.9.15 — Explicit High-Risk Context Mode

**Handle-derived context is no longer implicitly eligible for model context once fetch is enabled.**
- Add `context.handle_content_fetch.high_risk_context_admit_mode` with explicit modes `disabled`, `metadata_only`, and `model_context`.
- Default the runtime to `metadata_only`, so handle refs remain resolvable as metadata without automatically lifting fetched content into prompt context.
- Require explicit `model_context` opt-in before Workbench-fetched handle content can enter `assembled_context.model_messages`.
- Expose the active high-risk context mode in discovery metadata and add regression coverage for metadata-only vs model-context behavior.

## v0.9.14 — High-Risk Context Discovery

**High-risk context intents are now advertised only where the active boundary/runtime can actually admit them.**
- Filter `GET /capabilities` intent discovery by the active boundary profile so `public` no longer advertises `artifact.handle`.
- Add intent metadata in capabilities describing current admission and risk class, keeping high-risk context visible to trusted operators without teaching it to public clients.
- Tighten `GET /intent-template` so example envelopes are only emitted for intents currently admitted by the active boundary/runtime configuration.
- Add focused tests for public capability minimization and operator/demo high-risk context discovery.

## v0.9.13 — Deterministic Public Admission

**Public exposure can now deny expensive or high-risk intent shapes before any `INTENT` is written.**
- Extend boundary config artifacts with an explicit `admission.public` block so public admission limits live in the versioned boundary contract instead of ad hoc runtime logic.
- Add deterministic public-mode rejections for `artifact.handle`, non-empty `declared_refs`, excessive `declared_tools`, and over-limit budgets.
- Keep these checks input- and config-derived only; no queue/load/runtime-state feedback is introduced into admission.
- Add focused regression coverage proving public rejections append no `INTENT` while operator mode still admits the same shapes.

## v0.9.12 — Boundary Exposure Modes

**Surface exposure is now controlled by a versioned boundary configuration instead of being implicitly demo-open.**
- Add boundary config artifacts in `config/` with explicit `exposure_mode` and `surface_rules`.
- Introduce central surface gating so exposure decisions are enforced in one place instead of route-by-route drift.
- Default runtime exposure now becomes `operator`: runtime and discovery surfaces stay available, but `/ui/*` remains demo-only.
- Filter `GET /capabilities` and `GET /surfaces` by the active boundary exposure mode so hidden surfaces are not advertised.
- Demo mode now selects the demo boundary config explicitly, keeping the existing zero-config demo flow intact.
- Add focused tests for public/operator/demo route exposure and capability-surface leak prevention.

## v0.9.11 — Replay Validation Notes

**Replay validation is now documented as an optional reference-runtime artifact.**
- Restore gateway-enriched DECISION fields during replay so normative digests reproduce exactly under fixed inputs and policy configuration.
- Add `docs/EMPIRICAL_VALIDATION.md` with the replay bench flow, result table, and reproduction steps.
- Refine replay documentation and README positioning so runtime users can ignore validation details unless they need the architectural background.

## v0.9.10 — Opaque Policy Fallback

**The observer now degrades gracefully when a loaded policy has no structural `describe()` surface.**
- Keep `GET /ui/policy-structure` usable for plain `dbl-policy` objects that do not expose `describe()`.
- Return an `opaque_policy` tree with policy id, version, module, class, and digest instead of hard `Unavailable`.
- Preserve the richer structural tree path for policies that do expose `describe()`.
- Align observer docs and discovery metadata so `/ui/policy-structure` is listed in capability surfaces.
- Add observer UI coverage for the opaque-policy fallback path.

## v0.9.9 — Policy Tree Inspector

**The observer now includes a structural policy view for DECISION events.**
- Add `GET /ui/policy-structure` as an auth-free observer route.
- Add a `Policy` tab to the bottom inspector for DECISION events.
- Render the current policy as a tree with structural paths, labels, metadata,
  and digest.
- Add a togglable `70/30` and `30/70` inspector layout for tree vs detail.
- Add observer UI tests for policy structure availability and HTML tab presence.

## v0.9.8 — Demo Replay Default

**Zero-config demo mode now defaults to replayable turns.**
- When `GATEWAY_DEMO_MODE=1` and `GATEWAY_ENABLE_CONTEXT_RESOLUTION` is unset,
  the gateway now enables context resolution automatically.
- This keeps the existing production feature gate intact while making the
  demo path replay-ready by default.
- Explicit `GATEWAY_ENABLE_CONTEXT_RESOLUTION=0/false/no` still wins and is not
  overridden.
- Added tests covering both the default-on and explicit-off demo cases.

## v0.9.7 — Policy Contract Alignment

**The gateway now aligns with `dbl-policy 0.3.x` as a contract-first policy layer.**
- Update the `dbl-policy` dependency to `>=0.3.0,<0.4.0`.
- Route policy evaluation through the policy contract's safe entrypoint instead
  of adapter-local shape enforcement.
- Preserve structured JSON-safe authoritative inputs at the policy boundary
  instead of reducing them to scalar-only values.
- Replace eager adapter package imports with lazy imports, reducing import-time
  coupling and unblocking lightweight test collection.
- Update gateway tests and policy stubs to match the `dbl-policy 0.3.0`
  contract surface.

## v0.9.6 — Zero-Config Stub Demo

**The gateway can now run a full governance demo without any API keys or external dependencies.**
- New stub provider (`src/dbl_gateway/providers/stub.py`) with two modes:
  - `echo` (default) — mirrors the user message back, predictable for contract testing.
  - `scenario` — rotates through canned governance-demo responses, deterministic by turn index.
- `GATEWAY_DEMO_MODE=1` activates zero-config operation:
  - Stub provider auto-registers (no API keys checked).
  - Policy defaults to `dbl_policy.allow_all` when none configured.
  - SQLite trail defaults to `data/demo-trail.sqlite`.
  - Inline decision processing enabled (no work queue needed).
  - Startup log prints the browser entry path.
- Stub provider follows the existing `ProviderCapabilities` contract (`requires_api_key: False`, `execution_mode: "local"`).
- Capabilities discovery extended: stub models appear in `/capabilities` and `/ui/capabilities` when demo mode is active.
- Provider resolution extended: `resolve_provider()` and `_allowed_model_ids()` include stub models in demo mode.
- `compose.yaml` extended with a `demo` profile for `docker compose --profile demo up --build`.
- Explicit registration pattern: stub is registered in `app.py` startup, not via import side-effect in `__init__.py`.
- 11 new tests covering stub capabilities contract, echo mode, scenario mode, demo mode activation, and demo-off isolation.

## v0.9.5 — Docker Demo Start

**Observer demo runtime now has a clean containerized start path.**
- Added `.env.example` as the minimal local template for Docker/local startup with one active provider or local Ollama.
- Added `compose.yaml` for a single-command `docker compose up --build` entry path.
- Added `run_demo.ps1` as a Windows convenience launcher: start container, wait briefly, open `/ui/`.
- Fixed Python packaging so `dbl_gateway/static/index.html` is included in built wheels and in Docker-installed packages; `/ui/` now works from the container image.
- Startup logging now emits an explicit browser-facing observer URL (`http://localhost:8010/ui/`) even when the server binds to `0.0.0.0`.
- README refocused the top-level entry path around the one-command Docker start and moved the observer screenshot directly under that flow.

## v0.9.4 — Observer Runtime Demo

**Observer runtime becomes a usable demo/playground, not just a viewer.**
- Explicit discovery surfaces added:
  - `GET /surfaces` returns the callable surface catalog with path/method/auth/plane metadata.
  - `GET /capabilities` now includes `surface_catalog` alongside the compact `surfaces` booleans.
  - `GET /intent-template` returns valid example envelopes for self-teaching ingress discovery.
- Integrated `Demo Agent` control in the built-in observer UI:
  - `GET /ui/demo/status`
  - `POST /ui/demo/start`
- Shared demo scenario module introduced so the browser-triggered controller and CLI demo script use the same turn sequence.
- Bottom inspector added to the event observer with `Event`, `Turn`, and `Raw` views.
- Manual intent panel added to the observer UI:
  - `POST /ui/intent` added as an auth-free observer proxy for valid `IntentEnvelope` submission
  - generated `curl` and PowerShell snippets stay valid for direct `/ingress/intent` use
- Demo turn tracking fixed to check the concrete thread/turn timeline instead of a bounded global snapshot window, preventing false timeout failures on larger trails.
- Observer SSE polling tuned for smoother turn-by-turn arrival in the UI.
- Request logging now suppresses high-frequency observer polling routes by default to keep terminal output readable during demos.
- Observer UI tests expanded for `/ui/intent` and for integrated demo success with a trail containing more than 100 preexisting events.

## v0.9.3 — Active Verification

**Phase 3: Browser-triggered verification on top of the semantic observer panels.**
- `GET /ui/verify-chain` added as an auth-free observer route: recomputes the full `v_digest` chain from persisted events and compares it to the rolling store state.
- `GET /ui/replay` added as an auth-free observer route: replays a single turn decision by `thread_id` + `turn_id` and returns digest match/mismatch details.
- Observer UI Verify panel now supports active verification:
  - `Verify Chain` button shows `VALID` / `MISMATCH` for the full chain.
  - Selecting a `DECISION` in the inspector triggers server-side replay and shows per-turn verification status.
  - Mismatch output includes stored vs recomputed digest values for triage.
- Observer UI layout extended beyond the semantic panels:
  - event stream selection opens a bottom inspector with `Event`, `Turn`, and `Raw` views.
- Replay path aligned with runtime reality:
  - replay uses the gateway's configured policy adapter, not a fresh default adapter.
  - replay digest recomputation now includes `intent_index`, matching stored normative DECISION digests.
- Store adapter/port extended so UI verification can call `recompute_v_digest()` through the app state abstraction.
- Observer UI tests expanded with auth-free coverage for chain verification, successful replay, and missing-turn replay failure.

## v0.9.2 — Semantic Panels

**Phase 2: Three sidebar panels alongside the event stream.**
- Two-column grid layout: 280px sidebar + event stream.
- **Agent Activity** panel — per-turn phase tracking from SSE, last event per kind, turn count.
- **Capabilities** panel — one-time fetch from `/ui/capabilities`, shows gateway version, providers, model health, surfaces.
- **Verify** panel — periodic (5s) + manual refresh from `/ui/snapshot`, shows `v_digest` (truncated with tooltip), event count, last DECISION metadata.
- `GET /ui/capabilities` — auth-free proxy with `Cache-Control: max-age=30`.
- `GET /ui/snapshot` — auth-free proxy (limit capped at 100).
- Both new routes excluded from OpenAPI schema.
- 3 new test classes: capabilities proxy, snapshot proxy, comprehensive OpenAPI exclusion check for all `/ui/*` routes.

## v0.9.1 — Event Observer UI

**Phase 1: Pure event observer served by the gateway itself.**
- `GET /ui` serves a single-file observer page (no frameworks, no dependencies).
- `GET /ui/tail` — auth-free SSE proxy for browser EventSource (read-only infrastructure).
- Root redirect: `GET /` -> `/ui/`.
- SSE generator extracted into shared `_sse_event_stream()` helper, used by both `/tail` and `/ui/tail`.
- Turn grouping by `correlation_id` with visual separators.
- Delta-time column shows latency between events in the same turn.
- Sticky header with stream name and event count.
- 6 new tests covering proxy auth bypass, SSE format, lane filtering, header contract, OpenAPI exclusion, and HTML serving.

## v0.9.0 — Substrate Axiom Enforcement

**Axiom-level runtime enforcement in the gateway core.**
- Enforced A1 (append-only stream semantics) and A5 (turn-local order: DECISION before EXECUTION) directly in persistence/runtime paths.
- Enforced A3/A4 governance-input purity before policy evaluation: policy inputs are validated against the authoritative key set and exclude observational fields.
- Updated invariant documentation to align implementation-level guarantees with substrate axioms.
- Refreshed tests and OpenAPI snapshot for the enforced behavior.

## v0.8.1 — Chain-of-Record / Observability

**Axis 4: Decision lineage, context release guard, policy config digest.**
- `policy_config_digest` added to `DecisionResult` and normative DECISION payload — SHA256 of policy rules, computed by gateway.
- `intent_index` in DECISION payload links each decision back to its originating INTENT event index.
- Context Release Guard: PROOF event emitted between DECISION and EXECUTION, carrying `payload_digest` over the full provider release (messages + model + limits + tools).
- EXECUTION payload includes `release_digest` referencing the PROOF event's `payload_digest` for lineage verification.
- `compute_release_digest` helper in `digest.py` — deterministic SHA256 over canonical JSON of the release object.
- Feature-gated via `GATEWAY_ENABLE_RELEASE_GUARD` env var (default ON).
- `DecisionNormative` and `PolicyIdent` contracts extended for `policy_config_digest` and `intent_index`.

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
