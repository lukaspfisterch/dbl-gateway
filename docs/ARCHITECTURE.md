# Architecture

The gateway enforces a deterministic boundary between what a caller asks for,
what policy allows, and what actually executes.

Every request passes through a deterministic event chain:

    INTENT  ->  DECISION  ->  PROOF  ->  EXECUTION

Each surface has a single responsibility. No surface can see the internals
of another. The event stream records what happened at every boundary crossing.
The built-in observer UI is a read-only consumer of this stream; it never owns
verification logic or recomputes digests in the browser.

Policy logic is external (dbl-policy). The gateway evaluates and enforces
decisions; it does not define policy rules.

---

## 1. Intent Surface

**Accepts the request. Validates structure. Records what was asked.**

The caller sends an `IntentEnvelope` to `POST /ingress/intent`.
Ingress validates the envelope against the wire contract (version, shape,
identity anchors) and appends an INTENT event to the stream.

The intent surface does not evaluate the request. It does not know whether
the action will be allowed. It only knows whether the envelope is well-formed.

Outputs:
- INTENT event (immutable, append-only)
- HTTP acknowledgement with stream index

Rejects:
- Wrong `interface_version` (must be 3)
- Missing identity anchors (`stream_id`, `lane`, `actor`)
- Malformed payload

## 2. Decision Surface

**Evaluates policy. Produces the normative verdict.**

The decision surface receives the validated intent and delegates to the
policy module via `PolicyPort.decide()`. The gateway never contains policy
decision logic itself -- all rules live in dbl-policy.

Policy sees only authoritative inputs: the intent payload and (when enabled)
resolved governance context. It never sees execution traces, model outputs,
or timing data.

The decision is `ALLOW` or `DENY`. When allowing, the decision also records:

- `permitted_tools` -- which tools the model may invoke
- `enforced_budget` -- token and duration limits
- `assembly_digest` / `context_digest` -- deterministic hashes of the inputs
  that produced this decision
- `policy_config_digest` -- SHA-256 of the policy rules used (computed by the gateway, not the adapter)
- `intent_index` -- index of the originating INTENT event (decision lineage)

The DECISION event is normative. A replayer can verify that the same inputs
produce the same verdict. Everything downstream depends on this event.

Outputs:
- DECISION event (normative, digest-pinned)

Invariants:
- Only DECISION events carry policy authority
- Observational data never enters the policy evaluation
- No EXECUTION may occur without a preceding ALLOW decision

## 3. Context Release Guard (PROOF)

**Captures what will be sent to the provider before execution begins.**

After DECISION(ALLOW) and before the provider call, the gateway emits a
PROOF event containing the `payload_digest` -- a SHA-256 over the canonical
JSON of the full release object (messages, model_id, provider, permitted_tools,
enforced_budget).

This creates an auditable link: the EXECUTION event carries `release_digest`
which must match the PROOF event's `payload_digest`.

The release guard is feature-gated via `GATEWAY_ENABLE_RELEASE_GUARD` (default ON).

Outputs:
- PROOF event (proof_type: `context_release_guard`)

Invariants:
- EXECUTION.release_digest == PROOF.payload_digest
- PROOF is emitted before the provider call, never after

## 4. Execution Surface

**Calls the provider. Enforces tool and budget constraints. Records the result.**

When the decision is ALLOW, the execution surface calls the configured
provider (OpenAI, Anthropic, or Ollama) with the permitted parameters.
Providers are stateless adapters exposing `execute()` and `get_capabilities()`
against a formal `ProviderCapabilities` schema.

Enforcement happens here, not at the provider:
- Tool calls not in `permitted_tools` are blocked (strict mode) or logged (advisory mode)
- `max_tokens` is passed to the provider
- Wall-clock timeout is enforced as `min(runtime_limit, client_max_duration_ms)`

The EXECUTION event records the model output, any tool calls that passed
enforcement, any tool calls that were blocked, resource usage, and
`release_digest` linking back to the PROOF event.

Outputs:
- EXECUTION event (observational, never feeds back into policy)

Invariants:
- Blocked tool calls are recorded, not silently dropped
- Execution output never influences the decision that authorized it
- Provider errors produce an EXECUTION event with error details, not a missing event

---

## Event Stream

All events are appended to a single, totally ordered stream per `stream_id`.
Events are never updated or deleted.

Four event kinds exist:

| Kind | Surface | Role |
|------|---------|------|
| INTENT | Intent | What was asked |
| DECISION | Decision | What was allowed (normative) |
| PROOF | Release Guard | What will be sent to the provider |
| EXECUTION | Execution | What happened (observational) |

Events are linked by `correlation_id`. A single intent produces exactly
one INTENT, one DECISION, and (if allowed) one PROOF and one EXECUTION event.

Chain-of-record lineage:
- DECISION.intent_index links to the originating INTENT event index
- PROOF.payload_digest captures the release payload before execution
- EXECUTION.release_digest references the PROOF event's digest

Digests are SHA-256 over canonical JSON (sorted keys, ASCII-only,
`(",", ":")` separators). This makes event identity deterministic
across implementations.

Observer verification:
- Full-chain verification recomputes `v_digest` server-side from persisted events.
- Decision replay recomputes one normative DECISION digest server-side from stored turn artifacts.
- The browser only triggers these checks and renders the returned match/mismatch state.

---

## Component Ownership

Each component owns specific logic. The gateway never reimplements
functionality that belongs to another component.

| Component | Owns | Gateway may... |
|-----------|------|----------------|
| dbl-core | Canonical JSON, digest computation | call `digest_bytes`, never reimplement |
| dbl-policy | Policy evaluation, governance rules | call `PolicyPort.decide()`, never evaluate rules |
| Providers | LLM execution, capabilities | call `execute()` / `get_capabilities()` via `ProviderProtocol` |
| dbl-ingress | Wire contract parsing, admission | call `parse_intent_envelope`, never parse envelopes |

The pre-commit hook enforces these boundaries. See [HOOKS.md](HOOKS.md).

---

## What the Gateway Does Not Do

- **No conversation history.** The gateway does not assemble threads or infer
  context. Clients declare explicit references; the gateway validates them.
- **No semantic inference.** No embeddings, no similarity search, no RAG.
- **No workflow orchestration.** One intent in, events out. No chaining,
  no retries, no conditional branching.
- **No model selection.** The caller specifies the model. The gateway
  dispatches it.
- **No policy definition.** Policy rules live in dbl-policy. The gateway
  delegates all decisions through `PolicyPort.decide()`.

---

## Why This Model

LLM integrations typically mix policy, execution, and observation into a
single call path. When something goes wrong, there is no record of what
was authorized versus what happened.

The three-surface model separates these concerns:

- **Audit**: every decision is recorded with its inputs and can be replayed.
- **Governance**: policy never sees execution outputs, preventing feedback loops.
- **Enforcement**: tool and budget constraints are applied at a single boundary,
  not scattered across middleware.

The cost is explicitness. Nothing is implicit, nothing is inferred,
nothing happens without an event.

For the theoretical foundation, see the
[Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer)
specification.
