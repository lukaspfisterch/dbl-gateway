# Architecture

The gateway enforces a deterministic boundary between what a caller asks for,
what policy allows, and what actually executes.

Every request passes through three surfaces, in order:

    Intent  ->  Decision  ->  Execution

Each surface has a single responsibility. No surface can see the internals
of another. The event stream records what happened at every boundary crossing.

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

The decision surface receives the validated intent and calls the policy module.
Policy sees only authoritative inputs: the intent payload and (when enabled)
resolved governance context. It never sees execution traces, model outputs,
or timing data.

The decision is `ALLOW` or `DENY`. When allowing, the decision also records:

- `permitted_tools` -- which tools the model may invoke
- `enforced_budget` -- token and duration limits
- `assembly_digest` / `context_digest` -- deterministic hashes of the inputs
  that produced this decision

The DECISION event is normative. A replayer can verify that the same inputs
produce the same verdict. Everything downstream depends on this event.

Outputs:
- DECISION event (normative, digest-pinned)

Invariants:
- Only DECISION events carry policy authority
- Observational data never enters the policy evaluation
- No EXECUTION may occur without a preceding ALLOW decision

## 3. Execution Surface

**Calls the provider. Enforces tool and budget constraints. Records the result.**

When the decision is ALLOW, the execution surface calls the configured
provider (OpenAI, Anthropic, or Ollama) with the permitted parameters.

Enforcement happens here, not at the provider:
- Tool calls not in `permitted_tools` are blocked (strict mode) or logged (advisory mode)
- `max_tokens` is passed to the provider
- Wall-clock timeout is enforced as `min(runtime_limit, client_max_duration_ms)`

The EXECUTION event records the model output, any tool calls that passed
enforcement, any tool calls that were blocked, and resource usage.

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
| DECISION | Decision | What was allowed |
| EXECUTION | Execution | What happened |
| PROOF | (reserved) | Verification artifacts |

Events are linked by `correlation_id`. A single intent produces exactly
one INTENT, one DECISION, and (if allowed) one EXECUTION event.

Digests are SHA-256 over canonical JSON (sorted keys, ASCII-only,
`(",", ":")` separators). This makes event identity deterministic
across implementations.

---

## Component Ownership

Each component owns specific logic. The gateway never reimplements
functionality that belongs to another component.

| Component | Owns | Gateway may... |
|-----------|------|----------------|
| dbl-core | Canonical JSON, digest computation | call `digest_bytes`, never reimplement |
| dbl-policy | Policy evaluation, governance rules | call the policy module, never evaluate rules |
| kl-kernel-logic | Provider abstraction, model dispatch | call `_execute_llm_call`, never call providers directly |
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
