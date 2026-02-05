# DBL Gateway

![Tests](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/github/license/lukaspfisterch/dbl-gateway)
[![PyPI version](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)

**Current version:** 0.5.2  
This README reflects the 0.5.x execution and runtime model.

Client-facing capabilities are defined in `docs/capabilities.gateway.v1.json`.

DBL Gateway is a deterministic execution boundary for LLM calls.

It accepts explicitly declared intents, applies policy decisions, executes permitted calls, and records the result as an auditable, replayable event stream.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

This is **not**:
- a RAG pipeline
- a workflow engine
- a UI product

The gateway does not decide what to do. It decides whether an explicitly declared action may execute.

The gateway does not assemble conversation history, infer relevance, or manage memory. It only accepts explicitly declared references and enforces their admissibility.

## What changed in 0.5.x

- Job runtime governance (queues, concurrency limits, wall-clock timeouts).
- Formalized scheduling without adding workflow semantics.
- Stabilized decision digests for replay and audit.
- Expanded runtime observability for job admission and execution gating.

## Supported Providers (v0.5.x)

The gateway supports multiple providers through a unified execution contract.

Currently supported:
- **OpenAI** (cloud)
- **Anthropic** (cloud)
- **Ollama** (local or remote)

Providers are configured via environment variables and exposed at runtime through capabilities introspection.

---

## Interaction Model

Every accepted request follows the same event sequence:

1. **INTENT**: explicit request with identity anchors (`thread_id`, `turn_id`)
2. **DECISION**: policy outcome (ALLOW or DENY)
3. **EXECUTION**: provider call and result (only when ALLOW)
4. **OBSERVATION**: read-only access via snapshot or tail

Only DECISION events are normative. EXECUTION events are observational and never influence policy.

No step is implicit. Every event is linked via a stable `correlation_id`.

---

## Design Principles

- **Explicit boundaries**: separation between admission, policy, and execution
- **Append-only records**: immutable event trail for audit and replay
- **No hidden state**: no heuristics, no implicit memory, no semantic inference
- **Observer-safe**: clients may project state, but cannot affect policy, execution, or ordering

---

## Reference Resolution (explicit only)

The gateway does not generate or interpret context.

It supports explicit references to prior events so downstream clients can build multi-turn interactions without implicit history.

### declared_refs

Clients may reference prior events via `IntentEnvelope.payload.declared_refs`:

```json
{
  "declared_refs": [
    {"ref_type": "event", "ref_id": "correlation-id-1"},
    {"ref_type": "event", "ref_id": "turn-id-2"}
  ]
}
```

The gateway validates and resolves these references and makes them available to the execution pipeline as deterministic, scope-bound inputs.

The gateway never infers conversational context. All references are explicit and must be scope-bound to the thread.

`context_digest` identifies the resolved context assembly (context specification + referenced artifacts). It is not a provider payload digest and does not claim to represent the exact request sent to a model. A provider-specific “final payload digest” is intentionally out of scope for v0.5.x.

### Workbench Handle Fetch (Optional)

For `artifact.handle` references, the gateway can optionally fetch content from a
Workbench resolver and admit it into **model context** for `chat.message`.
This is disabled by default and must be explicitly enabled in config/env.

Guardrails:
- Resolver base URL is config-driven and must be http/https.
- Content-Type must be `text/plain`.
- Enforced timeout and max bytes.
- Allowlist of artifact kinds.

Env overrides:
- `ALLOW_HANDLE_CONTENT_FETCH`
- `WORKBENCH_RESOLVER_URL`
- `WORKBENCH_AUTH_BEARER_TOKEN`
- `WORKBENCH_FETCH_TIMEOUT_MS`
- `WORKBENCH_MAX_BYTES`
- `WORKBENCH_ADMIT_KINDS`

### I_context / O_context split

| Type | Admitted For | Policy Access |
|------|--------------|---------------|
| INTENT events | `governance` | Yes |
| EXECUTION events | `execution_only` | No |

This ensures observational outputs never influence governance decisions.

See [docs/CONTEXT.md](docs/CONTEXT.md) for the full specification.

---

## Repository Landscape

The gateway is part of a small toolchain:

> **Looking for the full end-to-end demo?**  
> See [dbl-stack](https://github.com/lukaspfisterch/dbl-stack) for a one-command setup including UI and observer.

### dbl-gateway (this repository)
Authoritative execution boundary and event log. The gateway is authoritative for execution, not interpretation.
- Accepts explicit intents.
- Applies policy.
- Executes provider calls.
- Emits canonical events (`INTENT`, `DECISION`, `EXECUTION`).
- Persists an append-only event trail.
- Exposes read-only observation surfaces (`/snapshot`, `/tail`).

### [dbl-observer](https://github.com/lukaspfisterch/dbl-observer)
Observer UI for rendering timelines, audits, and decision views. Does not evaluate policy or store authoritative state.

### [dbl-chat-client](https://github.com/lukaspfisterch/dbl-chat-client)
Pure event-projection UI. Real-time visualization of the gateway event stream and identity anchor management.

---

## Installation

### Local install
```bash
pip install .
```

### Docker (quick start)

Observer mode (no policy, no providers required):

```bash
docker run -p 8010:8010 dbl-gateway
```

Execution-enabled:

```bash
docker run --rm -p 8010:8010 \
  -e OPENAI_API_KEY="sk-..." \
  -e DBL_GATEWAY_POLICY_MODULE="dbl_policy.allow_all" \
  -e DBL_GATEWAY_POLICY_OBJECT="policy" \
  lukaspfister/dbl-gateway:0.5.1
```

---

## Running the Gateway

### Start command
```bash
dbl-gateway serve --host 127.0.0.1 --port 8010
```

### Environment variables

#### Required for execution
| Variable | Description |
|---|---|
| DBL_GATEWAY_POLICY_MODULE | Policy module path (e.g. `dbl_policy.allow_all`) |
| OPENAI_API_KEY | OpenAI API key (or configure another provider) |

#### Model configuration

```bash
# OpenAI (comma-separated)
OPENAI_API_KEY="sk-..."
OPENAI_CHAT_MODEL_IDS="gpt-5.2,gpt-4.1,gpt-4o-mini"

# Anthropic
ANTHROPIC_API_KEY="sk-ant-..."
ANTHROPIC_MODEL_IDS="claude-sonnet-4-20250514,claude-3-5-sonnet-20241022,claude-3-haiku-20240307"

# Ollama
OLLAMA_HOST="http://localhost:11434"
OLLAMA_MODEL_IDS="qwen2.5-coder:7b,llama3.2:latest,deepseek-r1:8b"
```

#### Other options
| Variable | Description |
|---|---|
| DBL_GATEWAY_POLICY_OBJECT | Policy object name (default: `POLICY`) |
| OPENAI_BASE_URL | Custom OpenAI-compatible endpoint |

#### Job runtime (v0.5.x)
| Variable | Description |
|---|---|
| DBL_JOB_QUEUE_MAX | Max queued jobs per type (default: 100) |
| DBL_JOB_CONCURRENCY_INGEST | Max concurrent `case.ingest` (default: 2) |
| DBL_JOB_CONCURRENCY_EMBED | Max concurrent `case.embed` (default: 1) |
| DBL_JOB_CONCURRENCY_INDEX | Max concurrent `case.index` (default: 1) |
| DBL_JOB_CONCURRENCY_LLM | Max concurrent `chat.message` provider calls (default: 1) |
| DBL_LLM_WALL_CLOCK_S | LLM wall-clock timeout seconds (default: 60) |

---

## Observation Surfaces

### Snapshot (`/snapshot`)

Point-in-time view of the event log, suitable for audits and offline inspection.

### Tail (`/tail`)

Live SSE stream of events.
Parameters:

- `since`: start streaming from a specific event index
- `backlog`: number of recent events to emit on connect (default: 20)

### Status (`/status`)

Runtime status plus job runtime metrics:

- `job_runtime.queue_sizes`
- `job_runtime.active_counts`
- `job_runtime.queue_max`
- `job_runtime.llm.queue_position` (per requesting user)

---

## Integration Examples

### Using the [Observer](https://github.com/lukaspfisterch/dbl-observer)
```powershell
$env:DBL_GATEWAY_BASE_URL = "http://127.0.0.1:8010"
uvicorn dbl_observer.app:app --host 127.0.0.1 --port 8787
```

### Using the [Chat Client](https://github.com/lukaspfisterch/dbl-chat-client)
```powershell
# In the dbl-chat-client repository:
npm install && npm run dev
```

---

## Status
**Early, but operational.** Core execution, policy gating, and auditing are stable. Current focus: surface stabilization and contract clarity.
