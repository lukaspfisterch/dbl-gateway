# DBL Gateway

![Tests](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/github/license/lukaspfisterch/dbl-gateway)
[![PyPI version](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)

> **Looking for the full end-to-end demo?**
> See [dbl-stack](https://github.com/lukaspfisterch/dbl-stack) for a one-command setup including UI and observer.


DBL Gateway is a deterministic execution boundary for LLM calls.

It enforces explicit intent, policy decisions, and execution as an auditable, replayable event stream.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

This is **not**:
- a RAG pipeline
- a workflow engine
- a UI product

The gateway does not decide *what* to do. It decides *whether* an explicitly declared action may execute.

## Supported Providers (v0.4.x)

The gateway supports multiple LLM providers through a unified execution contract.

Currently supported:
- **OpenAI** (cloud)
- **Anthropic** (cloud)
- **Ollama** (local or remote)

Providers are currently configured via environment variables and exposed at runtime through capabilities introspection.

---

## Repository Landscape

The gateway is part of a small toolchain:

### dbl-gateway (this repository)
Authoritative execution boundary and event log. The gateway is authoritative for execution, but not for interpretation. It emits facts, not narratives.
- Accepts explicit intents.
- Applies policy.
- Executes provider calls.
- Emits canonical events (`INTENT`, `DECISION`, `EXECUTION`).
- Persists an append-only event trail.
- Exposes read-only observation surfaces (`/snapshot`, `/tail`).

### [dbl-operator](https://github.com/lukaspfisterch/dbl-operator)
Observer and intervention client. Used for rendering timelines, audits, and decision views. Does not evaluate policy or store authoritative state.

### [dbl-chat-cli](https://github.com/lukaspfisterch/dbl-chat-cli)
Minimal interactive CLI client for smoke testing and quick interaction via terminal.

### [dbl-chat-client](https://github.com/lukaspfisterch/dbl-chat-client)
Pure event-projection UI. Real-time visualization of the gateway event stream and identity anchor management.

---

## Interaction Model

Every interaction follows the same sequence:

1. **INTENT** – explicit request with identity anchors (`thread_id`, `turn_id`).
2. **DECISION** – policy outcome (ALLOW/DENY).
3. **EXECUTION** – provider call and result.
4. **OBSERVATION** – read-only access via snapshot or tail.

Only DECISION events are normative. EXECUTION events are observational and cannot influence policy or state.

No step is implicit; every event is linked via a stable `correlation_id`.

---

## Design Principles

- **Explicit boundaries**: Strict separation between core logic, policy, and execution.
- **Append-only records**: Immutable event trail for audit and replay.
- **No hidden state**: No heuristics or internal memory beyond the event stream.
- **Observer-safe**: Clients may observe and project state, but cannot affect policy, execution, or event ordering.

---

## Context System (v0.4.0+)

The gateway supports explicit context declaration for multi-turn conversations.

### declared_refs

Clients can reference prior events as context via `IntentEnvelope.payload.declared_refs`:

```json
{
  "declared_refs": [
    {"ref_type": "event", "ref_id": "correlation-id-1"},
    {"ref_type": "event", "ref_id": "turn-id-2"}
  ]
}
```

These references are resolved by the gateway and **injected into the LLM context** as a deterministic system block. This allows for multi-turn conversations without the gateway implicitly managing history.

### I_context / O_context Split

| Type | Admitted For | Digest Scope | Policy Access |
|------|--------------|--------------|---------------|
| INTENT events | `governance` | ✅ Included | ✅ Yes |
| EXECUTION events | `execution_only` | ✅ Included (audit) | ❌ No |

This ensures **observations never influence governance decisions** (DBL Claim 4).

### Configuration

Context behavior is controlled by `config/context.json`:

```json
{
  "max_refs": 50,
  "empty_refs_policy": "DENY",
  "canonical_sort": "event_index_asc",
  "enforce_scope_bound": true
}
```

The config digest is pinned in every DECISION event for replay verification.

See [docs/CONTEXT.md](docs/CONTEXT.md) for the full specification.

---

## Installation

### Local Install
Create a virtual environment and install the gateway:
```bash
pip install .
```

### Docker (Quick Start)

The gateway can be started in **observer mode** without executing any LLM calls:

```bash
docker run -p 8010:8010 dbl-gateway
```

This allows inspecting capabilities, snapshots, and event streams.

To enable execution, provide a policy and at least one provider:

**Execution-enabled (dev policy, evaluation only):**
```bash
docker run --rm -p 8010:8010 \
  -e OPENAI_API_KEY="sk-..." \
  -e DBL_GATEWAY_POLICY_MODULE="dbl_policy.allow_all" \
  -e DBL_GATEWAY_POLICY_OBJECT="policy" \
  lukaspfister/dbl-gateway:0.4.3
```

---

## Running the Gateway

### Environment Variables

#### Required for execution
| Variable | Description |
|---|---|
| DBL_GATEWAY_POLICY_MODULE | Policy module path (e.g., `dbl_policy.allow_all`) |
| OPENAI_API_KEY | OpenAI API key (or configure another provider) |

#### Model Configuration

```bash
# OpenAI (comma-separated)
OPENAI_API_KEY="sk-..."
OPENAI_CHAT_MODEL_IDS="gpt-5.2,gpt-4.1,gpt-4o-mini"

# Anthropic
ANTHROPIC_API_KEY="sk-ant-..."
ANTHROPIC_MODEL_IDS="claude-sonnet-4-20250514,claude-3-5-sonnet-20241022,claude-3-haiku-20240307"

# Ollama (auto-discovered from OLLAMA_HOST, or override manually)
OLLAMA_HOST="http://localhost:11434"
OLLAMA_MODEL_IDS="qwen2.5-coder:7b,llama3.2:latest,deepseek-r1:8b"
```

#### Other Options
| Variable | Description |
|---|---|
| DBL_GATEWAY_POLICY_OBJECT | Policy object name (default: `POLICY`) |
| OPENAI_BASE_URL | Custom OpenAI-compatible endpoint |

### Start Command
```bash
dbl-gateway serve --host 127.0.0.1 --port 8010
```

---

## Observation Surfaces

### Snapshot (`/snapshot`)
Returns a point-in-time state of the event log. Suitable for audits and offline inspection.

### Tail (`/tail`)
A live SSE stream of events. 
- `since`: Start streaming from a specific event index.
- `backlog`: Number of recent events to emit on connect (default: 20).

---

## Integration Examples

### Using the [Operator](https://github.com/lukaspfisterch/dbl-operator)
```powershell
$env:DBL_GATEWAY_BASE_URL = "http://127.0.0.1:8010"
dbl-operator thread-view --thread-id t-1
```

### Using the [Chat CLI](https://github.com/lukaspfisterch/dbl-chat-cli)
```powershell
dbl-chat-cli --base-url http://127.0.0.1:8010 --principal-id user-1
```

### Using the [Chat Client](https://github.com/lukaspfisterch/dbl-chat-client)
```powershell
# In the dbl-chat-client repository:
npm install && npm run dev
```

---

## Status
**Early, but operational.** Core execution, policy gating, and auditing are stable. Current focus: surface stabilization and contract clarity.
