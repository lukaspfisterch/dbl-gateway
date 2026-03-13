# dbl-gateway

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

When organizations deploy LLM systems, they quickly need to answer three questions:
Who asked what, what was permitted, and what actually happened.

dbl-gateway is the execution boundary for the Deterministic Boundary Layer.
It accepts declared intents, enforces policy decisions, and records everything
as an append-only, digest-pinned event stream.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

## Model

Every request passes through a deterministic event chain:

    INTENT  ->  DECISION  ->  PROOF  ->  EXECUTION

**INTENT** records what was asked.
**DECISION** records what policy allowed (normative, digest-pinned).
**PROOF** captures the context release guard -- a digest of the payload sent to the provider.
**EXECUTION** records what the provider returned.

Events are append-only, linked by `correlation_id`,
and digested with SHA-256 over canonical JSON.

Only DECISION events are normative. Execution output never feeds back into policy.
Policy logic lives in dbl-policy; the gateway only evaluates and enforces.

## Example

```
POST /ingress/intent
{
  "interface_version": 3,
  "correlation_id": "c-1",
  "payload": {
    "stream_id": "default",
    "lane": "user",
    "actor": "user@example.com",
    "intent_type": "chat.message",
    "thread_id": "t-1",
    "turn_id": "turn-1",
    "parent_turn_id": null,
    "payload": {
      "message": "hello",
      "thread_id": "t-1",
      "turn_id": "turn-1",
      "declared_tools": ["web.search"],
      "tool_scope": "strict",
      "budget": { "max_tokens": 1024 }
    }
  }
}
```

The gateway produces up to four events:

    INTENT     what was asked
    DECISION   what was allowed  (permitted_tools, enforced_budget, intent_index)
    PROOF      what will be sent (context release guard, payload_digest)
    EXECUTION  what happened     (model output, tool_calls, release_digest)

Read them back:

```
GET /tail?stream_id=default&since=0
```

## Install

```
pip install dbl-gateway
```

Or from source:

```
pip install -e .
```

## Run

```
export DBL_GATEWAY_DB=./data/trail.sqlite
export DBL_GATEWAY_POLICY_MODULE=dbl_policy.allow_all
export DBL_GATEWAY_POLICY_OBJECT=policy
export OPENAI_API_KEY=sk-...

dbl-gateway serve --host 127.0.0.1 --port 8010
```

## Providers

OpenAI, Anthropic, and Ollama. Each provider is a stateless adapter
exposing `execute()` and `get_capabilities()` against a formal
`ProviderCapabilities` schema. Runtime capabilities are self-describing
via `GET /capabilities`.

## Observer UI

The gateway serves a built-in event observer at `/ui` (also the root redirect target).
No separate frontend, no frameworks — a single HTML file that connects via SSE to
`/ui/tail` and renders the event stream in real-time.

```
http://127.0.0.1:8010/ui
```

Three-zone layout:

- **Agent Activity** — live phase tracking per turn, last event per kind, turn count.
- **Capabilities** — gateway version, providers, model health, surfaces.
- **Verify** — current `v_digest`, event count, last DECISION metadata, active chain verification, and per-turn decision replay.
- **Event Stream** — chronological turn-grouped event timeline with click selection.
- **Inspector** — event detail, turn-local view, and raw JSON for the selected event.

Events are grouped by turn (`correlation_id`), color-coded by kind, and show
delta-time between events in the same turn.

Verification stays server-side. The browser only works with events and calls
read-only observer routes:

- `GET /ui/tail` — SSE event stream for the observer.
- `GET /ui/capabilities` — provider and surface summary.
- `GET /ui/snapshot` — latest `v_digest` and event count.
- `POST /ui/intent` — manual intent submission from the observer.
- `GET /ui/verify-chain` — full-chain `v_digest` recomputation and match/mismatch result.
- `GET /ui/replay?thread_id=...&turn_id=...` — decision replay for one turn.
- `GET /ui/demo/status` / `POST /ui/demo/start` — integrated demo controller.

Workflow:

1. Open `/ui`.
2. Click `Start Demo` to run the built-in scenario, or send an intent manually.
3. Click any event row to open the inspector.
4. Click `Verify Chain` in the Verify panel to recompute the full chain.
5. Replay a selected `DECISION` from the inspector to compare stored vs recomputed decision digests.

All `/ui/*` routes are read-only observer infrastructure and require no authentication.

### Demo Agent

The observer now includes a right-side `Demo Agent` panel with a `Start Demo`
button. When at least one provider/model is healthy in `GET /capabilities`,
the integrated controller runs a scenario directly from the UI.

It also includes a left-side `Manual Intent` panel for sending a valid minimal
intent directly from the browser or copying ready-to-run `curl` / PowerShell
commands for terminal use.

Scenario:

- normal turn
- follow-up turn
- tool-and-budget turn
- intentional governance-shape deny
- recovery turn

For terminal-driven demos, the bundled CLI agent is still available after the
gateway is up and at least one provider is active:

```bash
./.venv/bin/python scripts/demo_agent.py --base-url http://127.0.0.1:8010
```

Both paths use the same scenario definition and actor (`demo-agent`) so the
gateway, stream, inspector, and verification surfaces all show the same
reproducible sequence.

## What This Is Not

- Not a RAG pipeline.
- Not a workflow engine.
- Not a chat UI.

The gateway does not decide what to do. It enforces whether a declared
action may execute. Policy rules are defined externally in dbl-policy.

## Documentation

| Document | Content |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Three-surface model, component ownership, invariants |
| [QUICKSTART.md](docs/QUICKSTART.md) | Setup, first request, reading events |
| [wire_contract.md](docs/wire_contract.md) | Envelope format, tool gating, budget, refs |
| [env_contract.md](docs/env_contract.md) | All environment variables |
| [CAPABILITIES.md](docs/CAPABILITIES.md) | Runtime capability introspection |
| [INVARIANTS.md](docs/INVARIANTS.md) | Machine-checkable invariant list |
| [CONTEXT.md](docs/CONTEXT.md) | Context resolution and ref classification |
| [HOOKS.md](docs/HOOKS.md) | Pre-commit boundary enforcement |
| [VALIDATION.md](docs/VALIDATION.md) | Validation workflow |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Related Repositories

- [deterministic-boundary-layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) -- specification and theory
- [dbl-observer](https://github.com/lukaspfisterch/dbl-observer) -- timeline and audit UI
- [dbl-chat-client](https://github.com/lukaspfisterch/dbl-chat-client) -- event-projection chat UI
- [dbl-stack](https://github.com/lukaspfisterch/dbl-stack) -- one-command full-stack setup

## Status

**v0.9.4.** Observer UI as runtime demo/playground:
semantic panels, stream inspector, manual intent submission, full-chain
`v_digest` recomputation, per-turn decision replay, and integrated demo control.
Substrate-axiom enforcement (A1 append-only, A5 turn-local order, A3/A4 governance-input purity).
Chain-of-record lineage, context release guard, policy config digest.
Self-describing capabilities via `GET /capabilities`. Wire contract v3.
