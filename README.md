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

**v0.9.0.** Substrate-axiom enforcement (A1 append-only stream, A5 turn-local order, A3/A4 governance-input purity),
plus chain-of-record lineage (`intent_index`), context release guard (PROOF events), and policy config digest.
Self-describing capabilities via `GET /capabilities`. Wire contract v3.
