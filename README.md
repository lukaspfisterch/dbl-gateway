# dbl-gateway

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

When organizations deploy LLM systems, they quickly need to answer three questions:
Who asked what, what was permitted, and what actually happened.

dbl-gateway introduces a deterministic boundary layer between intent, policy and execution for LLM calls.

This repository provides a reference implementation of the Deterministic Boundary Layer concept.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

## Model

Every request passes through three surfaces:

    Intent  ->  Decision  ->  Execution

**Intent** accepts and validates the request.
**Decision** evaluates policy and produces a normative verdict (ALLOW / DENY).
**Execution** calls the provider and enforces tool and budget constraints.

Each surface emits one event. Events are append-only, linked by `correlation_id`,
and digested with SHA-256 over canonical JSON.

Only DECISION events are normative. Execution output never feeds back into policy.

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

The gateway produces three events:

    INTENT     what was asked
    DECISION   what was allowed  (permitted_tools, enforced_budget)
    EXECUTION  what happened     (model output, tool_calls, tool_blocked)

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

OpenAI, Anthropic, and Ollama. Configured via environment variables,
exposed through `GET /capabilities`.

## What This Is Not

- Not a RAG pipeline.
- Not a workflow engine.
- Not a chat UI.

The gateway does not decide what to do. It decides whether a declared
action may execute.

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

**v0.6.0.** Core execution, policy gating, tool enforcement, and budget
constraints are stable. Wire contract v3.
