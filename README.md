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

Every request passes through the same deterministic chain:

    INTENT  ->  DECISION  ->  PROOF  ->  EXECUTION

**INTENT** records what was asked.  
**DECISION** records what policy allowed.  
**PROOF** records what will be sent.  
**EXECUTION** records what happened.

Only DECISION events are normative. Execution output never feeds back into policy.

## Example

```json
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
      "declared_tools": ["web.search"],
      "tool_scope": "strict",
      "budget": { "max_tokens": 1024 }
    }
  }
}
```

Read events:

```text
GET /tail?stream_id=default&since=0
```

## Install

```bash
pip install dbl-gateway
```

Or from source:

```bash
pip install -e .
```

## Run

```bash
export DBL_GATEWAY_DB=./data/trail.sqlite
export DBL_GATEWAY_POLICY_MODULE=dbl_policy.allow_all
export DBL_GATEWAY_POLICY_OBJECT=policy
export OPENAI_API_KEY=sk-...

dbl-gateway serve --host 127.0.0.1 --port 8010
```

## Observer

The gateway includes a built-in observer at `/ui`.

It visualizes the event stream, decision replay, chain verification, manual
intent submission, and the integrated demo controller.

![Observer UI](pictures/demorun.png)

## Discovery

The runtime exposes three machine-readable discovery surfaces:

- `GET /capabilities`
- `GET /surfaces`
- `GET /intent-template`

Together they describe what the gateway can do, which surfaces exist, and how
to speak valid ingress envelopes.

## Documentation

See:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/QUICKSTART.md](docs/QUICKSTART.md)
- [docs/observer.md](docs/observer.md)
- [docs/demo.md](docs/demo.md)
- [docs/discovery.md](docs/discovery.md)
- [docs/CAPABILITIES.md](docs/CAPABILITIES.md)
- [docs/wire_contract.md](docs/wire_contract.md)
- [docs/env_contract.md](docs/env_contract.md)
- [CHANGELOG.md](CHANGELOG.md)

## Status

**v0.9.4.** Observer runtime, discovery surfaces, decision replay, manual intent
submission, and integrated demo control.
