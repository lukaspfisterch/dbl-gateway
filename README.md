# dbl-gateway: Deterministic Governance Gateway

[![DBL DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19600832.svg)](https://doi.org/10.5281/zenodo.19600832)
[![Execution Without Normativity DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19600773.svg)](https://doi.org/10.5281/zenodo.19600773)

Companion papers:
[Deterministic Boundary Layers](https://doi.org/10.5281/zenodo.19600832) ·
[Execution Without Normativity](https://doi.org/10.5281/zenodo.19600773)

`dbl-gateway` is a deterministic governance gateway for non-deterministic
systems.

It introduces an explicit `DECISION` event in front of execution.

Execution can be stochastic.
Logs are partial.
But what was allowed must be deterministic and replayable.

Most systems record what happened after execution.
`dbl-gateway` records what was explicitly allowed before execution.

Every request is recorded as:

```text
INTENT → DECISION → PROOF → EXECUTION
```

`DECISION` is the only normative event.
`PROOF` binds what is released to the backend.
`EXECUTION` remains observational.

> **If the decision cannot be replayed independently of the backend run, the
> boundary cannot be audited or defended.**

This repository ships that boundary in an LLM-facing form: external policy
evaluation, boundary-configured exposure, proof-bound provider release,
append-only event storage, and a read-side observer/demo UI.
The contract does not depend on LLMs; they are simply the most visible
runtime here.

`dbl-gateway` is for platform teams running probabilistic backends in
regulated or policy-constrained environments where what was allowed must be
explicit before the call.

The chain is tamper-evident: events are cryptographically linked via a rolling
`v_digest` that can be recomputed end-to-end to verify the stored stream.
Identity is mapped from an OIDC bearer token (Entra example included) into the
`DECISION` event, so `who was allowed` is part of the normative record.

`1.0.0` marks the core boundary-to-decision contract as stable.

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

Fastest way to inspect the full boundary end to end:

```bash
docker compose --profile demo up demo
```

No API keys are required for the demo profile.
Open [http://localhost:8010/ui](http://localhost:8010/ui) and click **Start Demo**.

The Docker demo runs scripted intents through the same deterministic governance chain the runtime uses normally.
Use **Manual Intent** in the observer to submit your own requests after that; the demo is an entry path into the runtime, not a separate architecture.

![Observer UI](pictures/demorun.png)

## A minimal request

Send an intent:

```bash
curl -X POST http://127.0.0.1:8010/ingress/intent \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

Read the event stream:

```bash
curl "http://127.0.0.1:8010/tail?stream_id=default&since=0"
```

Four events are produced for every intent:

1. **INTENT** — the request as received, immutable
2. **DECISION** — policy verdict (`ALLOW` / `DENY`), permitted tools, enforced budget, identity line — the only normative event
3. **PROOF** — `payload_digest` of what is released to the provider
4. **EXECUTION** — model output, tool calls, usage — observational, never feeds back into policy

Verify the full chain:

```bash
curl http://127.0.0.1:8010/ui/verify-chain
```

Recomputes `v_digest` from the stored events and reports any break.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

## Use your own provider

```bash
cp .env.example .env        # add one API key (OpenAI, Anthropic, or Ollama)
docker compose up
```

One active provider is enough. See [.env.example](.env.example) for all options.

The default runtime boundary profile is `operator`:
- `/ingress/intent`, `/capabilities`, `/snapshot`, `/tail`, `/status`, `/surfaces`, and `/intent-template` stay available
- `/ui/*` is not exposed

For the boundary contract in detail, see [env_contract.md](docs/env_contract.md),
[wire_contract.md](docs/wire_contract.md), and [CAPABILITIES.md](docs/CAPABILITIES.md).

## Install

```bash
pip install dbl-gateway
```

Or from source:

```bash
pip install -e .
```

For a minimal Python helper over the raw HTTP surfaces, use
`dbl_gateway.client.GatewayClient`.

## Observer UI

Open `/ui` only when the active boundary profile is `demo`.

The built-in observer includes the event stream, decision replay, chain
verification, a policy inspector for DECISION events, manual intent
submission, and the integrated demo controller.

## Documentation

Start here:

- [QUICKSTART.md](docs/QUICKSTART.md) — first request, reading events, UI verification
- [FIRST_INTEGRATION.md](docs/FIRST_INTEGRATION.md) — start gateway, send one request, read decision, verify replay

Integrating:

- [CONTRACT_BOUNDARY.md](docs/CONTRACT_BOUNDARY.md) — stable core contract vs evolving surface
- [INTEGRATION_SLICE.md](docs/INTEGRATION_SLICE.md) — raw send, decision inspection, and replay path
- [OIDC_INTEGRATION.md](docs/OIDC_INTEGRATION.md) — OIDC token mapping and concrete Entra example
- [wire_contract.md](docs/wire_contract.md) — envelope format, tool gating, budget, refs
- [env_contract.md](docs/env_contract.md) — all environment variables

Evaluating:

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — surfaces, component ownership, invariants
- [EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md) — optional replay bench and policy-diff notes
- [observer.md](docs/observer.md) — UI layout and verification routes
- [demo.md](docs/demo.md) — demo modes and scenario definition
- [Full manifest](docs/MANIFEST.md)
