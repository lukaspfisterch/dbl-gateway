# dbl-gateway: Deterministic AI Governance Gateway

Most LLM runtimes can tell you what the model produced, but not what the system explicitly allowed before execution.
That is a governance problem: execution is probabilistic, logs are partial, and approval logic often disappears into application code.
If you cannot replay the decision independent of the model run, you cannot audit or defend the boundary.

`dbl-gateway` is for platform teams running LLM agents in regulated or policy-constrained environments where what was allowed must be explicit before a provider call.

Every request is recorded as:

```text
INTENT → DECISION → PROOF → EXECUTION
```

`DECISION` is the only normative event.
`PROOF` binds what will be released to the provider.
`EXECUTION` records what happened and remains observational.
The chain is replayable and auditable under fixed inputs and policy.

`dbl-gateway` is the runtime boundary between non-deterministic LLM execution and deterministic governance evidence.

`1.0.0` marks the core boundary-to-decision contract as stable.

For the architectural map above this runtime, see
[deterministic-boundary-layer](https://github.com/lukaspfisterch/deterministic-boundary-layer).

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

## How it works

Every request passes through the same deterministic chain:

    INTENT  →  DECISION  →  PROOF  →  EXECUTION

**INTENT** records what was asked.
**DECISION** records what policy allowed — the only normative event.
**PROOF** records what will be sent to the provider.
**EXECUTION** records what happened.

Execution output never feeds back into policy.

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

## Reference implementation

`dbl-gateway` is the DBL runtime reference implementation, with normative `DECISION`, release-bound `PROOF`, and observational `EXECUTION` under replayable fixed inputs and policy.

## Observer UI

Open `/ui` only when the active boundary profile is `demo`.

The built-in observer includes the event stream, decision replay, chain
verification, a policy inspector for DECISION events, manual intent
submission, and the integrated demo controller.

## Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) — first request, reading events, UI verification
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — surfaces, component ownership, invariants
- [CONTRACT_BOUNDARY.md](docs/CONTRACT_BOUNDARY.md) — stable core contract vs evolving surface
- [FIRST_INTEGRATION.md](docs/FIRST_INTEGRATION.md) — start gateway, send one request, read decision, verify replay
- [INTEGRATION_SLICE.md](docs/INTEGRATION_SLICE.md) — raw send, decision inspection, and replay path
- [OIDC_INTEGRATION.md](docs/OIDC_INTEGRATION.md) — OIDC token mapping and concrete Entra example
- [EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md) — optional replay bench and policy-diff notes
- [wire_contract.md](docs/wire_contract.md) — envelope format, tool gating, budget, refs
- [env_contract.md](docs/env_contract.md) — all environment variables
- [observer.md](docs/observer.md) — UI layout and verification routes
- [demo.md](docs/demo.md) — demo modes and scenario definition
- [Full manifest](docs/MANIFEST.md)
