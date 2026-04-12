# dbl-gateway

Records what was allowed before anything runs.

`dbl-gateway` puts a deterministic decision layer in front of non-deterministic execution.
Every request is recorded as:

```text
INTENT → DECISION → PROOF → EXECUTION
```

`DECISION` happens first.
Execution stays non-normative.
The full chain is replayable.

For the architecture entry point, see
[deterministic-boundary-layer](https://github.com/lukaspfisterch/deterministic-boundary-layer).

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

Run it in 1 minute with Docker, or install the package and connect your own provider.

No API keys required:

```bash
docker compose --profile demo up demo
```

Open [http://localhost:8010/ui](http://localhost:8010/ui) and click **Start Demo**.

The demo runs scripted scenarios through the full governance pipeline.
Use **Manual Intent** in the observer to submit your own requests —
the gateway is a working runtime, not just a demo harness.

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

## Active Boundary Topics

- Exposure modes — `operator` by default, full built-in observer only in `demo`
- High-risk ingress — `public` blocks shapes like `artifact.handle`, `declared_refs`, and over-broad tool declarations before any `INTENT` is appended
- Tool and request shaping — tool families, request classes, and budget ceilings live in the versioned boundary artifact
- Economic shaping — slot and cost classes are declared in the boundary and carried into `DECISION`
- Identity — a minimal verified identity line is injected into policy-visible inputs and recorded in `DECISION`

See [env_contract.md](docs/env_contract.md), [wire_contract.md](docs/wire_contract.md), and [CAPABILITIES.md](docs/CAPABILITIES.md) for the boundary contract in detail.

## Install

```bash
pip install dbl-gateway
```

Or from source:

```bash
pip install -e .
```

## Reference implementation

`dbl-gateway` implements the Deterministic Boundary Layer (DBL) as a runtime
system.

It realizes the event chain INTENT → DECISION → PROOF → EXECUTION, where
DECISION events are recorded before any execution and remain the only
normative layer. Execution outputs are treated as non-normative observations.

The gateway enforces the core invariants of the model:
- append-only event stream
- strict ordering of DECISION before EXECUTION
- governance input purity (authoritative inputs only)
- deterministic replay under fixed inputs and policy configuration

As such, it serves both as a usable governed gateway and as a reference
implementation of the DBL model.

For the stable-core versus evolving-surface split, see
[CONTRACT_BOUNDARY.md](docs/CONTRACT_BOUNDARY.md).

For empirical validation, including replay equivalence and policy variation
benchmarks, see
[EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md).

## Observer UI

Open `/ui` only when the active boundary profile is `demo`.

The built-in observer includes the event stream, decision replay, chain
verification, a policy inspector for DECISION events, manual intent
submission, and the integrated demo controller.

## Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) — first request, reading events, UI verification
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — surfaces, component ownership, invariants
- [CONTRACT_BOUNDARY.md](docs/CONTRACT_BOUNDARY.md) — stable core contract vs evolving surface
- [EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md) — optional replay bench and policy-diff notes
- [wire_contract.md](docs/wire_contract.md) — envelope format, tool gating, budget, refs
- [env_contract.md](docs/env_contract.md) — all environment variables
- [observer.md](docs/observer.md) — UI layout and verification routes
- [demo.md](docs/demo.md) — demo modes and scenario definition
- [Full manifest](docs/MANIFEST.md)
