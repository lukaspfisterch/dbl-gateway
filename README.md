# dbl-gateway

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

When organizations deploy LLM systems, they quickly need to answer three questions:
Who asked what, what was permitted, and what actually happened.

dbl-gateway is the reference runtime implementation of the DBL execution boundary
for the Deterministic Boundary Layer.
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

Send an intent through `POST /ingress/intent` and read events through
`GET /tail?stream_id=default&since=0`.

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full envelope example.

## Zero-Config Demo

No API keys, no `.env` editing. See the full governance pipeline in 60 seconds:

```bash
docker compose --profile demo up --build
```

Open `http://localhost:8010/ui/` and click **Start Demo**.

Or locally:

```bash
GATEWAY_DEMO_MODE=1 dbl-gateway serve
```

The stub provider generates synthetic responses through the full
INTENT, DECISION, PROOF, EXECUTION chain.
Demo mode also enables context resolution by default so observer replay works
without extra env setup.

## One-Command Start

Configure `.env` once from [​.env.example](.env.example), set one provider key
or local Ollama, then start the gateway with:

```bash
docker compose up --build
```

Open `http://localhost:8010/ui/` to watch the event chain in real time.

On Windows, use:

```powershell
.\run_demo.ps1
```

![Observer UI](pictures/demorun.png)

## Install

```bash
pip install dbl-gateway
```

Or from source:

```bash
pip install -e .
```

## Run With Docker

```bash
cp .env.example .env
# add one provider key or configure local Ollama in .env
docker compose up --build
```

Supports OpenAI, Anthropic, or local Ollama. One active provider is enough to
run the gateway.

`.env` is local and must not be committed. Copy `.env.example` and configure it
for your environment.

## Run Locally

```bash
export DBL_GATEWAY_DB=./data/trail.sqlite
export DBL_GATEWAY_POLICY_MODULE=dbl_policy.allow_all
export DBL_GATEWAY_POLICY_OBJECT=policy
export OPENAI_API_KEY=sk-...

dbl-gateway serve --host 127.0.0.1 --port 8010
```

## Observer

Open `/ui` to watch the event chain in real time.

The built-in observer includes the event stream, decision replay, chain
verification, manual intent submission, and the integrated demo controller.

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
