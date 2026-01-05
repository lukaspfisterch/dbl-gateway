# DBL Gateway

[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)

Authoritative DBL and KL gateway.

The gateway is the single writer for append-only trails. It admits INTENTs, evaluates policy via `dbl-policy`,
and performs execution via `kl-kernel-logic`. UIs and boundary clients consume snapshots and emit INTENT only.

This release stabilizes the 0.3.x stackline and does not introduce new wire contracts.

## Design Note

This gateway is an attempt to make the use of AI admissible within a DBL-based architecture.

The goal is not to explain or justify AI behavior, but to ensure that any AI-assisted action is preceded by an explicit INTENT, governed by a DECISION, and recorded in an append-only trail.

This allows AI components to be used as execution backends while preserving determinism, auditability, and decision primacy.

The gateway does not make AI safe or correct.
It makes AI usage observable, reviewable, and replayable.

## Compatibility

- dbl-core==0.3.6
- dbl-policy==0.2.2
- dbl-main==0.3.1
- kl-kernel-logic==0.5.0

## Install (PowerShell)

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Run (PowerShell)

```powershell
dbl-gateway serve --db .\data\trail.sqlite --host 127.0.0.1 --port 8010
```

Alternative (uvicorn):

```powershell
$env:DBL_GATEWAY_DB=".\data\trail.sqlite"
py -3.11 -m uvicorn dbl_gateway.app:app --host 127.0.0.1 --port 8010
```

## OpenAPI

When running locally:

- Swagger UI: http://127.0.0.1:8010/docs
- OpenAPI JSON: http://127.0.0.1:8010/openapi.json

Quick probes:

- Health: http://127.0.0.1:8010/healthz
- Capabilities: http://127.0.0.1:8010/capabilities
- Snapshot: http://127.0.0.1:8010/snapshot?offset=0&limit=50&stream_id=default

## Emit an INTENT (PowerShell)

```powershell
$body = @{
  interface_version = 1
  correlation_id = [guid]::NewGuid().ToString()
  payload = @{
    stream_id = "default"
    lane = "ui"
    actor = "dev"
    intent_type = "ui.ping"
    payload = @{ text = "hello" }
  }
} | ConvertTo-Json -Depth 8

curl -s -X POST "http://127.0.0.1:8010/ingress/intent" `
  -H "content-type: application/json" `
  -d $body
```

## OpenAI execution (development)

To execute chat intents via OpenAI, set an API key in the environment.

PowerShell (Windows):

```powershell
$env:OPENAI_API_KEY="sk-..."
dbl-gateway serve --db .\data\trail.sqlite --host 127.0.0.1 --port 8010
```

Bash (macOS / Linux):

```bash
export OPENAI_API_KEY="sk-..."
dbl-gateway serve --db ./data/trail.sqlite --host 127.0.0.1 --port 8010
```

Notes:

- The key is used for execution only.
- Admission, DECISION generation, canonicalization, and digests are provider-independent.
- The key is not persisted and is not written to the trail.
- Execution failures are recorded as observational EXECUTION events.
- DECISION events remain authoritative regardless of execution outcome.

## API surface

Write:

- `POST /ingress/intent`

Read:

- `GET /snapshot`
- `GET /capabilities`
- `GET /healthz`
- `GET /tail` (SSE)

## Git hooks

The repository includes an optional pre-commit hook that enforces DBL boundaries and invariants.

Quick usage (PowerShell):

```powershell
git commit -m "your message"
$env:DBL_HOOK_EXPLAIN = "1"; git commit -m "msg"
$env:DBL_HOOK_LIST_RULES = "1"; git commit -m "test"
```

See docs/GIT_HOOKS.md for details.

## Documentation

- Environment contract: docs/env_contract.md
- Validation workflow: docs/validation_workflow.md
- Architecture: docs/ARCHITECTURE.md

## Boundary notes

The gateway is the only component that performs governance and execution.

Boundary and UI clients must not import dbl-core or dbl-policy.

Canonicalization and digests follow dbl-core.

