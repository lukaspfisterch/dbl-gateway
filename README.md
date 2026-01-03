# DBL Gateway

Authoritative DBL and KL gateway. This service is the single writer for append-only trails,
applies policy via dbl-policy, and executes via kl-kernel-logic. UI and boundary services
consume its snapshots and emit INTENT only.

This release stabilizes the 0.3.x stackline and does not introduce new wire contracts.

Compatible stack versions:
- dbl-core==0.3.2
- dbl-policy==0.2.2
- dbl-main==0.3.1
- kl-kernel-logic==0.5.0

## Quickstart (PowerShell)

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run the gateway:
```powershell
dbl-gateway serve --db .\data\trail.sqlite --host 127.0.0.1 --port 8010
```

Run with uvicorn:
```powershell
$env:DBL_GATEWAY_DB=".\data\trail.sqlite"
py -3.11 -m uvicorn dbl_gateway.app:app --host 127.0.0.1 --port 8010
```

## Quick start with OpenAI (development)

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
- INTENT admission, DECISION generation, and canonicalization are provider-independent.
- The key is not persisted and is not written to the trail.
- Execution failures (missing or invalid key) are recorded as observational EXECUTION events.
- DECISION events remain authoritative regardless of execution outcome.

## Local API docs (OpenAPI)

When the gateway is running, the interactive API docs are available at:
- Swagger UI: `http://127.0.0.1:8010/docs`
- OpenAPI JSON: `http://127.0.0.1:8010/openapi.json`

Quick verification:
- Health: `http://127.0.0.1:8010/healthz`
- Capabilities: `http://127.0.0.1:8010/capabilities`
- Snapshot (first page): `http://127.0.0.1:8010/snapshot?offset=0&limit=50&stream_id=default`

## Quick probes (PowerShell)

Health:
```powershell
curl -s "http://127.0.0.1:8010/healthz"
```

Capabilities:
```powershell
curl -s "http://127.0.0.1:8010/capabilities"
```

Snapshot (page through the trail):
```powershell
curl -s "http://127.0.0.1:8010/snapshot?offset=0&limit=50&stream_id=default"
curl -s "http://127.0.0.1:8010/snapshot?offset=50&limit=50&stream_id=default"
```

Tail (SSE stream):
```powershell
curl -N "http://127.0.0.1:8010/tail?since=0&stream_id=default"
```

Emit an INTENT (example):
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

## Endpoints

Write:
- POST `/ingress/intent`

Read:
- GET `/snapshot`
- GET `/capabilities`
- GET `/healthz`

## Environment contract

See `docs/env_contract.md`.

## Validation against dbl-reference

See `docs/validation_workflow.md`.

## Notes

- The gateway is the only component that performs governance and execution.
- All stabilization is expressed explicitly via DECISION events.
- Boundary and UI clients do not import dbl-core or dbl-policy.
- The gateway uses dbl-core for canonicalization and digest computation.
