# DBL Gateway 0.3.2

Authoritative DBL and KL gateway. This service is the single writer for append-only trails,
applies policy via dbl-policy, and executes via kl-kernel-logic. UI and boundary services
consume its snapshots and emit INTENT only.

This release stabilizes the 0.3.x stackline and does not introduce new wire contracts.

Compatible stack versions:
- dbl-core==0.3.2
- dbl-policy==0.1.0
- dbl-main==0.3.0
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

## Endpoints

Write:
- POST `/ingress/intent`

Read:
- GET `/snapshot`
- GET `/capabilities`
- GET `/healthz`

## Environment contract

See `docs/env_contract.md`.

## Notes

- The gateway is the only component that performs governance and execution.
- All stabilization is expressed explicitly via DECISION events.
- Boundary and UI clients do not import dbl-core or dbl-policy.
- The gateway uses dbl-core for canonicalization and digest computation.
