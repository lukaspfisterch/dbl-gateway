# DBL Gateway 0.2.1

Central writer for append-only stabilization trails in a
Deterministic Boundary Layers (DBL) system.

The gateway is not a user-facing service.
It is a **stabilization and governance primitive** used by boundary services
and domain runners to record normative and observational events
in a strictly ordered, append-only trail.

## Role in the DBL stack

The DBL Gateway occupies the **write authority layer**:

- Accepts validated INTENT, DECISION, EXECUTION, and PROOF events
- Enforces append-only ordering and digest stability
- Produces replayable snapshots for verification and audit
- Does not perform user interaction, policy reasoning, or UI rendering

User-facing interaction typically happens in a **Boundary Service**,
which calls the gateway as its persistence and stabilization backend.

For conceptual background, see:
- Deterministic Boundary Layers overview: https://github.com/lukaspfisterch/deterministic-boundary-layers

## Quickstart (PowerShell)

Create venv and install editable:
```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run the gateway:
```powershell
dbl-gateway serve --db .\data\trail.sqlite --host 127.0.0.1 --port 8010
```

Run with uvicorn (dev reload):
```powershell
$env:DBL_GATEWAY_DB=".\data\trail.sqlite"
py -3.11 -m uvicorn dbl_gateway.app:app --host 127.0.0.1 --port 8010 --reload
```

## Environment contract
See `docs/env_contract.md` for the full environment contract.

## Secrets
API keys and credentials are never stored in the repository
or inside event payloads.
Use environment variables or an external secrets provider.

## Endpoints

Write surfaces:
- POST `/ingress/intent`
- POST `/governance/decision`
- POST `/governance/policy-update`
- POST `/governance/boundary-update`
- POST `/execution/event`
- POST `/proof/artifact`
- POST `/llm/call`

Read surfaces:
- GET `/snapshot`
- GET `/snapshot/norm`
- GET `/event/{index}`
- GET `/status`
- GET `/healthz`
- GET `/debug/config`

## Authentication

Dev mode:
```powershell
$env:DBL_GATEWAY_AUTH_MODE="dev"
$env:DBL_GATEWAY_DEV_ACTOR="lukas"
$env:DBL_GATEWAY_DEV_ROLES="gateway.intent.write,gateway.decision.write,gateway.snapshot.read,gateway.policy.update,gateway.boundary.update,gateway.admin.read"
dbl-gateway serve --host 127.0.0.1 --port 8010 --db .\data\trail.sqlite
```

Dev identity can be overridden via request headers:
- `x-dev-actor`
- `x-dev-tenant`
- `x-dev-client`
- `x-dev-roles`

OIDC:
```powershell
python -m pip install -e ".[dev,oidc]"
$env:DBL_GATEWAY_AUTH_MODE="oidc"
$env:DBL_GATEWAY_OIDC_ISSUER="https://login.microsoftonline.com/<tenant-id>/v2.0"
$env:DBL_GATEWAY_OIDC_AUDIENCE="<api-app-id-or-audience>"
$env:DBL_GATEWAY_OIDC_JWKS_URL="https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys"
$env:DBL_GATEWAY_ALLOWED_TENANTS="<tenant-id-1>,<tenant-id-2>"
dbl-gateway serve --host 0.0.0.0 --port 8010 --db .\data\trail.sqlite
```

## Notes
- Snapshot v_digest represents the digest of the full stream prefix known
  to the producer.
- Paging parameters (limit, offset) affect only the event window,
  not v_digest.
- The SQLite backend is the reference implementation and assumes a single
  writer process.
- Use DBL_GATEWAY_MODE=leader for write access and follower for read-only replicas.
- OIDC support requires python-jose[cryptography].
  Ensure at least one CI job installs it to exercise validation paths.
