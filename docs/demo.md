# Demo

The gateway supports two demo modes: a zero-config stub demo that requires no
external dependencies, and a live demo that uses a real provider.

## Zero-Config Stub Demo

Run the full governance pipeline without any API keys:

```bash
# Docker
docker compose --profile demo up --build demo

# Local
GATEWAY_DEMO_MODE=1 dbl-gateway serve

# PowerShell
$env:GATEWAY_DEMO_MODE="1"; dbl-gateway serve
```

Open `http://localhost:8010/ui/` and click **Start Demo**.

The stub provider generates synthetic responses through the full
INTENT, DECISION, PROOF, EXECUTION chain. The demo scenario includes an
intentional DENY turn so the observer shows both allowed and denied paths.

### Stub Modes

Control via `STUB_MODE` env var:

- `echo` (default) — mirrors the user message back. Predictable for contract
  testing.
- `scenario` — rotates through canned responses matching the governance-demo
  steps. Deterministic by turn index, so replay produces identical output.

### What Happens

When `GATEWAY_DEMO_MODE=1`:

- Stub provider auto-registers (no API keys checked).
- Policy defaults to `dbl_policy.allow_all` when none is configured.
- SQLite trail defaults to `data/demo-trail.sqlite`.
- Inline decision processing is enabled (no work queue).
- Context resolution defaults to ON so observer replay works out of the box.
- Startup log prints the browser entry path.

## Scenario

The default demo sequence is:

1. normal turn
2. follow-up turn
3. tools-and-budget turn
4. intentional deny
5. recovery turn

Both the UI demo controller and the CLI demo agent use the same scenario
definition from `dbl_gateway.demo_agent`.

## UI Demo

The browser starts the integrated demo through:

- `GET /ui/demo/status`
- `POST /ui/demo/start`

This produces a reproducible turn sequence while the observer is open.

## CLI Demo

```bash
./.venv/bin/python scripts/demo_agent.py --base-url http://127.0.0.1:8010
```

The CLI agent:

- checks gateway health
- checks capabilities for an active provider/model
- sends the scripted turns
- prints progress as the gateway emits events

## Runtime Notes

- Demo completion is tracked against the concrete thread timeline, not a bounded
  snapshot window.
- UI polling logs are suppressed by default so local runs stay readable.
