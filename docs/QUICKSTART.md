# Quickstart

## Prerequisites

- Python 3.11+
- editable installs of `dbl-ingress`, `dbl-policy`, `dbl-main`, `kl-kernel-logic`, `ensdg`

## Install

```
python -m venv .venv
source .venv/bin/activate        # bash
.venv\Scripts\Activate.ps1       # powershell

pip install -e .
```

## Configure

Three required environment variables:

```
export DBL_GATEWAY_DB=./data/trail.sqlite
export DBL_GATEWAY_POLICY_MODULE=policy_stub
export DBL_GATEWAY_POLICY_OBJECT=policy
```

See [env_contract.md](env_contract.md) for all variables.

Boundary exposure is controlled by `config/boundary*.json`.
The default runtime profile is `operator`, which keeps `/ui/*` disabled.

## Start

```
dbl-gateway serve --db ./data/trail.sqlite --host 127.0.0.1 --port 8010
```

## Verify

```
curl http://127.0.0.1:8010/healthz
curl http://127.0.0.1:8010/capabilities
```

In the default `operator` profile, use the runtime and discovery surfaces first:
- `GET /capabilities`
- `GET /surfaces`
- `GET /intent-template`
- `POST /ingress/intent`

Open the built-in observer UI at `http://127.0.0.1:8010/ui` only when the active boundary profile is `demo`.
The Verify panel now supports active browser-triggered verification:
- `Verify Chain` recomputes the full `v_digest` chain server-side.
- The inspector replays a selected `DECISION` turn server-side and reports digest match/mismatch.
- The `Policy` tab on a selected `DECISION` shows either a structural policy tree or an opaque policy summary when `describe()` is unavailable.
- The right-side `Demo Agent` panel can run the demo scenario directly from the UI.
- The left-side `Manual Intent` panel can send a valid minimal intent directly from the UI.

## Send an intent

```
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

Response (acknowledgement only, not execution output):

```json
{"accepted": true, "stream_id": "default", "index": 1, "correlation_id": "c-1", "queued": true}
```

## Read the event stream

```
curl "http://127.0.0.1:8010/tail?stream_id=default&since=0"
```

The gateway produces four events for every intent:

1. **INTENT** -- the request as received, immutable.
2. **DECISION** -- policy verdict (`ALLOW` / `DENY`), permitted tools, enforced budget. Normative.
3. **PROOF** -- context release guard (`payload_digest` of what is sent to the provider).
4. **EXECUTION** -- model output, tool calls, blocked tools, usage. Observational.

## Verify in the UI

After sending an intent, the observer should show four events:

1. **INTENT**
2. **DECISION**
3. **PROOF**
4. **EXECUTION**

Then:

1. Click `Verify Chain` in the Verify panel.
2. Expect `Chain: VALID` when the rolling digest matches a full recomputation.
3. Click the `DECISION` event row.
4. Use the inspector to replay the selected `DECISION`.
5. Expect `Decision #N: VALID` when replay reproduces the stored DECISION digest.

If verification fails, the panel shows the stored and recomputed digests for comparison.

## Run the integrated demo

For the full browser observer and one-click demo flow, run with the demo boundary profile.
The Docker demo profile already does this for you:

```bash
docker compose --profile demo up demo
```

If at least one provider is active in `GET /capabilities`, the simplest demo is then one click:

1. Open `http://127.0.0.1:8010/ui`
2. Press `Start Demo` in the `Demo Agent` panel
3. Watch the scripted turn sequence appear in the stream
4. Inspect events or replay the selected `DECISION`

## Send a manual intent from the UI

The observer includes a `Manual Intent` panel with:

1. a message field plus `actor` / `thread` inputs
2. a `Send` button that posts a valid envelope to `POST /ui/intent`
3. generated `curl` and PowerShell snippets for direct `/ingress/intent` testing

This is the simplest way to move from the scripted demo into your own ad hoc turns.

The integrated demo controller runs a scenario:

1. normal turn
2. follow-up turn
3. tool-and-budget turn
4. intentional governance-shape deny
5. recovery turn

## Run the CLI demo agent

If at least one provider is active in `GET /capabilities`, you can drive the
observer without manual `curl` calls:

```bash
./.venv/bin/python scripts/demo_agent.py --base-url http://127.0.0.1:8010
```

The demo agent:

1. checks that the gateway is healthy
2. requires at least one active provider/model
3. sends a small scripted sequence of intents
4. prints each resulting turn as events arrive

This is intended for live demos: the agent becomes visible as `actor=demo-agent`,
the event stream moves on its own, and the Verify panel can be used while the
script is running.

## Next

- [ARCHITECTURE.md](../docs/ARCHITECTURE.md) -- three-surface model
- [wire_contract.md](wire_contract.md) -- full envelope specification
- [env_contract.md](env_contract.md) -- all configuration variables
