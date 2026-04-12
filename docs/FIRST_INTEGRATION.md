# First Integration

This is the shortest practical path for integrating with `dbl-gateway`.

It assumes one thing only:
you want to send a request, find the resulting `DECISION`, and verify that the
decision replay is stable.

## 1. Start the gateway

For the smallest end-to-end path, use the demo runtime:

```bash
docker compose --profile demo up demo
```

This gives you:

- canonical write ingress at `POST /ingress/intent`
- replay helpers at `/ui/replay`
- a local stub model so no external provider is required

## 2. Send one request

You can do this either raw or through the tiny client.

### Raw HTTP

```bash
curl -X POST http://127.0.0.1:8010/ingress/intent \
  -H "Content-Type: application/json" \
  -d '{
    "interface_version": 3,
    "correlation_id": "integration-1",
    "payload": {
      "stream_id": "default",
      "lane": "user_chat",
      "actor": "user",
      "intent_type": "chat.message",
      "thread_id": "integration-thread-1",
      "turn_id": "integration-turn-1",
      "parent_turn_id": null,
      "requested_model_id": "stub-echo",
      "payload": {
        "message": "Hello"
      }
    }
  }'
```

### Tiny client

```python
from dbl_gateway.client import GatewayClient

envelope = {
    "interface_version": 3,
    "correlation_id": "integration-1",
    "payload": {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "thread_id": "integration-thread-1",
        "turn_id": "integration-turn-1",
        "parent_turn_id": None,
        "requested_model_id": "stub-echo",
        "payload": {"message": "Hello"},
    },
}

with GatewayClient("http://127.0.0.1:8010") as client:
    ack = client.send_intent(envelope)
    print(ack)
```

Expected acknowledgement shape:

```json
{
  "accepted": true,
  "stream_id": "default",
  "index": 1,
  "correlation_id": "integration-1",
  "queued": true
}
```

This is only the write acknowledgement.
It is not the execution result.

## 3. Read the resulting decision

Fetch the latest events:

```bash
curl "http://127.0.0.1:8010/ui/snapshot?stream_id=default&limit=20&offset=0"
```

Or with the client:

```python
with GatewayClient("http://127.0.0.1:8010") as client:
    snapshot = client.get_snapshot(limit=20)
    print(snapshot)
```

Find the turn with:

- `INTENT`
- `DECISION`
- `PROOF`
- `EXECUTION`

The event to inspect is `DECISION`.

At minimum, read:

- `payload.result`
- `payload.policy`
- `payload.reason_codes`
- `payload.request_class`
- `payload.trust_class`

That is the normative record of what the gateway allowed.

## 4. Verify replay

Replay the recorded decision for the same turn:

```bash
curl "http://127.0.0.1:8010/ui/replay?thread_id=integration-thread-1&turn_id=integration-turn-1"
```

Or with the client:

```python
with GatewayClient("http://127.0.0.1:8010") as client:
    replay = client.replay(
        thread_id="integration-thread-1",
        turn_id="integration-turn-1",
    )
    print(replay)
```

Expected shape:

```json
{
  "match": true,
  "recomputed_digest": "sha256:...",
  "stored_digest": "sha256:...",
  "decision_index": 2,
  "intent_index": 1
}
```

The important field is:

```text
match = true
```

That means the stored `DECISION` digest can be reproduced from the recorded
authoritative path.

## 5. What the integrator should take away

- write to `/ingress/intent`
- read the resulting `DECISION`
- treat execution as observational
- use replay to verify the normative path

## Next

- [INTEGRATION_SLICE.md](INTEGRATION_SLICE.md) for the raw seam only
- [CONTRACT_BOUNDARY.md](CONTRACT_BOUNDARY.md) for the stable-core boundary
- [wire_contract.md](wire_contract.md) for the full envelope shape
