# Integration Slice

This is the smallest raw integration path through `dbl-gateway`.

It is not a wrapper and not a demo story.
It shows one thing only:

```text
input → boundary → DECISION → replay
```

Use this first if you want to see where to dock an external client.

## Boundary for this slice

This slice uses the demo runtime because it exposes the built-in replay helpers
without extra auth setup.

The important part stays the same:

- write through the canonical ingress: `POST /ingress/intent`
- inspect the recorded chain
- replay the resulting `DECISION`

Start it with:

```bash
docker compose --profile demo up demo
```

## 1. Send one minimal intent

```bash
curl -X POST http://127.0.0.1:8010/ingress/intent \
  -H "Content-Type: application/json" \
  -d '{
    "interface_version": 3,
    "correlation_id": "slice-1",
    "payload": {
      "intent_type": "chat.message",
      "payload": { "message": "Hello" }
    }
  }'
```

Expected response:

```json
{
  "accepted": true,
  "stream_id": "default",
  "index": 1,
  "correlation_id": "slice-1",
  "queued": true
}
```

This is only an acknowledgement.
It is not execution output.

Everything else in the fuller envelope is optional here or derived
deterministically by the gateway.

## 2. Inspect the recorded chain

Read the latest events through the observer snapshot proxy:

```bash
curl "http://127.0.0.1:8010/ui/snapshot?stream_id=default&limit=20&offset=0"
```

You should see a turn containing:

- `INTENT`
- `DECISION`
- `PROOF`
- `EXECUTION`

The element to focus on is `DECISION`.

Normatively, that is the only authoritative event in the chain.

In the `DECISION.payload`, inspect at least:

- `result`
- `policy`
- `reason_codes`
- `request_class`
- `trust_class`
- `intent_index`

## 3. Replay the decision

Replay the recorded decision for the same turn:

```bash
curl "http://127.0.0.1:8010/ui/replay?thread_id=slice-thread-1&turn_id=slice-turn-1"
```

Expected shape:

```json
{
  "match": true,
  "recomputed_digest": "sha256:...",
  "stored_digest": "sha256:...",
  "assembly_digest": "sha256:...",
  "context_digest": "sha256:...",
  "decision_index": 2,
  "intent_index": 1
}
```

The point is `match: true`.

That means the stored `DECISION` digest can be reproduced from the recorded
authoritative path.

## 4. What this proves

This slice proves the core integration seam:

- a client writes to one ingress
- the boundary records what was asked
- the gateway records what was allowed before execution
- the decision can be replayed without re-running execution

## 5. Optional tiny client

If you want less typing without hiding the model, the package now exposes
`dbl_gateway.client.GatewayClient`.

It only wraps the same three surfaces:

- `send_intent(...)`
- `get_snapshot(...)`
- `replay(...)`

Example:

```python
from dbl_gateway.client import GatewayClient

envelope = {
    "interface_version": 3,
    "correlation_id": "slice-1",
    "payload": {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "thread_id": "slice-thread-1",
        "turn_id": "slice-turn-1",
        "parent_turn_id": None,
        "requested_model_id": "stub-echo",
        "payload": {"message": "Hello"},
    },
}

with GatewayClient("http://127.0.0.1:8010") as client:
    ack = client.send_intent(envelope)
    snapshot = client.get_snapshot(limit=20)
    replay = client.replay(thread_id="slice-thread-1", turn_id="slice-turn-1")
```

It does not build intents for you and it does not abstract `DECISION`.

## Next

- [FIRST_INTEGRATION.md](FIRST_INTEGRATION.md) for the shortest practical integration path
- [CONTRACT_BOUNDARY.md](CONTRACT_BOUNDARY.md) for the stable-core boundary
- [QUICKSTART.md](QUICKSTART.md) for the broader runtime setup
- [wire_contract.md](wire_contract.md) for the full envelope contract
