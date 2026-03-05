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

## Start

```
dbl-gateway serve --db ./data/trail.sqlite --host 127.0.0.1 --port 8010
```

## Verify

```
curl http://127.0.0.1:8010/healthz
curl http://127.0.0.1:8010/capabilities
```

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

The gateway produces three events for every intent:

1. **INTENT** -- the request as received, immutable.
2. **DECISION** -- policy verdict (`ALLOW` / `DENY`), permitted tools, enforced budget. Normative.
3. **EXECUTION** -- model output, tool calls, blocked tools, usage. Observational.

## Next

- [ARCHITECTURE.md](../docs/ARCHITECTURE.md) -- three-surface model
- [wire_contract.md](wire_contract.md) -- full envelope specification
- [env_contract.md](env_contract.md) -- all configuration variables
