# Wire Contract Notes

## Interface Version

The current interface version is `2`. All `IntentEnvelope` requests must include `interface_version: 2`.

## IntentEnvelope Structure

```json
{
  "interface_version": 2,
  "correlation_id": "unique-request-id",
  "payload": {
    "stream_id": "default",
    "lane": "user",
    "actor": "user@example.com",
    "intent_type": "chat.message",
    "thread_id": "thread-uuid",
    "turn_id": "turn-uuid",
    "parent_turn_id": null,
    "payload": {
      "message": "Hello, world!",
      "thread_id": "thread-uuid",
      "turn_id": "turn-uuid"
    },
    "declared_refs": [
      {"ref_type": "event", "ref_id": "correlation-id-1"},
      {"ref_type": "event", "ref_id": "turn-id-2"}
    ]
  }
}
```

## Declared Refs (v0.4.0+)

The `declared_refs` field allows clients to request specific events as context.

### Format

```typescript
interface DeclaredRef {
  ref_type: "event" | "document" | "external";
  ref_id: string;      // correlation_id or turn_id of the referenced event
  version?: string;    // Optional version specifier
}
```

### Semantics

| Aspect | Behavior |
|--------|----------|
| **Request, not guarantee** | Client requests refs; gateway validates and may reject |
| **Lookup order** | Refs are matched by `correlation_id` first, then `turn_id` |
| **Scope-bound** | All refs must belong to the same `thread_id` as the request |
| **Canonical ordering** | Refs are sorted by `event_index` regardless of request order |
| **Classification** | INTENT events → `governance`, EXECUTION → `execution_only` |

### Error Responses

| Error | HTTP Status | Response |
|-------|-------------|----------|
| Ref not found | 400 | `{"ok": false, "reason_code": "REF_NOT_FOUND", "detail": "..."}` |
| Cross-thread ref | 400 | `{"ok": false, "reason_code": "CROSS_THREAD_REF", "detail": "..."}` |
| Too many refs | 400 | `{"ok": false, "reason_code": "MAX_REFS_EXCEEDED", "detail": "..."}` |

## Attachment Handle Events (1A: Handle-Only Bridge)

To bridge external artifact storage (e.g., Workbench) without inlining content,
clients should emit **handle-only** INTENT events and then reference those
events in `declared_refs`.

### Handle Event (INTENT)

Use `intent_type: "artifact.handle"` and a payload that includes identity
anchors plus a `handle` block:

```json
{
  "interface_version": 2,
  "correlation_id": "wb-attach-uuid",
  "payload": {
    "stream_id": "default",
    "lane": "user_chat",
    "actor": "workbench",
    "intent_type": "artifact.handle",
    "thread_id": "case-uuid",
    "turn_id": "turn-uuid",
    "parent_turn_id": "turn-uuid",
    "payload": {
      "thread_id": "case-uuid",
      "turn_id": "turn-uuid",
      "parent_turn_id": "turn-uuid",
      "handle": {
        "artifact_ref_id": "artifact-uuid",
        "artifact_kind": "summary",
        "artifact_digest": "sha256:...",
        "mime": "text/plain",
        "bytes": 12345,
        "origin": "workbench",
        "scope": "full",
        "created_ts": "2026-02-03T12:34:56Z"
      },
      "resolver": {
        "type": "workbench",
        "endpoint": "workbench://cases/{case_id}/artifacts/{artifact_id}"
      }
    }
  }
}
```

These handle events are **metadata-only** and do **not** trigger policy decisions.

### Declared Refs for Chat Intents

Subsequent chat intents should reference the handle event by **`turn_id`**:

```json
"declared_refs": [
  {"ref_type": "event", "ref_id": "turn-uuid"}
]
```

## Tail Semantics

`GET /tail?since=<index>` streams events where `event.index > since`.

If the `Last-Event-Id` header is provided by the client, the server treats it as the effective `since` value.

Events are emitted as SSE envelopes:

- `id: <index>`
- `event: envelope`
- `data: <json>`

## Ingress Acknowledgement

`POST /ingress/intent` responds immediately after the INTENT is appended. The response is an acknowledgement and does not include execution output.

```json
{
  "accepted": true,
  "stream_id": "default",
  "index": 42,
  "correlation_id": "unique-request-id",
  "queued": true
}
```

## DECISION Payload (v0.5.x)

DECISION events include a `boundary` block for replay verification:

```json
{
  "policy": {"policy_id": "...", "policy_version": "..."},
  "assembly_digest": "sha256:...",
  "context_digest": "sha256:...",
  "result": "ALLOW",
  "reasons": [...],
  "transforms": [...],
  "boundary": {
    "context_config_digest": "sha256:...",
    "boundary_version": "1"
  },
  "context_spec": {...},
  "assembled_context": {...}
}
```

In 0.5.x, `context_digest` is the same digest as `assembly_digest` (context_spec + assembled_context). A provider payload digest is out of scope for 0.5.x.

The `boundary.context_config_digest` pins the configuration that was used to make this decision.
