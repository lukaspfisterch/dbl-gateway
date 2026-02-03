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
