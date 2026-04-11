# Wire Contract Notes

## Interface Version

The current interface version is `3`. All `IntentEnvelope` requests must include `interface_version: 3`.

Clients sending `interface_version: 2` will be rejected at ingress.

## IntentEnvelope Structure

```json
{
  "interface_version": 3,
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
      "turn_id": "turn-uuid",
      "declared_tools": ["web.search", "code.execute"],
      "tool_scope": "strict",
      "budget": {
        "max_tokens": 4096,
        "max_duration_ms": 30000
      }
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
  "interface_version": 3,
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

### Handle Content Fetch (Gateway)

If enabled, the gateway may resolve `artifact.handle` references into **model context**
for `chat.message` intents by fetching content from the Workbench resolver.

This is guarded by config and never uses the event-provided endpoint as a free URL.

Config keys (context.handle_content_fetch):
- `allow_handle_content_fetch` (bool)
- `high_risk_context_admit_mode` (`disabled` | `metadata_only` | `model_context`)
- `workbench_resolver_url` (base URL; must be http/https)
- `workbench_auth_bearer_token` (optional)
- `workbench_fetch_timeout_ms` (default 1500)
- `workbench_max_bytes` (default 512000)
- `workbench_admit_kinds` (default ["extracted_text","summary"])

Warnings (observational, stored in `assembled_context.warnings`):
- `HIGH_RISK_CONTEXT_DISABLED`
- `HIGH_RISK_CONTEXT_METADATA_ONLY`
- `HANDLE_CONTENT_FETCH_DISABLED`
- `HANDLE_CONTENT_FETCH_KIND_DENIED`
- `HANDLE_CONTENT_FETCH_TOO_LARGE`
- `HANDLE_CONTENT_FETCH_TIMEOUT`
- `HANDLE_CONTENT_FETCH_HTTP_ERROR`
- `HANDLE_CONTENT_FETCH_PARSE_ERROR`
- `HANDLE_CONTENT_FETCH_CONTENT_TYPE`

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

## Tool Gating (v0.6.0+)

Clients may declare which tools the model is allowed to invoke.

### Intent Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `declared_tools` | `list[str]` | No | Tool names the client authorizes. Max 20. |
| `tool_scope` | `"strict" \| "advisory"` | No | Enforcement mode. Default `"strict"` when `declared_tools` present. |

Tool names must match `^[a-z][a-z0-9_.]{0,63}$`.

### DECISION Fields

| Field | Description |
|-------|-------------|
| `request_class` | Deterministic request taxonomy derived from the authoritative request shape. |
| `budget_class` | Budget classification derived from the declared budget vs the boundary light-budget threshold. |
| `budget_policy_reason` | Stable request-policy reason such as `request.execution_heavy_denied` or `request.budget_clamped`. |
| `declared_tool_families` | Deterministic family buckets derived from `declared_tools`. |
| `allowed_tool_families` | Tool families allowed by the active boundary policy. |
| `permitted_tool_families` | Tool families remaining after boundary family gating and no-mix invariants. |
| `denied_tool_families` | Tool families explicitly denied during the boundary pass. |
| `permitted_tools` | Tools the gateway allows (normative). |
| `tool_scope_enforced` | `"strict"` or `"advisory"`. |
| `tools_denied` | Tools removed by boundary family policy or structural invariants. |
| `tools_denied_reason` | Stable denial reason such as `tool.unknown_family`, `tool.family_not_allowed`, or `tool.no_mix.exec_like`. |

Semantic tool denial is deterministic. Current runtime rule:
- `tool.unknown_family` — the declared tool does not match any configured boundary family pattern.
- `tool.family_not_allowed` — the declared tool's family is not admitted by the active boundary profile.
- `tool.no_mix.exec_like` — tools in the `exec_like` family (`code.*`, `shell.*`, `exec.*`) are denied when mixed with any other tool family in the same declaration.

Boundary config now carries `tool_policy.families` plus `tool_policy.matrix`:
- `public` — anonymous stays minimal, trusted callers may add retrieval families
- `operator` — `user`/`operator`/`internal` get progressively broader allowlists
- `demo` — `*`

Boundary config also carries `request_policy.classification.light_budget` plus `request_policy.matrix`:
- request classes: `probe`, `intent`, `execution_light`, `execution_heavy`
- matrix key: `(exposure_mode, trust_class, request_class)`
- rule payload: `decision` plus optional `max_budget`

The gateway injects this as `payload.inputs.extensions.gateway_request_policy` before policy evaluation and records the resulting request/budget fields in DECISION.

### EXECUTION Fields

| Field | Description |
|-------|-------------|
| `tool_calls` | Tool calls that passed enforcement. |
| `tool_blocked` | `[{"tool_call": name, "reason": "not_in_permitted_tools"}]` for blocked calls. |

### Enforcement

- **Strict**: undeclared tool calls are blocked and recorded in `tool_blocked`.
- **Advisory**: undeclared tool calls are logged but allowed through.

## Budget Constraint (v0.6.0+)

Clients may specify resource limits for execution.

### Intent Fields

```json
"budget": {
  "max_tokens": 4096,
  "max_duration_ms": 30000
}
```

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| `max_tokens` | `int` | 1-1000000 | Max output tokens for provider call. |
| `max_duration_ms` | `int` | 1000-300000 | Max execution wall clock (ms). |

Values must be integers (floats are rejected).

### DECISION Fields

```json
"enforced_budget": {
  "max_tokens": 4096,
  "max_duration_ms": 30000,
  "source": "intent_exact"
}
```

`source` is one of: `intent_exact` (client value used as-is), `intent_clamped` (client value clamped to runtime limit), `policy_default` (no client value, runtime default used).

`effective_timeout = min(runtime_wall_clock_ms, client_max_duration_ms)`.

### EXECUTION Fields

```json
"usage": {
  "duration_ms": 1234
}
```

## DECISION Payload (v0.9.0)

DECISION events include normative fields for replay verification:

```json
{
  "policy": {
    "policy_id": "...",
    "policy_version": "...",
    "policy_config_digest": "sha256:..."
  },
  "assembly_digest": "sha256:...",
  "context_digest": "sha256:...",
  "result": "ALLOW",
  "reasons": [...],
  "transforms": [...],
  "request_class": "execution_light",
  "budget_class": "light",
  "budget_policy_reason": "request.budget_clamped",
  "permitted_tools": ["web.search", "code.execute"],
  "enforced_budget": {"max_tokens": 4096, "max_duration_ms": 30000, "source": "intent_exact"},
  "intent_index": 0,
  "boundary": {
    "context_config_digest": "sha256:...",
    "boundary_version": "1"
  },
  "context_spec": {...},
  "assembled_context": {...}
}
```

All of `request_class`, `budget_class`, `budget_policy_reason`, `permitted_tools`, `enforced_budget`, `policy_config_digest`, and `intent_index` are normative (included in decision digest).

| Field | Since | Description |
|-------|-------|-------------|
| `policy.policy_config_digest` | v0.8.1 | SHA-256 of the policy rules, computed by the gateway |
| `intent_index` | v0.8.1 | Index of the originating INTENT event (decision lineage) |
| `boundary.context_config_digest` | v0.5.x | Pins the context configuration. `"CONTEXT_RESOLUTION_DISABLED"` when OFF |

## PROOF Event: Context Release Guard (v0.9.0)

Before execution, the gateway emits a PROOF event capturing a digest of the full provider payload:

```json
{
  "proof_type": "context_release_guard",
  "payload_digest": "sha256:...",
  "model_id": "gpt-4o-mini",
  "provider": "openai",
  "message_count": 3
}
```

The digest covers the canonical JSON of: `messages`, `model_id`, `provider`, `permitted_tools`, `enforced_budget`.

Feature-gated via `GATEWAY_ENABLE_RELEASE_GUARD` (default ON).

## EXECUTION Lineage (v0.9.0)

EXECUTION events include `release_digest` which must match the preceding PROOF event's `payload_digest`. This creates a verifiable chain: INTENT -> DECISION -> PROOF -> EXECUTION.
