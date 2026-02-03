# Context References

> Deterministic context assembly for DBL Gateway.

This document describes how context references are handled in the gateway, including the separation between normative and observational inputs, the digest computation scope, and the invariants that must be maintained.

## Core Concepts

| Term | Definition |
|------|------------|
| `declared_refs` | Client-provided list of event references to include as context |
| `resolved_refs` | Gateway-validated references with metadata (event_index, event_digest, admitted_for) |
| `normative_inputs` | INTENT events admitted for governance (policy input) |
| `execution_only` | EXECUTION events admitted only for prompt construction, excluded from governance |
| `assembly_digest` | SHA256 over context_spec + assembled_context (deterministic identifier) |
| `context_digest` | Digest of final allowed model payload (ALLOW only; null on DENY) |
| `context_config_digest` | SHA256 over the context configuration (pinned in DECISION) |
| `I_context` | Normative context inputs (only INTENT payloads) |
| `O_context` | Observational context (EXECUTION outputs, post-decision only) |

## The I_context / O_context Split

The fundamental principle: **Observations must not influence governance decisions.**

The gateway never infers conversational context; all references are explicit and scope-bound.

### I_context (Normative)
- Contains only INTENT event payloads
- Used for policy evaluation (G)
- Included in `assembly_digest` computation
- Digests stored in `normative_input_digests`

### O_context (Observational)
- Contains EXECUTION event outputs (LLM responses)
- Used only for prompt construction **after** DECISION
- Excluded from `assembly_digest` computation
- Marked as `admitted_for: "execution_only"`

### Example 1: Chat History

```
Thread:
  INTENT-1:    "What is 2+2?"           ← I_context ✓
  EXECUTION-1: "2+2 equals 4"           ← O_context (execution_only)
  INTENT-2:    "Explain more"           ← I_context ✓
  
declared_refs: [INTENT-1, EXECUTION-1]

Resolution:
  resolved_refs: [
    {ref_id: "INTENT-1", admitted_for: "governance", event_digest: "sha256:..."},
    {ref_id: "EXECUTION-1", admitted_for: "execution_only", event_digest: "sha256:..."},
  ]
  
Policy sees: [INTENT-1]
Execution context receives: [INTENT-1, EXECUTION-1, INTENT-2]
```

Only explicitly declared references are admitted; no automatic history is added.

### Example 2: Policy Count Limit

```
Policy: "max 5 user messages per thread"

Thread: INTENT-1..5 (all governance)

Request INTENT-6 with declared_refs: [INTENT-1..5]
→ resolved_refs contains 5 governance refs
→ Policy sees 5 prior user messages + current = 6
→ Policy returns DENY
```



## Use in Execution

While **policy** only sees I_context (INTENTs), the **execution** (LLM prompt) receives the full resolved context (I_context + O_context).

1. **Assembly**: The gateway constructs a deterministic system message block from `resolved_refs`.
2. **Injection**: This block is prepended to the user's message.
3. **Execution**: The provider receives `[system_context, user_message]`.

This ensures execution receives explicit, deterministic references (O_context) while the policy remains purely normative (I_context).

## Digest Scope

### Included in `assembly_digest`

| Component | Reason |
|-----------|--------|
| `identity` (thread_id, turn_id, parent_turn_id) | Causal structure |
| `intent` (intent_type, user_input) | Current request |
| `declared_refs` | What client requested |
| `resolved_refs` (including execution_only) | What was resolved (audit trail) |
| `normalization` (applied_rules, config_digest) | Boundary configuration |
| `assembly_rules` (schema_version, ordering) | Determinism parameters |
| `normative_input_digests` | INTENT payload digests |

### Excluded from `assembly_digest`

| Component | Reason |
|-----------|--------|
| Timestamps | Non-deterministic |
| Event IDs (mutable storage identifiers) | Storage-internal |
| EXECUTION output content | Observational (Claim 4) |
| `_obs` fields | Explicitly observational |

## Replay Modes

### Stream Replay
- All events available in the event stream
- Refs resolved against stream
- `assembly_digest` recomputed and compared

### Ledger Replay
- Stream projected into database
- Queries against deterministic projection
- Same verification: recompute and compare

### What Can Be Verified

| Assertion | Verification Method |
|-----------|---------------------|
| Same config was used | `DECISION.boundary.context_config_digest == reloaded_config.digest` |
| Same refs were resolved | `DECISION.context_spec.retrieval.resolved_refs` contains event_digests |
| Same context was assembled | `recompute(context_spec, assembled_context) == stored.assembly_digest` |
| Final payload digest present only for ALLOW | `stored.context_digest != null` |
| No observation leaked | `normative_input_digests` contains only INTENT digests |

## Failure Modes

| Error | Code | Cause | Resolution |
|-------|------|-------|------------|
| Reference not found | `REF_NOT_FOUND` | ref_id doesn't match any event | Client must use valid correlation_id or turn_id |
| Cross-thread reference | `CROSS_THREAD_REF` | Referenced event belongs to different thread | Client must only reference events in current thread |
| Too many references | `MAX_REFS_EXCEEDED` | declared_refs.length > config.max_refs | Client must respect limits |
| Empty refs policy | `EMPTY_REFS_DENIED` | declared_refs is empty and policy is DENY | Client must provide at least one ref (or config must allow empty) |
| Policy evaluation error | `evaluation_error` | Policy evaluation raised an exception | DECISION includes `error_ref` pointing to a PROOF artifact |
| DENY is final | `DENY` | Policy returns DENY | `context_digest` is null and execution input is not emitted |

## Configuration

Context behavior is controlled by `config/context.json`:

```json
{
  "schema_version": "1",
  "context": {
    "max_refs": 50,
    "empty_refs_policy": "DENY",
    "expand_last_n": 10,
    "allow_execution_refs_for_prompt": true,
    "canonical_sort": "event_index_asc",
    "enforce_scope_bound": true
  },
  "normalization": {
    "rules": ["FILTER_INTENT_ONLY", "SCOPE_BOUND", "SORT_CANONICAL"]
  }
}
```

The config digest is computed once at startup and pinned in every DECISION event via `boundary.context_config_digest`.

## Invariants

1. **Observation excluded from dom(G)**: EXECUTION events never influence policy decisions
2. **Normalization materialized**: Every transformation is recorded in `context_spec.retrieval.normalization`
3. **Config pinned via digest**: Every DECISION contains `boundary.context_config_digest`
4. **Canonical ordering**: Refs are sorted by `event_index` regardless of client order
5. **Scope-bound refs**: All refs must belong to the same thread_id
6. **Replay recompute equality**: `recompute(stored_inputs) == stored.assembly_digest`

## Not Supported (Explicit Non-Goals)

- **Auto-expansion**: No automatic thread history inclusion
- **Summarization**: No LLM-based context compression
- **Hot reload**: Config is loaded once at startup
- **Cross-thread context**: Refs must be scope-bound to current thread
