# Invariants

Invariants that the gateway maintains across all requests. Violations are bugs.

## Substrate Axioms (from DBL Paper)

These invariants enforce the formal axioms from the DBL paper. They are the foundation on which all other invariants rest.

**I-STREAM-1** (A1): The event stream V is append-only. Once an event is persisted, it MUST NOT be modified or removed. The only allowed mutation is `append(e_new)`. Enforced via SQLite triggers that block UPDATE and DELETE on the events table.

**I-ORDER-1** (A5): For each turn, `t(DECISION) < t(EXECUTION)`. An EXECUTION event MUST NOT be appended unless a DECISION event already exists for the same turn. Enforced in the store layer before insertion.

**I-GOV-INPUT-1** (A3/A4): Governance input MUST be derived exclusively from authoritative inputs I_L. Observational data O_obs (provider responses, execution results, timing, traces) MUST NOT be present in the input to `PolicyPort.decide()`. Enforced by key-set validation before every policy call. Allowed keys: `stream_id`, `lane`, `actor`, `intent_type`, `correlation_id`, `payload`, `tenant_id`.

**I-STREAM-2** (A1): Events are cryptographically linked. The stream digest `v_digest` is updated on every append via `v_digest_step(prev_digest, index, event_digest)`. A replayer can recompute the full digest from the event sequence and verify stream integrity.

**I-NORM-1** (A2): Only DECISION events are normative. `V_norm = { e in V | kind(e) = DECISION }`. INTENT, EXECUTION, and PROOF events are observational and carry no normative authority. The `is_authoritative` field is set exclusively for DECISION events.

## Tool Gating

**I-TOOL-1**: If `tool_scope_enforced == "strict"` and a provider returns a tool call whose `tool_name` is not in `permitted_tools`, the call MUST appear in `tool_blocked` (not `tool_calls`) in the EXECUTION event.

**I-TOOL-2**: Every tool call returned by the provider appears in exactly one of `tool_calls` or `tool_blocked` in the EXECUTION event. No call is silently dropped.

## Budget Constraint

**I-BUDGET-1**: `enforced_budget.max_duration_ms <= runtime_wall_clock_ms`. The client cannot increase the execution timeout beyond the runtime limit.

**I-BUDGET-2**: `enforced_budget.max_tokens` is passed to the provider call as-is. The gateway does not modify the token budget.

## Context Resolution Gate

**I-GATE-1**: When `GATEWAY_ENABLE_CONTEXT_RESOLUTION` is OFF, no context resolution or ref fetching occurs. `declared_refs` are stored in the INTENT event payload for audit only.

**I-GATE-2**: When context resolution is OFF, `artifact.handle` intents are rejected at ingress (before INTENT event is appended).

**I-GATE-3**: When `context.handle_content_fetch.high_risk_context_admit_mode != "model_context"`, handle-derived content MUST NOT enter model context. Handle refs may remain metadata-only and auditable, but fetched content does not populate prompt context.

## Wire Contract

**I-WIRE-1**: Requests with `interface_version != 3` are rejected at ingress.

## Decision Normative Surface

**I-NORM-1**: `request_class`, `budget_class`, `budget_policy_reason`, `permitted_tools`, `enforced_budget`, `policy_config_digest`, and `intent_index` are included in the normative decision digest. Changes to these fields produce a different digest.

## Chain-of-Record (v0.9.0)

**I-CHAIN-1**: Every DECISION event contains `intent_index` linking to its originating INTENT event index.

**I-CHAIN-2**: When the release guard is enabled, a PROOF event with `proof_type: "context_release_guard"` is emitted between DECISION and EXECUTION.

**I-CHAIN-3**: `EXECUTION.release_digest` matches the preceding `PROOF.payload_digest`. A replayer can verify that the executed payload matches what was recorded before execution.

**I-CHAIN-4**: `policy_config_digest` is computed by the gateway over the policy rules object. Different policy configurations produce different digests.

## Policy Externalization (v0.7.0)

**I-POLICY-1**: The gateway contains zero policy decision logic. All decisions are delegated through `PolicyPort.decide()`.
