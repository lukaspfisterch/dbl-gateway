# Invariants

Invariants that the gateway maintains across all requests. Violations are bugs.

## Tool Gating

**I-TOOL-1**: If `tool_scope_enforced == "strict"` and a provider returns a tool call whose `tool_name` is not in `permitted_tools`, the call MUST appear in `tool_blocked` (not `tool_calls`) in the EXECUTION event.

**I-TOOL-2**: Every tool call returned by the provider appears in exactly one of `tool_calls` or `tool_blocked` in the EXECUTION event. No call is silently dropped.

## Budget Constraint

**I-BUDGET-1**: `enforced_budget.max_duration_ms <= runtime_wall_clock_ms`. The client cannot increase the execution timeout beyond the runtime limit.

**I-BUDGET-2**: `enforced_budget.max_tokens` is passed to the provider call as-is. The gateway does not modify the token budget.

## Context Resolution Gate

**I-GATE-1**: When `GATEWAY_ENABLE_CONTEXT_RESOLUTION` is OFF, no context resolution or ref fetching occurs. `declared_refs` are stored in the INTENT event payload for audit only.

**I-GATE-2**: When context resolution is OFF, `artifact.handle` intents are rejected at ingress (before INTENT event is appended).

## Wire Contract

**I-WIRE-1**: Requests with `interface_version != 3` are rejected at ingress.

## Decision Normative Surface

**I-NORM-1**: `permitted_tools` and `enforced_budget` are included in the normative decision digest. Changes to these fields produce a different digest.
