# Goals & Purpose
- Deliver a deployable deterministic gateway, not a conceptual demo.
- Keep the system auditable, reproducible, and defensible over time.
- Support coherent multi-turn usage, deterministic decisions, reproducible context, and post-hoc audit without hidden state.
- Optimize for governance clarity over UX convenience or model creativity.

## Core Fields
### 1) Boundary and Policy (Normative Control)
- Purpose: Deterministic admission/decision layer governing what may proceed to execution.
- Responsibilities: Evaluate against explicit policies; produce deterministic DECISION artifacts; make rejections, transforms, and approvals explicit and replayable.
- Outputs: DECISION event; decision_digest; policy identifier and version.
- Non-Goals: No execution logic; no heuristic/adaptive behavior; no reliance on model outputs for governance decisions. If this layer is bypassed, governance does not exist.

### 2) Deterministic Context Assembly (Technical Motor)
- Purpose: Build reproducible, explainable context for downstream processing.
- Responsibilities: Construct context only from declared inputs and references; enforce canonical ordering and inclusion rules; produce a stable assembly digest.
- Outputs: context_spec; assembled context; assembly_digest (recorded as context_digest in 0.5.x).
- Non-Goals: No implicit context accumulation, hidden memory, or dynamic relevance scoring/learning. If context cannot be rebuilt deterministically, decisions and outputs are not explainable.

### 3) Session and State (Coherence Carrier)
- Purpose: Maintain coherence across interactions for use, demonstration, and audit over time (not a memory feature).
- Responsibilities: Anchor all events in a stable session structure; preserve causal ordering across turns; enable full thread reconstruction.
- Required Anchors: thread_id (required), turn_id (required), parent_turn_id (optional for forks).
- Non-Goals: No summarization, long-term memory products, or semantic user modeling. Without session identity, the gateway only processes isolated calls.

## Core Invariants
- No event exists without identity anchors (thread_id, turn_id).
- Equal inputs -> equal context -> equal digests.
- DECISION artifacts are replayable without execution.
- Observational data never influences normative digests.
- Behavior is explained through artifacts, not interpretation.

## Demonstrable Capabilities (success criteria)
- Same session, different context spec -> different assembly_digest -> different DECISION.
- Advisory content admitted while output scope is rejected by policy.
- Stable, replayable assembly_digest per turn.
- Full thread reconstruction with causal ordering.

## Explicit Non-Goals
- Not a chat framework, memory system, personalization engine, orchestration monolith, or learning system. Those belong elsewhere, not here.

## Design Principle
- Favor coherence over convenience, determinism over flexibility, auditability over opacity. If a feature cannot be explained, replayed, and defended, it does not belong in this gateway.
