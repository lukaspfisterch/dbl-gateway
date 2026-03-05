# Constitution

## What This System Is

dbl-gateway is the execution boundary for the Deterministic Boundary Layer.
It accepts declared intents, applies policy, executes permitted calls,
and records everything as an append-only event stream.

## Governing Principles

1. **Only DECISION events are normative.** Execution output never influences policy.
2. **Append-only.** Events are never updated or deleted.
3. **Explicit only.** No inferred context, no implicit history, no hidden state.
4. **Component ownership.** The gateway never reimplements logic owned by dbl-core, dbl-policy, kl-kernel-logic, or dbl-ingress.
5. **Deterministic digests.** SHA-256 over canonical JSON. Same inputs, same digest.

## What This System Is Not

- Not a RAG pipeline.
- Not a workflow engine.
- Not a chat UI.
- Not a model selector.

## Authority

The [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) specification is the theoretical authority. This gateway is one implementation of that specification.
