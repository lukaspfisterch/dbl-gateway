# Contract Boundary

This document defines the `1.x` contract of `dbl-gateway` and what still
remains an evolving surface around it.

It is not a capability list.
It is the boundary between:

- what integrators should be able to build against
- what may continue to expand without redefining the core runtime contract

## Stable

These are the parts of `dbl-gateway` that remain stable across the `1.x` line
unless a deliberate breaking change is called out.

### Event chain

The runtime chain is:

```text
INTENT → DECISION → PROOF → EXECUTION
```

The ordering is structural:

- `DECISION` is the only normative event
- `DECISION` precedes any allowed execution
- `PROOF` precedes provider execution when release guarding is enabled
- `EXECUTION` remains observational

### DECISION role and semantics

The gateway contract is that `DECISION` carries the normative result of the
request.

At a stable level this includes:

- policy verdict
- identity and trust footprint
- request classification footprint
- budget and economic shaping footprint
- lineage back to the originating intent

Field sets may grow carefully, but the role of `DECISION` as the normative
record must not drift into execution, UI, replay helpers, or provider adapters.

### Boundary config as a hashed artifact

Boundary configuration is part of the contract.

The active boundary is treated as a versioned artifact and contributes to the
deterministic input line for governance and replay. That includes:

- exposure mode and surface rules
- public admission rules
- tool policy
- request policy
- economic policy
- identity policy

### Deterministic replay guarantees

The contract of the gateway includes deterministic replay at the decision layer.

That means:

- governance works only from admitted authoritative inputs
- replay can reconstruct the normative path from stored artifacts
- observational execution data must not silently change the decision outcome

## Evolving

These parts are expected to keep moving without redefining the stable core.

### Capability surfaces

The contents of discovery surfaces may continue to evolve, including:

- `/capabilities`
- `/surfaces`
- `/intent-template`
- operator-facing summaries

Those surfaces should stay truthful, but they are not the stable core contract.

### Policy dimensions and detail

The boundary may grow more detail over time in areas such as:

- tool families
- request classes
- economic classes
- identity mapping detail
- tenant derivation detail

The principle stays stable even if the concrete dimensions expand.

### Provider integrations

Provider support, adapter polish, and execution ergonomics remain evolving
product seams. They are important, but they are not the same thing as the
stable decision contract.

## What 1.0 means

`1.0` does not mean "feature complete".

It means:

- the core boundary-to-decision contract is stable
- integrators can rely on the event chain and replay guarantees
- later expansion happens around that contract, not by redefining it

## What this does not mean

This document does not promise:

- frozen `/capabilities` payloads forever
- fixed provider set forever
- no new boundary dimensions ever
- no new client-facing helper layers

It only fixes the ground those changes must stand on.
