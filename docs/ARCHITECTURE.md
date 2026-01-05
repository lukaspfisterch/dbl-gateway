# DBL Gateway Architecture

This document defines structure, boundaries, and invariants for DBL Gateway.

## Purpose
- Authority of record for append-only stabilization trails.
- Accept authenticated writes, validate identity fields, persist events, serve snapshots.

## Non-goals
- No policy evaluation, execution, or optimization.
- No mutation or deletion of existing events.
- No identity inference or auto-correction.

## Core invariants
- Append-only stream with a monotonically increasing index.
- Event digest is computed from deterministic fields only.
- Any deterministic append changes `v_digest`.
- Normative projection includes only DECISION, POLICY_UPDATE_DECISION, BOUNDARY_UPDATE_DECISION.
- Identity fields must be present for each kind, missing fields are rejected.

## Trust boundaries
- AuthN validates who the caller is.
- AuthZ enforces required roles.
- Tenant allowlisting is enforced and is a trust boundary.
- Unknown tenant_id is rejected when allowlisting is enabled.
- Auth attribution is observational only and stored under `_obs`.
- Leader accepts writes, follower rejects writes.
- Single-writer behavior is enforced at the gateway mode boundary.

## Storage architecture
- Store interface abstracts append, snapshot, snapshot_norm, stream_status, close.
- SQLite is the reference backend.
- Postgres is planned later with the same interface.
- SQLite assumes a single-writer process.

## Wire contract discipline
- All external interaction is via versioned wire contracts.
- Write envelopes include `interface_version` and unsupported versions are rejected.
- /llm/call is a domain runner surface and is intentionally not a generic wire envelope.
- `v_digest` is a rolling digest of the full V prefix known to the producer.
- Paging parameters only affect the `events` window, not `v_digest`.
- Snapshot responses must pass `validate_wire_snapshot` server-side.
- Unsupported interface versions are rejected explicitly.

## Stack fingerprint
- `policy_pack_digest` is `unknown` or a digest-ref.
- `boundary_config_hash` is `unknown` or an opaque hash string.

## Determinism rules
- Canonical JSON encoding is stable and ASCII only.
- Gateway enforces canonicalizability for generic endpoints, not semantic normalization.
- `_obs` is excluded from event digesting and does not affect event digests.
