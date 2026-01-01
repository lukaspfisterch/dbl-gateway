# Changelog

## Unreleased
- Pending.

## 0.2.1
### Added
- Append-only DBL Gateway with leader-only write enforcement and follower read-only mode.
- Versioned wire contracts with explicit interface version validation.
- Snapshot and normative snapshot surfaces with stable `v_digest` semantics.
- Domain runner surface `/llm/call` with explicit INTENT → DECISION → EXECUTION ordering.
- Deterministic intent normalization and input digesting for LLM calls.
- OIDC and dev authentication modes with role mapping and tenant allowlisting.
- Idempotency-Key support for write deduplication.
- Stack fingerprint propagation (`policy_pack_digest`, `boundary_config_hash`).

### Guarantees
- Append-only event stream with monotonically increasing indices.
- Event digests exclude observational fields (`_obs`) while preserving full attribution.
- `v_digest` changes on any deterministic append and is independent of paging.
- Normative projection includes only DECISION, POLICY_UPDATE_DECISION, and BOUNDARY_UPDATE_DECISION.
- Governance decisions are independent of execution output.

### Tests
- End-to-end verification of ordering, digest stability, and replay invariants.
- Enforcement tests for boundary vs policy allowlists.
- Leader lock and follower mode rejection tests.
- OIDC authentication, role mapping, and tenant validation tests.

### Notes
- SQLite backend is the reference implementation and assumes a single writer process.
- Postgres backend is scaffolded but not yet implemented.
