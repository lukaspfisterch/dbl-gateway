# Changelog

## Unreleased
- Pending.

## 0.3.2
### Changed
- Stabilized gateway behavior and contracts within the existing 0.3.x stackline.
- Clarified authority boundaries between gateway, boundary, and UI clients.
- Tightened admission, governance, and execution flow without altering wire semantics.
- Refined policy and execution adapter integration while preserving determinism.

### Guarantees
- No changes to wire contracts or `interface_version`.
- No changes to event ordering, digest computation, or projection rules.
- Replay, digest, and decision primacy invariants remain unchanged.

### Tests
- Extended invariant-level tests covering admission, decision primacy, replay determinism, and digest stability.
- Verified reference replay compatibility against `dbl-reference`.
- Locked OpenAPI surface via snapshot tests.

### Notes
- This release does not introduce a new stackline.
- Compatible with the existing 0.3.x dependency ranges.
- Intended as a stabilization and consolidation release, not a feature expansion.

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
