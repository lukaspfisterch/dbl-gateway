# Stabilization Stack Map

This document is the single page map that ties together trails, actions, packs, and surfaces.
It is intentionally minimal: it defines responsibilities, flow, and contracts.
It is not a product spec and does not introduce new abstractions.

## 1. Parts

### Trails
- **V (append-only event stream)**: ordered, replayable record of what happened.
- **Digests**: event digest and V digest provide stable identity for replay and diff.
- **Snapshots**: bounded views over V for transport and UI.

### Actions
- **INTENT**: declares a request and freezes the environment metadata used for attribution.
- **DECISION**: explicit stabilization commit, the only normative event in V_norm.
- **EXECUTION**: observational outputs produced after a decision, never normative.
- **PROOF**: observational verification artifacts, never normative.
- **POLICY_UPDATE_DECISION**: explicit operator commit changing policy version.
- **BOUNDARY_UPDATE_DECISION**: explicit operator commit changing boundary version or config hash.

### Packs
- **Policy Pack**: versioned policy artifact, referenced by digest and policy_version.
- **Boundary Config**: versioned boundary artifact, referenced by boundary_version and boundary_config_hash.
- **Identity Rules**: required deterministic fields that make stabilization attributable and replayable.

### Surfaces
- **Console**: observer-only inspector (stream, V_norm projection, verifier, diff or replay).
- **Connectors**: wire adapters (not SDK imports) for fetching snapshots and pack metadata.
- **Verifier**: checks ordering, identity-field presence, canonicalization, and projection invariants.

## 2. Flow (end to end)

1) **Ingress** admits traffic and writes `INTENT` with frozen environment metadata.
2) **Governance** writes `DECISION` (or `*_UPDATE_DECISION`) as explicit stabilization.
3) **Execution** may run after a decision and writes `EXECUTION` as observation only.
4) **Proof** may be produced and written as `PROOF` as observation only.
5) **Trail** remains append-only; replay and diff are defined by canonical bytes and digests.
6) **Console** reads snapshots, projects `V_norm` (DECISION-only), and verifies invariants.

Principle: traffic may be continuous, but stabilization is discrete and explicit.
Past stabilization is immutable; it is not reinterpreted, only replayed.

## 3. Contracts (wire-first)

### 3.1 Snapshot Envelope
A snapshot is a transport view over V and must be self describing:

- `interface_version`: integer identifying the wire contract version.
- `stack_fingerprint`: object with producer build identity and pack digest references.
  policy_pack_digest is a digest-ref or "unknown".
  boundary_config_hash is an opaque string and may be "unknown".
- `v_digest`: rolling digest of the full V prefix known by the producer.
- `length`: producer-known total length of V.
- `events`: ordered list of event summaries.

The console must reject unsupported `interface_version` values.

Write envelopes include `interface_version` and the gateway rejects unsupported versions.
`v_digest` is independent of paging parameters; `events` are a window view.
- /llm/call is a domain runner surface and is not a generic wire envelope.

### 3.2 Event Summary (minimal)
Event summaries are observational rows. They do not imply correctness or stabilization.

Required fields:
- `index`: integer, 0-based ordering.
- `kind`: string event kind.
- `correlation_id`: string, stable grouping identifier.
- `digest`: digest-ref `sha256:<hex>` of deterministic fields only.
- `canon_len`: length of canonical bytes used for digesting.
- `payload`: event payload (deterministic content for the console display).

Rule: observational-only fields must not affect the digest.
If present, a top-level `_obs` key is excluded from digesting.
Auth attribution is observational only and stored under `_obs`.

### 3.3 Identity Field Rules (deterministic)
Identity fields are required for replayability and attribution.

- For `INTENT`:
  - `correlation_id`
  - `boundary_version`
  - `boundary_config_hash`
  - `input_digest` or `intent_digest`
- For `DECISION`:
  - `correlation_id`
  - `policy_version`
  - optional: `policy_digest` (if available)
- For `POLICY_UPDATE_DECISION`:
  - `policy_version`
  - `policy_digest`
  - optional: `policy_pack_digest`
- For `BOUNDARY_UPDATE_DECISION`:
  - `boundary_version`
  - `boundary_config_hash`

The console surfaces identity violations as verifier findings.
The console does not auto-correct or infer missing identity fields.

### 3.5 Boundary vs policy allowlists
- Tenant boundary allowlist is enforced before INTENT is written.
- Policy allowlists (tenant, model, role) can produce DECISION DENY after INTENT.

### 3.4 Projection Rule (normative)
`V_norm` is defined as:
- `V_norm = { e in V | e.kind in {DECISION, POLICY_UPDATE_DECISION, BOUNDARY_UPDATE_DECISION} }`

Rule: projection is structural, not interpretive.

## 4. Integration Discipline (connectors)

- Connectors are **wire adapters**: they must not import Python types from upstream runtimes.
- Integrations are optional dependencies and must not be required for core console operation.
- Version mismatch handling is explicit:
  - reject unsupported interface versions
  - display digests and raw payloads for unknown fields
  - never best effort a normative interpretation

## 5. Non-goals

- The console does not evaluate policy.
- The console does not execute actions.
- The console does not optimize models.
- The console does not add a safety wrapper around AI.
- The console exists to inspect stabilization commits and their attribution surfaces.

## 6. Testable Invariants (examples)

- Append-only changes `v_digest` when deterministic events append.
- Ordering violations are detectable.
- `DECISION` requires policy identity fields.
- Observational-only changes do not affect event digest.
- Normative projection includes commit kinds only (DECISION, POLICY_UPDATE_DECISION, BOUNDARY_UPDATE_DECISION).
