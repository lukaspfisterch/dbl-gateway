# Empirical Validation

Quantitative evidence that the gateway enforces its core axioms at runtime.

## What is tested

`scripts/bench_replay.py` runs a single reproducible loop:

    generate → record → replay → compare

**Phase 1 — Generate.**
N intents are sent through the gateway (stub provider, mixed payload patterns).
Every turn produces INTENT → DECISION → EXECUTION events in the append-only
stream V.

**Phase 2 — Replay.**
Every DECISION event is replayed via `/ui/replay`: the stored authoritative
inputs and policy configuration are re-evaluated, a new decision digest is
computed, and the result is compared to the stored digest.

**Phase 3 — Policy Diff.**
The same INTENT inputs from V are re-evaluated against a second, stricter
policy (direct store access, no HTTP). Outcome flips (ALLOW→DENY) are counted
without re-executing any turn.

## Results (N = 1000)

| Metric | Value |
|---|---|
| Events generated | 3000 |
| DECISION events | 1000 |
| ALLOW / DENY ratio (v1) | 1000 / 0 |
| Replay time (avg) | 245.88 ms |
| Digest matches | 1000/1000 |
| Policy v1 | dbl_policy.allow_all |
| Policy v2 | bench.strict_extensions |
| v1→v2 ALLOW→DENY | 200 |
| v1→v2 DENY→ALLOW | 0 |
| v1→v2 unchanged | 800 |

All 1000 DECISION events reproduced identical digests under replay with fixed
authoritative inputs and unchanged policy configuration.

Under a modified policy (bench.strict_extensions), 200 of 1000 decisions
flipped from ALLOW to DENY without requiring re-execution.

## What this validates

**Replay Equivalence (A3).** The append-only stream V preserves all
authoritative inputs needed to reproduce any DECISION. Digests are
deterministic: same inputs + same policy = same digest.

**Policy Exchangeability.** Governance is deterministic but
policy-exchangeable. A different policy produces different outcomes from the
same recorded inputs, without touching the execution layer. The normative
layer (DECISION) and the observational layer (EXECUTION) are structurally
independent.

## Invariants under test

| Invariant | What the bench verifies |
|---|---|
| I-STREAM-1 (A1) | Events are append-only; V is intact after 1000 turns |
| I-ORDER-1 (A5) | Every EXECUTION is preceded by a DECISION |
| I-GOV-INPUT-1 (A3) | Replay uses only authoritative inputs, no execution data |
| I-NORM-1 (A2) | Only DECISION digests are compared; EXECUTION is non-normative |

## Reproduce

```bash
# Start gateway with stub provider
GATEWAY_DEMO_MODE=1 STUB_MODE=scenario dbl-gateway serve

# Run bench (100 turns, fast)
python scripts/bench_replay.py --turns 100 --policy-diff --db data/bench_trail.sqlite

# Full run (1000 turns, ~5 min)
python scripts/bench_replay.py --turns 1000 --policy-diff --db data/bench_trail.sqlite --report markdown
```

Output formats: `text` (default), `markdown` (paper-ready table), `json` (machine-readable).

Exit code 0 = all digests match. Exit code 1 = mismatch detected.

## v2 policy

The stricter policy (`bench.strict_extensions`) denies any intent whose
governance inputs contain non-scalar values in `extensions`. This is a
minimal shape-validation rule that a production compose policy would enforce.
It exists solely to demonstrate policy exchangeability — not as a realistic
governance configuration.
