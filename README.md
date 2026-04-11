# dbl-gateway

Deterministic governance for non-deterministic systems.

Inspect and replay LLM decisions through a deterministic execution boundary.

Every request produces a decision chain:
what was requested, what was decided, what was executed.

[![pytest](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/lukaspfisterch/dbl-gateway/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/dbl-gateway.svg)](https://pypi.org/project/dbl-gateway/)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://pypi.org/project/dbl-gateway/)

Run it in 1 minute with Docker, or install the package and connect your own provider.

No API keys required:

```bash
docker compose --profile demo up
```

Open [http://localhost:8010/ui](http://localhost:8010/ui) and click **Start Demo**.

The demo runs scripted scenarios through the full governance pipeline.
Use **Manual Intent** in the observer to submit your own requests —
the gateway is a working runtime, not just a demo harness.

![Observer UI](pictures/demorun.png)

## How it works

Every request passes through the same deterministic chain:

    INTENT  →  DECISION  →  PROOF  →  EXECUTION

**INTENT** records what was asked.
**DECISION** records what policy allowed — the only normative event.
**PROOF** records what will be sent to the provider.
**EXECUTION** records what happened.

Execution output never feeds back into policy.

Part of the [Deterministic Boundary Layer](https://github.com/lukaspfisterch/deterministic-boundary-layer) architecture.

## Use your own provider

```bash
cp .env.example .env        # add one API key (OpenAI, Anthropic, or Ollama)
docker compose up
```

One active provider is enough. See [.env.example](.env.example) for all options.

The default runtime boundary profile is `operator`:
- `/ingress/intent`, `/capabilities`, `/snapshot`, `/tail`, `/status`, `/surfaces`, and `/intent-template` stay available
- `/ui/*` is not exposed

The full built-in observer is demo-only unless you explicitly select the demo boundary config.
In `public`, the boundary still blocks high-risk shapes like `artifact.handle`, `declared_refs`, and over-broad tool declarations before any `INTENT` is appended.
High-risk context intents are only advertised in discovery when the active boundary/runtime can actually admit them.
Even outside `public`, handle-derived content is `metadata_only` by default and requires explicit `model_context` opt-in before it can enter prompt context.
The same boundary artifact now also declares tool families plus an exposure-by-trust matrix, and a request-policy matrix for request classes and budget ceilings. Tool and budget governance are therefore versioned, discoverable, and replay-stable instead of being hidden in execution.
Request classification now stays explicit in the decision line: `request_class`, `request_semantic_reason`, `request_constraints_applied`, and budget `source` explain whether a request was denied, allowed as-is, or clamped by the boundary.
The boundary now also declares economic shaping per request class. `slot_class`, `cost_class`, `reservation_required`, and `economic_policy_reason` enter DECISION normatively, but actual slot availability still remains an execution concern instead of feeding back into governance.
Identity now follows the same pattern: the gateway resolves a minimal verified identity line into `actor_id`, `tenant_id`, `roles`, `issuer`, `verified`, and `trust_class`, injects that into policy-visible inputs, and records the result in DECISION. The runtime stays generic: local dev headers work today, and later OIDC issuers such as Azure AD can plug into the same trust seam without changing tool, request, or economic policy structure.
OIDC is now treated as an adapter seam above that boundary logic: the adapter verifies JWTs against cached JWKS plus issuer/audience allowlists, maps claims into gateway roles, and emits `identity_source` plus `claims_digest` for audit without introducing gateway-owned user state.
The allowed identity mode and claim mapping are now part of the versioned boundary artifact as `identity_policy`, so trust derivation is no longer just an env/runtime concern.
Operator-facing discovery now exposes only the active identity structure that matters for boundary interpretation: `claim_mapping` field names and a compact `role_mapping_summary`. `public` omits that view entirely to avoid turning capability discovery into identity-topology recon.
In `public`, capabilities only advertise request classes that are actually allowed for the current caller instead of leaking denied heavy classes through discovery.
Startup logging now emits a concise config summary instead of listing every possible provider env var.

## Install

```bash
pip install dbl-gateway
```

Or from source:

```bash
pip install -e .
```

## Reference implementation

`dbl-gateway` implements the Deterministic Boundary Layer (DBL) as a runtime
system.

It realizes the event chain INTENT → DECISION → PROOF → EXECUTION, where
DECISION events are recorded before any execution and remain the only
normative layer. Execution outputs are treated as non-normative observations.

The gateway enforces the core invariants of the model:
- append-only event stream
- strict ordering of DECISION before EXECUTION
- governance input purity (authoritative inputs only)
- deterministic replay under fixed inputs and policy configuration

As such, it serves both as a usable governed gateway and as a reference
implementation of the DBL model.

For empirical validation, including replay equivalence and policy variation
benchmarks, see
[EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md).

## Observer UI

Open `/ui` only when the active boundary profile is `demo`.

The built-in observer includes the event stream, decision replay, chain
verification, a policy inspector for DECISION events, manual intent
submission, and the integrated demo controller.

## Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) — first request, reading events, UI verification
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — surfaces, component ownership, invariants
- [EMPIRICAL_VALIDATION.md](docs/EMPIRICAL_VALIDATION.md) — optional replay bench and policy-diff notes
- [wire_contract.md](docs/wire_contract.md) — envelope format, tool gating, budget, refs
- [env_contract.md](docs/env_contract.md) — all environment variables
- [observer.md](docs/observer.md) — UI layout and verification routes
- [demo.md](docs/demo.md) — demo modes and scenario definition
- [Full manifest](docs/MANIFEST.md)
