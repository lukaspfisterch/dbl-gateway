# Dependency Surface

This document captures the local dependency surfaces used by dbl-gateway.

## Gateway binding points
- Policy adapter: `src/dbl_gateway/adapters/policy_adapter_dbl_policy.py`
- Execution adapter: `src/dbl_gateway/adapters/execution_adapter_kl.py`
- Projection adapter: `src/dbl_gateway/projection.py`
- Digest adapter: `src/dbl_gateway/digest.py`

## dbl-core
- Import root: `D:\DEV\projects\dbl-core-dev\src\dbl_core\__init__.py`
- Public API (`__all__`): `DblEvent`, `DblEventKind`, `BehaviorV`, `GateDecision`, `normalize_trace`
- Contract-bearing modules:
  - Canonicalization and digest: `dbl_core/events/canonical.py`, `dbl_core/events/digest.py`
  - Event model and invariants: `dbl_core/events/model.py`
  - Trace digest: `dbl_core/events/trace_digest.py`
  - Gate decision model: `dbl_core/gate/model.py`
  - Trace normalization: `dbl_core/normalize/trace.py`

## dbl-policy
- Import root: `D:\DEV\projects\dbl-policy\src\dbl_policy\__init__.py`
- Public API (`__all__`): `DecisionOutcome`, `Policy`, `PolicyContext`, `PolicyDecision`, `PolicyId`, `PolicyVersion`, `TenantId`, `decision_to_dbl_event`
- Contract-bearing modules:
  - Policy context schema and decisions: `dbl_policy/model.py`

## dbl-main
- Import root: `D:\DEV\projects\dbl-main\src\dbl_main\__init__.py`
- Public API (`__all__`): `Phase`, `RunnerStatus`, `State`, `project_state`, `runner_status_from_phase`
- Contract-bearing modules:
  - Orchestrator state projection: `dbl_main/state_projection.py`

## kl-kernel-logic
- Import root: `D:\DEV\projects\kl-kernel-logic-dev\src\kl_kernel_logic\__init__.py`
- Public API (`__all__`): `PsiDefinition`, `Kernel`, `ExecutionTrace`, `FailureCode`, `CAEL`, `CaelResult`
- Contract-bearing modules:
  - Execution kernel and trace model: `kl_kernel_logic/kernel.py`
  - Psi definition: `kl_kernel_logic/psi.py`
  - CAEL pipeline: `kl_kernel_logic/cael.py`

## dbl-ingress
- Import root: `D:\DEV\projects\dbl-ingress\src\dbl_ingress\__init__.py`
- Public API (`__all__`): `AdmissionRecord`, `AdmissionError`, `InvalidInputError`, `shape_input`
- Contract-bearing modules:
  - Admission record validation: `dbl_ingress/admission/model.py`
  - JSON type constraints: `dbl_ingress/admission/json_types.py`
  - Shaping entry point: `dbl_ingress/shaping/shape.py`
