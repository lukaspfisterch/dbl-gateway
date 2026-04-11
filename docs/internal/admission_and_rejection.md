## Admission and rejection

Admission uses `dbl-ingress` for shaping, validation, and reason-code taxonomy.
The gateway is the authority and performs admission.
Boundary and UI do not perform admission.

Rejections are returned as HTTP 4xx with:
- `reason_code`: stable string from the admission taxonomy
- `detail`: human-readable explanation

Rejected requests MUST NOT append an INTENT.

Public exposure mode adds deterministic boundary-derived reason codes:
- `admission.intent_type_denied`
- `admission.context_refs_denied`
- `admission.declared_tools_denied`
- `admission.budget_exceeds_public_limit`

These checks are evaluated from request content plus the active boundary artifact.
They must not depend on queue depth, timing, load, or other observational runtime state.
