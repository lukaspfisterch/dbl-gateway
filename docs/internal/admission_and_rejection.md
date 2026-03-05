## Admission and rejection

Admission uses `dbl-ingress` for shaping, validation, and reason-code taxonomy.
The gateway is the authority and performs admission.
Boundary and UI do not perform admission.

Rejections are returned as HTTP 4xx with:
- `reason_code`: stable string from the admission taxonomy
- `detail`: human-readable explanation

Rejected requests MUST NOT append an INTENT.
