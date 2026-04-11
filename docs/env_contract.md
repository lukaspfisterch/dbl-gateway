# Environment Contract

Gateway startup uses environment variables plus versioned JSON boundary/context artifacts.
Secrets never appear in event payloads.

## Runtime

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DBL_GATEWAY_DB` | yes | `./data/trail.sqlite` | SQLite path for the event trail |
| `DBL_GATEWAY_POLICY_MODULE` | yes | -- | Python module path for policy (e.g. `dbl_policy.allow_all`) |
| `DBL_GATEWAY_POLICY_OBJECT` | no | `POLICY` | Attribute name of the policy object in the module |
| `DBL_GATEWAY_BOUNDARY_CONFIG` | no | `config/boundary.json` | Path to the boundary config artifact controlling `exposure_mode`, surface rules, and public admission limits |
| `GATEWAY_EXEC_MODE` | no | `embedded` | `embedded` (in-process provider calls) or `external` (sidecar) |
| `GATEWAY_ENABLE_CONTEXT_RESOLUTION` | no | OFF | `true`/`1`/`yes` to enable declared_refs resolution and Workbench handle fetch. When OFF, refs are stored but not resolved; `artifact.handle` intents are rejected. |

## Boundary Profiles

Built-in boundary profiles live in `config/`:
- `boundary.json` — default `operator` profile
- `boundary.public.json` — minimized public surface
- `boundary.operator.json` — explicit operator surface profile
- `boundary.demo.json` — full demo/observer surface

`GATEWAY_DEMO_MODE=1` selects the demo boundary profile when no explicit boundary config path is set.

Each boundary artifact also contains `admission.public`:
- `allow_artifact_handle`
- `allow_declared_refs`
- `max_declared_tools`
- `max_budget.max_tokens`
- `max_budget.max_duration_ms`

These limits are enforced deterministically from request content plus boundary config. They do not depend on queue depth, load, timing, or other runtime observations.

## Provider Credentials

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Enables OpenAI models |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible endpoint |
| `ANTHROPIC_API_KEY` | Enables Anthropic models |
| `OLLAMA_HOST` | Ollama server URL (default `http://localhost:11434`) |

At least one provider must be configured for execution mode.

## Model Lists

Comma-separated model identifiers. Models are exposed through `/capabilities`.

| Variable | Provider | Notes |
|----------|----------|-------|
| `OPENAI_CHAT_MODEL_IDS` | OpenAI | Chat completions API |
| `OPENAI_RESPONSES_MODEL_IDS` | OpenAI | Responses API |
| `OPENAI_MODEL_IDS` | OpenAI | Fallback if chat/responses lists are absent |
| `ANTHROPIC_MODEL_IDS` | Anthropic | Messages API |
| `OLLAMA_MODEL_IDS` | Ollama | Local/remote models |

## Job Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `DBL_JOB_QUEUE_MAX` | 100 | Max queued jobs per type |
| `DBL_JOB_CONCURRENCY_INGEST` | 2 | Concurrent `case.ingest` jobs |
| `DBL_JOB_CONCURRENCY_EMBED` | 1 | Concurrent `case.embed` jobs |
| `DBL_JOB_CONCURRENCY_INDEX` | 1 | Concurrent `case.index` jobs |
| `DBL_JOB_CONCURRENCY_LLM` | 1 | Concurrent `chat.message` provider calls |
| `DBL_LLM_WALL_CLOCK_S` | 60 | LLM call wall-clock timeout (seconds) |

## Workbench Handle Fetch

Only relevant when `GATEWAY_ENABLE_CONTEXT_RESOLUTION=true`.

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOW_HANDLE_CONTENT_FETCH` | false | Enable content fetch for `artifact.handle` refs |
| `WORKBENCH_RESOLVER_URL` | -- | Base URL for content fetch (must be http/https) |
| `WORKBENCH_AUTH_BEARER_TOKEN` | -- | Optional bearer token |
| `WORKBENCH_FETCH_TIMEOUT_MS` | 1500 | Fetch timeout |
| `WORKBENCH_MAX_BYTES` | 512000 | Max content size |
| `WORKBENCH_ADMIT_KINDS` | `extracted_text,summary` | Allowed artifact kinds |

## Security Expectations

- Secrets are never stored in event payloads.
- `/ingress/intent` is the canonical write surface.
- `/execution/event` is an optional write surface when `GATEWAY_EXEC_MODE=external`.
- AuthN/AuthZ and tenant gating are enforced at request entry.
