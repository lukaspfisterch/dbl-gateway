# Env Contract

This document describes configuration for the gateway runtime.

## Runtime
- `DBL_GATEWAY_DB`: sqlite path (default `.\data\trail.sqlite`)
- `GATEWAY_EXEC_MODE`: `embedded` or `external` (default `embedded`)

## Provider credentials
- `OPENAI_API_KEY`: enables OpenAI models
- `ANTHROPIC_API_KEY`: enables Anthropic models

## Model lists
- `OPENAI_CHAT_MODEL_IDS`: comma list for chat/completions
- `OPENAI_RESPONSES_MODEL_IDS`: comma list for responses API
- `OPENAI_MODEL_IDS`: fallback list for chat models
- `ANTHROPIC_MODEL_IDS`: comma list

## Security expectations
- Secrets are never stored in event payloads.
- `/ingress/intent` is the canonical write surface.
- `/execution/event` is an optional write surface in `GATEWAY_EXEC_MODE=external`.
- AuthN/AuthZ and tenant gating are enforced at request entry.
