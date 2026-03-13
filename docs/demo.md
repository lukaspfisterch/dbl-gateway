# Demo

The observer includes an integrated `Demo Agent` panel and the repository also
ships a CLI demo agent.

Both use the same scenario definition.

## Scenario

The default demo sequence is:

1. normal turn
2. follow-up turn
3. tools-and-budget turn
4. intentional deny
5. recovery turn

## UI Demo

The browser starts the integrated demo through:

- `GET /ui/demo/status`
- `POST /ui/demo/start`

This produces a reproducible turn sequence while the observer is open.

## CLI Demo

```bash
./.venv/bin/python scripts/demo_agent.py --base-url http://127.0.0.1:8010
```

The CLI agent:

- checks gateway health
- checks capabilities for an active provider/model
- sends the scripted turns
- prints progress as the gateway emits events

## Runtime Notes

- Demo completion is tracked against the concrete thread timeline, not a bounded
  snapshot window.
- UI polling logs are suppressed by default so local runs stay readable.
