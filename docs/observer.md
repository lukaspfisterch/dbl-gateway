# Observer

The gateway serves a built-in event observer at `/ui`.

It is a single-file browser surface that consumes the event stream via `/ui/tail`
and keeps all verification logic server-side.

![Observer UI](../pictures/demorun.png)

## Layout

- Left: `Agent Activity`, `Capabilities`, `Verify`, `Manual Intent`
- Center: event stream and bottom inspector
- Right: `Demo Agent`

## Stream

The stream groups events by `correlation_id` and shows:

- event kind
- intent type
- correlation id
- actor
- delta time inside a turn

## Inspector

Selecting an event opens the inspector with:

- `Event` view
- `Turn` view
- `Raw` view

From a selected `DECISION`, the inspector can trigger replay.

## Verification

The observer uses auth-free proxy routes:

- `GET /ui/snapshot`
- `GET /ui/verify-chain`
- `GET /ui/replay`

The browser never recomputes digests itself. It only triggers and renders
server-side verification results.

## Manual Intent

The `Manual Intent` panel can:

- send a valid minimal envelope through `POST /ui/intent`
- generate a valid `curl` example
- generate a valid PowerShell example

This turns the observer into a small execution playground, not just a viewer.
