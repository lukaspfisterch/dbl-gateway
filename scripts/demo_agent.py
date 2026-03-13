from __future__ import annotations

import argparse
import sys
import time
import uuid
from typing import Any

import httpx
from dbl_gateway.demo_agent import DemoStep, active_provider_model, build_envelope, default_steps


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Drive dbl-gateway with a small visible demo script.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8010",
        help="Gateway base URL. Default: http://127.0.0.1:8010",
    )
    parser.add_argument(
        "--stream-id",
        default="default",
        help="Target stream_id. Default: default",
    )
    parser.add_argument(
        "--lane",
        default="demo",
        help="Lane used for demo intents. Default: demo",
    )
    parser.add_argument(
        "--actor",
        default="demo-agent",
        help="Actor label shown in the observer. Default: demo-agent",
    )
    parser.add_argument(
        "--thread-id",
        default="",
        help="Optional fixed thread_id. Default: generated per run",
    )
    parser.add_argument(
        "--step-delay",
        type=float,
        default=2.0,
        help="Default delay after each step in seconds. Default: 2.0",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="Polling interval for turn progress in seconds. Default: 0.5",
    )
    parser.add_argument(
        "--turn-timeout",
        type=float,
        default=30.0,
        help="Max time to wait for one turn to complete. Default: 30.0",
    )
    parser.add_argument(
        "--auth-token",
        default="",
        help="Optional bearer token for protected gateways.",
    )
    return parser.parse_args()


def _headers(token: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _require_ok(resp: httpx.Response, context: str) -> None:
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            body = resp.json()
            detail = f" response={body!r}"
        except Exception:
            detail = f" response={resp.text[:300]!r}"
        raise SystemExit(f"{context} failed: {exc}{detail}") from exc


def _preflight(client: httpx.Client, token: str) -> str:
    print("== Preflight ==")
    health = client.get("/healthz", headers=_headers(token))
    _require_ok(health, "GET /healthz")
    print("gateway: healthy")

    capabilities = client.get("/capabilities", headers=_headers(token))
    _require_ok(capabilities, "GET /capabilities")
    caps = capabilities.json()
    active = active_provider_model(caps)
    if active is None:
        raise SystemExit(
            "No active providers/models found via GET /capabilities. "
            "Start the gateway with at least one reachable provider before running the demo agent."
        )

    provider_id, model_id = active
    print(f"provider: {provider_id}")
    print(f"model:    {model_id}")
    print()
    return model_id


def _short(value: Any, limit: int = 16) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _format_event(event: dict[str, Any]) -> str:
    kind = str(event.get("kind") or "UNKNOWN")
    idx = event.get("index", "?")
    payload = event.get("payload") or {}
    digest = _short(event.get("digest"))
    if kind == "DECISION":
        result = payload.get("result") or payload.get("decision") or "?"
        reasons = ",".join(str(code) for code in (payload.get("reason_codes") or []))
        return f"#{idx} {kind} result={result} reasons=[{reasons}] digest={digest}"
    if kind == "PROOF":
        payload_digest = _short(payload.get("payload_digest"))
        return f"#{idx} {kind} payload_digest={payload_digest} digest={digest}"
    if kind == "EXECUTION":
        provider = payload.get("provider") or "?"
        model_id = payload.get("model_id") or "?"
        duration = ((payload.get("usage") or {}).get("duration_ms"))
        if duration is None:
            return f"#{idx} {kind} provider={provider} model={model_id} digest={digest}"
        return f"#{idx} {kind} provider={provider} model={model_id} duration_ms={duration} digest={digest}"
    return f"#{idx} {kind} digest={digest}"


def _fetch_turn_events(
    client: httpx.Client,
    *,
    token: str,
    stream_id: str,
    correlation_id: str,
) -> list[dict[str, Any]]:
    snap = client.get(
        "/ui/snapshot",
        params={"stream_id": stream_id, "limit": 100, "offset": 0},
        headers=_headers(token),
    )
    _require_ok(snap, "GET /ui/snapshot")
    events = snap.json().get("events") or []
    return [
        event for event in events
        if event.get("correlation_id") == correlation_id
    ]


def _wait_for_turn(
    client: httpx.Client,
    *,
    token: str,
    stream_id: str,
    correlation_id: str,
    timeout_s: float,
    poll_interval: float,
) -> dict[str, Any]:
    started = time.monotonic()
    seen_indices: set[int] = set()
    final_decision: str | None = None

    while (time.monotonic() - started) < timeout_s:
        events = _fetch_turn_events(
            client,
            token=token,
            stream_id=stream_id,
            correlation_id=correlation_id,
        )
        for event in events:
            index = event.get("index")
            if not isinstance(index, int) or index in seen_indices:
                continue
            seen_indices.add(index)
            print("  event:", _format_event(event))
        for event in events:
            if event.get("kind") != "DECISION":
                continue
            payload = event.get("payload") or {}
            final_decision = str(payload.get("result") or payload.get("decision") or "")
        if final_decision == "DENY":
            return {"events": events, "decision": "DENY"}
        if any(event.get("kind") == "EXECUTION" for event in events):
            return {"events": events, "decision": final_decision or "ALLOW"}
        time.sleep(poll_interval)

    raise SystemExit(f"Timed out waiting for turn events for correlation_id={correlation_id}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    args = _parse_args()
    base_url = args.base_url.rstrip("/")
    thread_id = args.thread_id.strip() or f"demo-thread-{uuid.uuid4().hex[:8]}"
    steps = default_steps(args.step_delay)

    print("dbl-gateway demo agent")
    print(f"gateway: {base_url}")
    print(f"thread:  {thread_id}")
    print(f"actor:   {args.actor}")
    print(f"lane:    {args.lane}")
    print()

    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        requested_model_id = _preflight(client, args.auth_token)
        parent_turn_id: str | None = None

        for idx, step in enumerate(steps, start=1):
            turn_id = f"turn-{idx}"
            envelope = build_envelope(
                step=step,
                requested_model_id=requested_model_id,
                stream_id=args.stream_id,
                lane=args.lane,
                actor=args.actor,
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
            )
            print(f"== Step {idx}/{len(steps)}: {step.name} ==")
            print(step.description)
            print(f"expected: {step.expected}")
            resp = client.post("/ingress/intent", headers=_headers(args.auth_token), json=envelope)
            _require_ok(resp, "POST /ingress/intent")
            ack = resp.json()
            correlation_id = str(ack.get("correlation_id") or envelope["correlation_id"])
            print(
                "ack: accepted={accepted} queued={queued} index={index} correlation_id={correlation_id}".format(
                    accepted=ack.get("accepted"),
                    queued=ack.get("queued"),
                    index=ack.get("index"),
                    correlation_id=correlation_id,
                )
            )
            result = _wait_for_turn(
                client,
                token=args.auth_token,
                stream_id=args.stream_id,
                correlation_id=correlation_id,
                timeout_s=args.turn_timeout,
                poll_interval=args.poll_interval,
            )
            print(f"turn result: {result['decision']}")
            print()
            parent_turn_id = turn_id
            time.sleep(max(0.0, step.pause_s))

    print("Demo script completed.")
    print("Open /ui to inspect the full stream and click a DECISION row for replay.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
