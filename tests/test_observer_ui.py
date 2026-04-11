"""Tests for Observer UI: /ui/tail, /ui/capabilities, /ui/snapshot proxies and static mount."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.requests import Request

from dbl_gateway.app import create_app
from dbl_gateway.adapters.policy_adapter_dbl_policy import DblPolicyAdapter
from dbl_gateway.ports.execution_port import ExecutionResult
from dbl_gateway.store.sqlite import SQLiteStore
from dbl_gateway.wire_contract import INTERFACE_VERSION


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
    monkeypatch.setenv("DBL_GATEWAY_INLINE_DECISION", "1")
    monkeypatch.setenv("GATEWAY_ENABLE_CONTEXT_RESOLUTION", "1")
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    boundary_demo = Path(__file__).resolve().parents[1] / "config" / "boundary.demo.json"
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", str(boundary_demo))


def _make_app() -> Any:
    return create_app(start_workers=False)


class _DescribePolicy:
    def describe(self) -> dict[str, object]:
        return {
            "describe_version": 1,
            "type": "root_policy",
            "policy_id": "chat.guardrails",
            "policy_version": "1.0.0",
            "root": {
                "describe_version": 1,
                "type": "chain",
                "label": "guardrail_chain",
                "gates": [
                    {
                        "describe_version": 1,
                        "type": "match",
                        "label": "chat_capability",
                        "key": "capability",
                        "value": "chat",
                    },
                    {
                        "describe_version": 1,
                        "type": "bound",
                        "label": "output_token_limit",
                        "key": "max_output_tokens",
                        "lo": 1,
                        "hi": 4096,
                    },
                ],
            },
        }


async def _with_client(app: Any, fn: Any) -> Any:
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await fn(client)


def _append_test_event(
    store: SQLiteStore,
    kind: str,
    **overrides: Any,
) -> Any:
    defaults = dict(
        kind=kind,
        thread_id="t1",
        turn_id="turn1",
        parent_turn_id=None,
        lane="default",
        actor="test-actor",
        intent_type="test.intent",
        stream_id="default",
        correlation_id="c1",
        payload={"test": True},
    )
    defaults.update(overrides)
    return store.append(**defaults)


def _intent_envelope(
    message: object,
    *,
    correlation_id: str = "c-1",
    thread_id: str = "thread-1",
    turn_id: str = "turn-1",
) -> dict[str, object]:
    return {
        "interface_version": INTERFACE_VERSION,
        "correlation_id": correlation_id,
        "payload": {
            "stream_id": "default",
            "lane": "user_chat",
            "actor": "user",
            "intent_type": "chat.message",
            "thread_id": thread_id,
            "turn_id": turn_id,
            "parent_turn_id": None,
            "requested_model_id": "gpt-4o-mini",
            "payload": {"message": message},
        },
    }


def _get_ui_tail_route(app: Any) -> Any:
    """Find the /ui/tail route in the app."""
    for route in app.router.routes:
        if getattr(route, "path", "") == "/ui/tail":
            return route
    raise AssertionError("/ui/tail route not found")


def _make_request(query_string: bytes = b"") -> Request:
    """Build a minimal ASGI Request for /ui/tail (no auth headers)."""
    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": "/ui/tail",
        "query_string": query_string,
        "headers": [],  # no auth headers
        "client": ("testclient", 123),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope, _receive)


async def _collect_sse_data(
    route: Any,
    request: Request,
    *,
    stream_id: str | None = "default",
    since: int = -1,
    lanes: str | None = None,
    max_data_lines: int = 1,
    timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Call /ui/tail endpoint directly and collect parsed SSE data events."""
    response = await route.endpoint(
        request, stream_id=stream_id, since=since, lanes=lanes,
    )
    data_events: list[dict[str, Any]] = []
    body_iter = response.body_iterator

    async def _read() -> None:
        try:
            async for chunk in body_iter:
                if not chunk:
                    continue
                text = chunk if isinstance(chunk, str) else chunk.decode("utf-8")
                for line in text.splitlines():
                    if line.startswith("data:"):
                        data_events.append(json.loads(line[5:]))
                        if len(data_events) >= max_data_lines:
                            return
        finally:
            if hasattr(body_iter, "aclose"):
                await body_iter.aclose()

    await asyncio.wait_for(_read(), timeout=timeout)
    return data_events


class TestUiTailProxy:
    """Tests for the /ui/tail SSE proxy endpoint."""

    def test_ui_tail_no_auth_required(self) -> None:
        """The proxy endpoint works without any auth headers."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            store: SQLiteStore = app.state.store
            _append_test_event(store, "INTENT")

            route = _get_ui_tail_route(app)
            request = _make_request()
            data = await _collect_sse_data(route, request)

            assert len(data) >= 1
            assert data[0]["kind"] == "INTENT"

        asyncio.run(_with_client(app, check))

    def test_ui_tail_streams_sse_format(self) -> None:
        """Events arrive with correct kind and index fields."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            store: SQLiteStore = app.state.store
            _append_test_event(store, "INTENT", correlation_id="c1")
            _append_test_event(store, "INTENT", correlation_id="c2")

            route = _get_ui_tail_route(app)
            request = _make_request()
            data = await _collect_sse_data(route, request, max_data_lines=2)

            assert len(data) == 2
            assert data[0]["kind"] == "INTENT"
            assert data[1]["kind"] == "INTENT"
            assert "index" in data[0]
            assert "index" in data[1]
            assert data[0]["index"] < data[1]["index"]

        asyncio.run(_with_client(app, check))

    def test_ui_tail_filters_lanes(self) -> None:
        """Lane filtering works on the proxy endpoint."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            store: SQLiteStore = app.state.store
            _append_test_event(store, "INTENT", lane="user")
            _append_test_event(store, "INTENT", lane="system", correlation_id="c2")

            route = _get_ui_tail_route(app)
            request = _make_request(b"lanes=user")
            data = await _collect_sse_data(
                route, request, lanes="user", max_data_lines=1,
            )

            assert len(data) >= 1
            assert all(e["lane"] == "user" for e in data)

        asyncio.run(_with_client(app, check))

    def test_ui_tail_response_headers(self) -> None:
        """Proxy sets correct SSE headers including X-Accel-Buffering."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            store: SQLiteStore = app.state.store
            _append_test_event(store, "INTENT")

            route = _get_ui_tail_route(app)
            request = _make_request()
            response = await route.endpoint(
                request, stream_id="default", since=-1, lanes=None,
            )

            assert response.media_type == "text/event-stream"
            assert response.headers.get("cache-control") == "no-cache"
            assert response.headers.get("x-accel-buffering") == "no"

            # Clean up the generator
            if hasattr(response.body_iterator, "aclose"):
                await response.body_iterator.aclose()

        asyncio.run(_with_client(app, check))


class TestUiCapabilitiesProxy:
    """Tests for the /ui/capabilities proxy endpoint."""

    def test_ui_capabilities_no_auth(self) -> None:
        """GET /ui/capabilities returns 200 with JSON, no auth required."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/ui/capabilities")
            assert resp.status_code == 200
            data = resp.json()
            assert "gateway_version" in data or "interface_version" in data
            assert resp.headers.get("cache-control") == "max-age=30"

        asyncio.run(_with_client(app, check))


class TestUiSnapshotProxy:
    """Tests for the /ui/snapshot proxy endpoint."""

    def test_ui_snapshot_no_auth(self) -> None:
        """GET /ui/snapshot returns 200 with v_digest, no auth required."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            store: SQLiteStore = app.state.store
            _append_test_event(store, "INTENT")

            resp = await client.get("/ui/snapshot")
            assert resp.status_code == 200
            data = resp.json()
            assert "v_digest" in data

        asyncio.run(_with_client(app, check))

    def test_ui_policy_structure_no_auth(self) -> None:
        """GET /ui/policy-structure returns viewer payload when policy exposes describe()."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            app.state.policy = DblPolicyAdapter(policy=_DescribePolicy())
            resp = await client.get("/ui/policy-structure")
            assert resp.status_code == 200
            assert resp.headers.get("cache-control") == "max-age=30"
            data = resp.json()
            assert data["available"] is True
            assert data["source"] == "describe"
            assert data["policy_id"] == "chat.guardrails"
            assert data["policy_version"] == "1.0.0"
            assert data["tree"]["path"] == "root"
            assert data["tree"]["kind"] == "root_policy"
            assert data["tree"]["children"][0]["kind"] == "chain"

        asyncio.run(_with_client(app, check))

    def test_ui_policy_structure_opaque_without_describe(self) -> None:
        """GET /ui/policy-structure falls back to opaque metadata when describe() is missing."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/ui/policy-structure")
            assert resp.status_code == 200
            data = resp.json()
            assert data["available"] is True
            assert data["source"] == "opaque"
            assert data["policy_id"] == "test"
            assert data["policy_version"] == "1"
            assert data["tree"]["path"] == "root"
            assert data["tree"]["kind"] == "opaque_policy"
            assert data["tree"]["label"] == "test"
            assert data["tree"]["children"] == []
            assert data["tree"]["meta"]["policy_module"] == "policy_stub"
            assert data["tree"]["meta"]["policy_class"] == "AllowPolicy"
            assert "describe" in data["detail"]

        asyncio.run(_with_client(app, check))


class TestUiIntentProxy:
    """Tests for the auth-free manual intent proxy."""

    def test_ui_intent_no_auth(self) -> None:
        """POST /ui/intent accepts a valid envelope without auth headers."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.post("/ui/intent", json=_intent_envelope("hello from ui"))
            assert resp.status_code == 202
            data = resp.json()
            assert data["accepted"] is True
            assert data["correlation_id"] == "c-1"

            snap = await client.get("/ui/snapshot")
            assert snap.status_code == 200
            assert snap.json()["length"] >= 1

        asyncio.run(_with_client(app, check))


class TestUiVerificationProxy:
    """Tests for the verification proxy endpoints."""

    def test_ui_verify_chain_no_auth(self) -> None:
        """GET /ui/verify-chain returns a matching recomputed digest without auth."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.post("/ingress/intent", json=_intent_envelope("hello verify"))
            assert resp.status_code == 202

            verify = await client.get("/ui/verify-chain")
            assert verify.status_code == 200
            data = verify.json()
            assert data["match"] is True
            assert data["rolling_digest"] == data["recomputed_digest"]
            assert data["event_count"] >= 4

        asyncio.run(_with_client(app, check))

    def test_ui_replay_no_auth(self) -> None:
        """GET /ui/replay returns matching decision digests for a valid turn."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.post("/ingress/intent", json=_intent_envelope("hello replay"))
            assert resp.status_code == 202

            replay = await client.get("/ui/replay", params={"thread_id": "thread-1", "turn_id": "turn-1"})
            assert replay.status_code == 200
            data = replay.json()
            assert data["match"] is True
            assert data["recomputed_digest"] == data["stored_digest"]
            assert isinstance(data["decision_index"], int)
            assert isinstance(data["intent_index"], int)

        asyncio.run(_with_client(app, check))

    def test_ui_replay_missing_turn(self) -> None:
        """GET /ui/replay returns 422 when the requested turn does not exist."""
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            replay = await client.get("/ui/replay", params={"thread_id": "missing-thread", "turn_id": "missing-turn"})
            assert replay.status_code == 422
            data = replay.json()
            assert data["error"] in {"decision.not_found", "intent.not_found"}
            assert "detail" in data

        asyncio.run(_with_client(app, check))


class TestUiDemoProxy:
    """Tests for the integrated UI demo controller."""

    def test_ui_demo_status_no_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_app()
        monkeypatch.setattr(
            "dbl_gateway.app.get_capabilities_cached",
            lambda *_args, **_kwargs: {
                "providers": [
                    {
                        "id": "openai",
                        "models": [{"id": "gpt-4o-mini", "health": {"status": "ok"}}],
                    }
                ]
            },
        )

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/ui/demo/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["scenario_name"] == "governance-demo"
            assert data["active_provider"] == "openai"
            assert data["active_model"] == "gpt-4o-mini"
            assert data["can_start"] is True

        asyncio.run(_with_client(app, check))

    def test_ui_demo_start_no_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = _make_app()
        monkeypatch.setattr(
            "dbl_gateway.app.get_capabilities_cached",
            lambda *_args, **_kwargs: {
                "providers": [
                    {
                        "id": "openai",
                        "models": [{"id": "gpt-4o-mini", "health": {"status": "ok"}}],
                    }
                ]
            },
        )

        async def fake_run(self: Any, intent_event: Any, **_: Any) -> ExecutionResult:
            return ExecutionResult(
                output_text="ok",
                provider="openai",
                model_id="gpt-4o-mini",
                trace={"trace_id": "demo-trace"},
                trace_digest="sha256:" + ("1" * 64),
                usage={"duration_ms": 10},
            )

        async def check(client: httpx.AsyncClient) -> None:
            monkeypatch.setattr(type(app.state.execution), "run", fake_run)
            store: SQLiteStore = app.state.store
            for idx in range(110):
                _append_test_event(
                    store,
                    "INTENT",
                    correlation_id=f"seed-{idx}",
                    thread_id=f"seed-thread-{idx}",
                    turn_id=f"seed-turn-{idx}",
                )
            app.state.demo_agent["step_delay_s"] = 0.0
            app.state.demo_agent["turn_timeout_s"] = 2.0
            app.state.demo_agent["poll_interval_s"] = 0.01

            started = await client.post("/ui/demo/start")
            assert started.status_code == 202
            started_data = started.json()
            assert started_data["running"] is True

            for _ in range(120):
                status = await client.get("/ui/demo/status")
                data = status.json()
                if data["running"] is False and data["completed_at"] is not None:
                    assert data["last_error"] is None
                    assert data["provider"] == "openai"
                    assert data["model"] == "gpt-4o-mini"
                    assert any("demo completed" in entry["message"] for entry in data["logs"])
                    return
                await asyncio.sleep(0.05)

            raise AssertionError("demo run did not complete")

        asyncio.run(_with_client(app, check))


class TestUiRoutesNotDocumented:
    """All /ui/* routes must be excluded from the OpenAPI schema."""

    def test_ui_routes_not_in_openapi(self) -> None:
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/openapi.json")
            schema = resp.json()
            paths = schema.get("paths", {})
            ui_paths = [p for p in paths if p.startswith("/ui")]
            assert ui_paths == [], f"UI routes leaked into OpenAPI: {ui_paths}"

        asyncio.run(_with_client(app, check))


class TestObserverHtml:
    """The observer page is served at /ui."""

    def test_observer_html_served(self) -> None:
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/ui/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers.get("content-type", "")
            assert "Event Observer" in resp.text
            assert "Manual Intent" in resp.text
            assert 'data-tab="policy"' in resp.text

        asyncio.run(_with_client(app, check))
