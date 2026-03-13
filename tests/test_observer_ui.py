"""Tests for Phase 1 Observer UI: /ui/tail proxy and static mount."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from starlette.requests import Request

from dbl_gateway.app import create_app
from dbl_gateway.store.sqlite import SQLiteStore


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
    monkeypatch.setenv("DBL_GATEWAY_INLINE_DECISION", "1")


def _make_app() -> Any:
    return create_app(start_workers=False)


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


class TestUiTailNotInOpenAPI:
    """The /ui/tail proxy must not appear in the OpenAPI schema."""

    def test_ui_tail_excluded_from_schema(self) -> None:
        app = _make_app()

        async def check(client: httpx.AsyncClient) -> None:
            resp = await client.get("/openapi.json")
            schema = resp.json()
            paths = schema.get("paths", {})
            assert "/ui/tail" not in paths

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

        asyncio.run(_with_client(app, check))
