from __future__ import annotations

import httpx

from dbl_gateway.client import GatewayClient


def test_send_intent_posts_raw_envelope() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["json"] = request.read().decode("utf-8")
        return httpx.Response(
            202,
            json={
                "accepted": True,
                "stream_id": "default",
                "index": 1,
                "correlation_id": "slice-1",
                "queued": True,
            },
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(base_url="http://testserver", transport=transport) as http_client:
        client = GatewayClient("http://testserver", client=http_client)
        envelope = {
            "interface_version": 3,
            "correlation_id": "slice-1",
            "payload": {
                "stream_id": "default",
                "lane": "user_chat",
                "actor": "user",
                "intent_type": "chat.message",
                "thread_id": "thread-1",
                "turn_id": "turn-1",
                "parent_turn_id": None,
                "payload": {"message": "Hello"},
            },
        }

        ack = client.send_intent(envelope)

    assert captured["method"] == "POST"
    assert captured["path"] == "/ingress/intent"
    assert '"correlation_id":"slice-1"' in str(captured["json"])
    assert ack["accepted"] is True
    assert ack["correlation_id"] == "slice-1"


def test_get_snapshot_keeps_query_surface_explicit() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={"length": 1, "offset": 5, "limit": 10, "v_digest": "sha256:test", "events": []},
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(base_url="http://testserver", transport=transport) as http_client:
        client = GatewayClient("http://testserver", client=http_client)
        snapshot = client.get_snapshot(limit=10, offset=5, stream_id="alpha", lane="user_chat")

    assert captured["path"] == "/snapshot"
    assert captured["query"] == {
        "limit": "10",
        "offset": "5",
        "stream_id": "alpha",
        "lane": "user_chat",
    }
    assert snapshot["v_digest"] == "sha256:test"


def test_replay_calls_raw_replay_route() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "match": True,
                "recomputed_digest": "sha256:a",
                "stored_digest": "sha256:a",
                "decision_index": 2,
                "intent_index": 1,
            },
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(base_url="http://testserver", transport=transport) as http_client:
        client = GatewayClient("http://testserver", client=http_client)
        replay = client.replay(thread_id="thread-1", turn_id="turn-1")

    assert captured["path"] == "/ui/replay"
    assert captured["query"] == {"thread_id": "thread-1", "turn_id": "turn-1"}
    assert replay["match"] is True
