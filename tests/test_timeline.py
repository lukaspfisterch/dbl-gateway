from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from dbl_gateway.app import create_app
from test_gateway import _intent_envelope, run_with_client


async def _post_intent(
    client: httpx.AsyncClient,
    *,
    thread_id: str,
    turn_id: str,
    parent_turn_id: str | None,
) -> httpx.Response:
    payload = _intent_envelope("hello")
    payload["payload"]["thread_id"] = thread_id
    payload["payload"]["turn_id"] = turn_id
    payload["payload"]["parent_turn_id"] = parent_turn_id
    return await client.post("/ingress/intent", json=payload)


async def _wait_for_decisions(client: httpx.AsyncClient, expected: int, attempts: int = 40) -> None:
    for _ in range(attempts):
        snap = (await client.get("/snapshot")).json()
        decisions = [event for event in snap["events"] if event["kind"] == "DECISION"]
        if len(decisions) >= expected:
            return
        await asyncio.sleep(0.05)
    assert False, "DECISION events not emitted"


def test_timeline_linear(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)
    thread_id = "t-linear"

    async def scenario(client: httpx.AsyncClient) -> dict[str, object]:
        await _post_intent(client, thread_id=thread_id, turn_id="turn-1", parent_turn_id=None)
        await _post_intent(client, thread_id=thread_id, turn_id="turn-2", parent_turn_id="turn-1")
        await _post_intent(client, thread_id=thread_id, turn_id="turn-3", parent_turn_id="turn-2")
        await _wait_for_decisions(client, expected=3)
        resp = await client.get(f"/threads/{thread_id}/timeline")
        return resp.json()

    timeline = run_with_client(app, scenario)
    assert timeline["thread_id"] == thread_id
    assert [t["turn_id"] for t in timeline["turns"]] == ["turn-1", "turn-2", "turn-3"]
    assert timeline["turns"][0]["parent_turn_id"] is None
    assert timeline["turns"][1]["parent_turn_id"] == "turn-1"
    assert timeline["turns"][2]["parent_turn_id"] == "turn-2"
    for turn in timeline["turns"]:
        kinds = [e["kind"] for e in turn["events"]]
        assert kinds[0] == "INTENT"
        assert "DECISION" in kinds
        decision_entries = [e for e in turn["events"] if e["kind"] == "DECISION"]
        assert decision_entries
        assert isinstance(decision_entries[-1].get("decision_digest"), str)
        # context_digest may be None when context resolution is OFF
        ctx_digest = decision_entries[-1].get("context_digest")
        assert ctx_digest is None or isinstance(ctx_digest, str)


def test_timeline_fork(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)
    thread_id = "t-fork"

    async def scenario(client: httpx.AsyncClient) -> dict[str, object]:
        await _post_intent(client, thread_id=thread_id, turn_id="root", parent_turn_id=None)
        await _post_intent(client, thread_id=thread_id, turn_id="child-a", parent_turn_id="root")
        await _post_intent(client, thread_id=thread_id, turn_id="child-b", parent_turn_id="root")
        await _wait_for_decisions(client, expected=3)
        resp = await client.get(f"/threads/{thread_id}/timeline")
        return resp.json()

    timeline = run_with_client(app, scenario)
    assert {t["turn_id"] for t in timeline["turns"]} == {"root", "child-a", "child-b"}
    parents = {t["turn_id"]: t["parent_turn_id"] for t in timeline["turns"]}
    assert parents["root"] is None
    assert parents["child-a"] == "root"
    assert parents["child-b"] == "root"


def test_invalid_parent_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await _post_intent(client, thread_id="t-invalid", turn_id="t1", parent_turn_id="missing")
        assert resp.status_code == 400
        body = resp.json()
        assert body["reason_code"] == "admission.invalid_parent"

    run_with_client(app, scenario)


def test_self_parent_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await _post_intent(client, thread_id="t-self", turn_id="t1", parent_turn_id="t1")
        assert resp.status_code == 400
        body = resp.json()
        assert body["reason_code"] == "admission.invalid_parent"

    run_with_client(app, scenario)


def test_cycle_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)
    thread_id = "t-cycle"

    async def scenario(client: httpx.AsyncClient) -> None:
        await _post_intent(client, thread_id=thread_id, turn_id="root", parent_turn_id=None)
        await _post_intent(client, thread_id=thread_id, turn_id="child", parent_turn_id="root")
        await _wait_for_decisions(client, expected=2)
        resp = await _post_intent(client, thread_id=thread_id, turn_id="root", parent_turn_id="child")
        assert resp.status_code == 400
        body = resp.json()
        assert body["reason_code"] == "admission.invalid_parent"

    run_with_client(app, scenario)
