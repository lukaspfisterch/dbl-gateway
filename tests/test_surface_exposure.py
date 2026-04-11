from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from dbl_gateway.app import create_app


def _boundary_path(name: str) -> str:
    return str(Path(__file__).resolve().parents[1] / "config" / name)


async def _with_client(app: Any, fn: Any) -> Any:
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await fn(client)


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))


def test_public_mode_blocks_ui_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", _boundary_path("boundary.public.json"))
    app = create_app(start_workers=False)

    async def scenario(client: httpx.AsyncClient) -> None:
        ui = await client.get("/ui/")
        assert ui.status_code == 404
        assert ui.json()["surface_id"] == "ui_root"

        surfaces = await client.get("/surfaces")
        assert surfaces.status_code == 403
        assert surfaces.json()["surface_id"] == "surfaces"

        template = await client.get("/intent-template")
        assert template.status_code == 403
        assert template.json()["surface_id"] == "intent_template"

    import asyncio

    asyncio.run(_with_client(app, scenario))


def test_public_capabilities_hide_non_public_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", _boundary_path("boundary.public.json"))
    app = create_app(start_workers=False)

    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.get("/capabilities")
        assert resp.status_code == 200
        data = resp.json()
        ids = {item["id"] for item in data["surface_catalog"]}
        assert data["boundary"]["exposure_mode"] == "public"
        assert ids == {"healthz", "capabilities", "ingress_intent"}
        assert data["intents"]["supported"] == ["chat.message"]
        assert "artifact.handle" not in data["intents"]["catalog"]
        assert data["tool_surface"]["trust_class_current"] == "internal"
        assert data["tool_surface"]["allowed_families_current"] == ["web_read", "retrieval"]
        assert data["tool_surface"]["allowed_families_by_exposure"]["operator"]["anonymous"] == []
        assert data["tool_surface"]["allowed_families_by_exposure"]["operator"]["internal"] == [
            "web_read",
            "retrieval",
            "llm_assist",
        ]
        assert data["budget"]["visible_request_classes_current"] == ["intent", "execution_light"]
        assert "execution_heavy" not in data["budget"]["current_request_policy"]
        assert data["budget"]["current_request_policy"]["intent"]["max_budget"] == {
            "max_tokens": 2048,
            "max_duration_ms": 12000,
        }
        assert set(data["economic"]["current_policy"]) == {"intent", "execution_light"}
        assert "execution_heavy" not in data["economic"]["current_policy"]

    import asyncio

    asyncio.run(_with_client(app, scenario))


def test_operator_mode_exposes_operator_surfaces_but_not_ui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", _boundary_path("boundary.operator.json"))
    app = create_app(start_workers=False)

    async def scenario(client: httpx.AsyncClient) -> None:
        surfaces = await client.get("/surfaces")
        assert surfaces.status_code == 200
        surface_ids = {item["id"] for item in surfaces.json()["surfaces"]}
        assert "surfaces" in surface_ids
        assert "snapshot" in surface_ids
        assert not any(surface_id.startswith("ui_") for surface_id in surface_ids)

        ui = await client.get("/ui/")
        assert ui.status_code == 404

    import asyncio

    asyncio.run(_with_client(app, scenario))


def test_demo_mode_exposes_ui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_BOUNDARY_CONFIG", _boundary_path("boundary.demo.json"))
    monkeypatch.setenv("GATEWAY_ENABLE_CONTEXT_RESOLUTION", "true")
    app = create_app(start_workers=False)

    async def scenario(client: httpx.AsyncClient) -> None:
        ui = await client.get("/ui/")
        assert ui.status_code == 200

        caps = await client.get("/capabilities")
        assert caps.status_code == 200
        caps_data = caps.json()
        ids = {item["id"] for item in caps_data["surface_catalog"]}
        assert "ui_root" in ids
        assert "ui_demo_start" in ids
        assert "artifact.handle" in caps_data["intents"]["supported"]
        assert caps_data["intents"]["catalog"]["artifact.handle"]["risk_class"] == "high_risk_context"
        assert caps_data["tool_surface"]["trust_class_current"] == "internal"
        assert caps_data["tool_surface"]["allowed_families_current"] == ["*"]
        assert caps_data["budget"]["visible_request_classes_current"] == [
            "probe",
            "intent",
            "execution_light",
            "execution_heavy",
        ]
        assert caps_data["budget"]["current_request_policy"]["execution_heavy"]["decision"] == "allow"
        assert caps_data["economic"]["current_policy"]["execution_heavy"]["slot_class"] == "reserved"
        assert caps_data["economic"]["current_policy"]["execution_heavy"]["reservation_required"] is True

    import asyncio

    asyncio.run(_with_client(app, scenario))
