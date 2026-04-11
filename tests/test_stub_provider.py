"""Tests for the stub provider and demo mode activation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from dbl_gateway.providers.stub import (
    STUB_MODEL_IDS,
    execute,
    get_capabilities,
)


class TestStubCapabilities:
    """Stub provider implements the ProviderCapabilities contract."""

    def test_capabilities_contract(self) -> None:
        caps = get_capabilities()
        assert caps.provider_id == "stub"
        assert caps.requires_api_key is False
        assert caps.execution_mode == "local"
        assert caps.features.streaming is False
        assert caps.features.tools is False
        assert caps.limits.timeout_seconds == 1.0

    def test_stub_model_ids(self) -> None:
        assert "stub-echo" in STUB_MODEL_IDS
        assert "stub-scenario" in STUB_MODEL_IDS


class TestStubEchoMode:
    """Echo mode mirrors the user message."""

    def test_echo_returns_user_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STUB_MODE", "echo")
        messages = [{"role": "user", "content": "Hello world"}]
        resp = execute(model_id="stub-echo", messages=messages)
        assert "[stub-echo]" in resp.text
        assert "Hello world" in resp.text
        assert resp.tool_calls == []

    def test_echo_extracts_last_user_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STUB_MODE", "echo")
        messages = [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "reply"},
            {"role": "user", "content": "second"},
        ]
        resp = execute(model_id="stub-echo", messages=messages)
        assert "second" in resp.text
        assert "first" not in resp.text

    def test_echo_empty_messages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STUB_MODE", "echo")
        resp = execute(model_id="stub-echo", messages=[])
        assert "[stub-echo]" in resp.text


class TestStubScenarioMode:
    """Scenario mode rotates through canned responses deterministically."""

    def test_scenario_deterministic_rotation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STUB_MODE", "scenario")
        messages_1 = [{"role": "user", "content": "turn 1"}]
        messages_2 = [
            {"role": "user", "content": "turn 1"},
            {"role": "assistant", "content": "reply"},
            {"role": "user", "content": "turn 2"},
        ]

        resp_1 = execute(model_id="stub-scenario", messages=messages_1)
        resp_2 = execute(model_id="stub-scenario", messages=messages_2)

        # Different turn counts produce different responses
        assert resp_1.text != resp_2.text

    def test_scenario_produces_identical_output_for_same_input(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("STUB_MODE", "scenario")
        messages = [{"role": "user", "content": "hello"}]
        resp_a = execute(model_id="stub-scenario", messages=messages)
        resp_b = execute(model_id="stub-scenario", messages=messages)
        assert resp_a.text == resp_b.text

    def test_scenario_default_mode_is_echo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("STUB_MODE", raising=False)
        messages = [{"role": "user", "content": "test"}]
        resp = execute(model_id="stub-echo", messages=messages)
        assert "[stub-echo]" in resp.text


class TestDemoModeActivation:
    """GATEWAY_DEMO_MODE=1 registers stub and sets defaults."""

    def test_demo_mode_registers_stub_provider(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("GATEWAY_DEMO_MODE", "1")
        monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
        monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "demo.sqlite"))

        from dbl_gateway.app import create_app
        from dbl_gateway.capabilities import _CAPS_CACHE
        from dbl_gateway.providers import PROVIDER_MODULES

        _CAPS_CACHE.clear()
        # Remove stub if left over from a previous test to verify re-registration
        PROVIDER_MODULES.pop("stub", None)

        app = create_app(start_workers=False)

        async def check(client: httpx.AsyncClient) -> None:
            assert "stub" in PROVIDER_MODULES

            # Capabilities should include stub models
            resp = await client.get("/capabilities")
            assert resp.status_code == 200
            data = resp.json()
            stub_providers = [p for p in data["providers"] if p["id"] == "stub"]
            assert len(stub_providers) == 1
            model_ids = [m["id"] for m in stub_providers[0]["models"]]
            assert "stub-echo" in model_ids
            assert "stub-scenario" in model_ids

        async def run() -> None:
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://testserver",
                ) as client:
                    await check(client)

        asyncio.run(run())

    def test_demo_mode_off_no_stub(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("GATEWAY_DEMO_MODE", raising=False)
        monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
        monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "normal.sqlite"))

        # Ensure stub is not in PROVIDER_MODULES (previous tests may have added it)
        from dbl_gateway.providers import PROVIDER_MODULES
        from dbl_gateway.capabilities import _CAPS_CACHE

        _CAPS_CACHE.clear()

        had_stub = "stub" in PROVIDER_MODULES
        if had_stub:
            del PROVIDER_MODULES["stub"]

        try:
            from dbl_gateway.app import create_app

            app = create_app(start_workers=False)

            async def check(client: httpx.AsyncClient) -> None:
                resp = await client.get("/capabilities")
                assert resp.status_code == 200
                data = resp.json()
                stub_providers = [p for p in data["providers"] if p["id"] == "stub"]
                assert len(stub_providers) == 0

            async def run() -> None:
                async with app.router.lifespan_context(app):
                    transport = httpx.ASGITransport(app)
                    async with httpx.AsyncClient(
                        transport=transport, base_url="http://testserver",
                    ) as client:
                        await check(client)

            asyncio.run(run())
        finally:
            # Restore if needed
            if had_stub:
                from dbl_gateway.providers import stub

                PROVIDER_MODULES["stub"] = stub

    def test_demo_mode_sets_policy_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        """When GATEWAY_DEMO_MODE=1 and no policy is set, allow_all is used."""
        monkeypatch.setenv("GATEWAY_DEMO_MODE", "1")
        monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
        monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "demo-policy.sqlite"))
        monkeypatch.delenv("DBL_GATEWAY_POLICY_MODULE", raising=False)

        import os
        from dbl_gateway.app import create_app

        app = create_app(start_workers=False)

        async def run() -> None:
            async with app.router.lifespan_context(app):
                # After startup, policy module should be set
                assert os.environ.get("DBL_GATEWAY_POLICY_MODULE") == "dbl_policy.allow_all"

        asyncio.run(run())

    def test_demo_mode_enables_context_resolution_by_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("GATEWAY_DEMO_MODE", "1")
        monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
        monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "demo-context.sqlite"))
        monkeypatch.delenv("GATEWAY_ENABLE_CONTEXT_RESOLUTION", raising=False)

        import os
        from dbl_gateway.app import create_app

        app = create_app(start_workers=False)

        async def run() -> None:
            async with app.router.lifespan_context(app):
                assert os.environ.get("GATEWAY_ENABLE_CONTEXT_RESOLUTION") == "1"

        asyncio.run(run())

    def test_demo_mode_does_not_override_explicit_context_resolution_setting(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("GATEWAY_DEMO_MODE", "1")
        monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "dev")
        monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "demo-context-explicit.sqlite"))
        monkeypatch.setenv("GATEWAY_ENABLE_CONTEXT_RESOLUTION", "0")

        import os
        from dbl_gateway.app import create_app

        app = create_app(start_workers=False)

        async def run() -> None:
            async with app.router.lifespan_context(app):
                assert os.environ.get("GATEWAY_ENABLE_CONTEXT_RESOLUTION") == "0"

        asyncio.run(run())
