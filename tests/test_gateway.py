from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Awaitable, Callable, TypeVar

import httpx
import pytest
import sys
from starlette.requests import Request

from dbl_gateway.app import create_app
from dbl_gateway.ports.execution_port import ExecutionResult
from dbl_gateway.wire_contract import INTERFACE_VERSION
from dbl_gateway.digest import event_digest
from dbl_gateway import governance
from dbl_core import normalize_trace
import kl_kernel_logic
from dbl_gateway.adapters.execution_adapter_kl import KlExecutionAdapter, _call_kernel
from dbl_gateway.providers import openai as openai_provider
from dbl_gateway.store.sqlite import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))

T = TypeVar("T")
ClientCallable = Callable[[httpx.AsyncClient], Awaitable[T]]


async def _with_client(app, fn: ClientCallable[T]) -> T:
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as client:
            return await fn(client)


def run_with_client(app, fn: ClientCallable[T]) -> T:
    return asyncio.run(_with_client(app, fn))


@pytest.fixture(autouse=True)
def _policy_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_POLICY_MODULE", "policy_stub")
    monkeypatch.setenv("DBL_GATEWAY_POLICY_OBJECT", "policy")


def _intent_envelope(
    message: object,
    model_id: str = "gpt-4o-mini",
    *,
    intent_type: str = "chat.message",
    payload_override: dict[str, object] | None = None,
) -> dict[str, object]:
    payload = {"message": message}
    if payload_override is not None:
        payload = payload_override
    return {
        "interface_version": INTERFACE_VERSION,
        "correlation_id": "c-1",
        "payload": {
            "stream_id": "default",
            "lane": "user_chat",
            "actor": "user",
            "intent_type": intent_type,
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "parent_turn_id": None,
            "requested_model_id": model_id,
            "payload": payload,
        },
    }


def _make_trace() -> tuple[dict[str, object], str]:
    psi = kl_kernel_logic.PsiDefinition(psi_type="test", name="test", metadata={})
    kernel = kl_kernel_logic.Kernel(deterministic_mode=True)
    trace = kernel.execute(psi=psi, task=lambda: "ok")
    trace_dict, trace_digest = normalize_trace(trace)
    return trace_dict, trace_digest


def test_admission_reject_does_not_append_intent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/ingress/intent",
            json=_intent_envelope(
                "noop",
                intent_type="other.intent",
                payload_override={"value": 1.5},
            ),
        )
        assert resp.status_code == 400
        assert resp.json()["reason_code"] == "admission.invalid_input"
        snap = (await client.get("/snapshot")).json()
        assert snap["length"] == 0

    run_with_client(app, scenario)


def test_admission_rejects_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        payload = _intent_envelope("hello")
        payload["payload"]["payload"]["api_key"] = "secret"
        resp = await client.post("/ingress/intent", json=payload)
        assert resp.status_code == 400
        assert resp.json()["reason_code"] == "admission.secrets_present"
        snap = (await client.get("/snapshot")).json()
        assert snap["length"] == 0

    run_with_client(app, scenario)


def test_decision_primacy_no_execution_without_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))

    class RejectPolicy:
        def evaluate(self, context):
            from dbl_policy import DecisionOutcome, PolicyDecision, PolicyId, PolicyVersion, TenantId

            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                reason_code="policy.reject",
                policy_id=PolicyId("test"),
                policy_version=PolicyVersion("1"),
                tenant_id=TenantId(context.tenant_id.value),
            )

    monkeypatch.setenv("DBL_GATEWAY_POLICY_MODULE", "policy_stub")
    monkeypatch.setenv("DBL_GATEWAY_POLICY_OBJECT", "policy")
    import policy_stub as policy_stub

    monkeypatch.setattr(policy_stub, "policy", RejectPolicy(), raising=False)
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        await asyncio.sleep(0.1)
        snap = (await client.get("/snapshot")).json()
        kinds = [event["kind"] for event in snap["events"]]
        assert kinds == ["INTENT", "DECISION"]

    run_with_client(app, scenario)


def test_ingress_returns_immediately_without_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))

    async def slow_execution(self, _intent, **kwargs):
        trace_dict, trace_digest = _make_trace()
        await asyncio.sleep(0.3)
        return ExecutionResult(
            output_text="ok",
            provider="openai",
            model_id="gpt-4o-mini",
            trace=trace_dict,
            trace_digest=trace_digest,
        )

    monkeypatch.setattr(
        "dbl_gateway.adapters.execution_adapter_kl.KlExecutionAdapter.run",
        slow_execution,
    )
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        start = time.monotonic()
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        elapsed = time.monotonic() - start
        assert resp.status_code == 202
        ack = resp.json()
        assert ack["accepted"] is True
        assert ack["queued"] is True
        assert ack["correlation_id"] == "c-1"
        assert isinstance(ack["index"], int)
        assert elapsed < 0.2
        for _ in range(10):
            snap = (await client.get("/snapshot")).json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                return
            await asyncio.sleep(0.05)
        assert False, "execution event not emitted"

    run_with_client(app, scenario)


def test_execution_error_captured_as_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))

    async def error_execution(self, _intent, **kwargs):
        trace_dict, trace_digest = _make_trace()
        return ExecutionResult(
            provider="openai",
            model_id="gpt-4o-mini",
            trace=trace_dict,
            trace_digest=trace_digest,
            error={"provider": "openai", "status_code": 401, "message": "unauthorized"},
        )

    monkeypatch.setattr(
        "dbl_gateway.adapters.execution_adapter_kl.KlExecutionAdapter.run",
        error_execution,
    )
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        for _ in range(10):
            snap = (await client.get("/snapshot")).json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                payload = executions[-1]["payload"]
                assert "error" in payload
                assert payload["error"]["status_code"] == 401
                assert "api_key" not in str(payload)
                return
            await asyncio.sleep(0.05)
        assert False, "execution error event not emitted"

    run_with_client(app, scenario)


def test_execution_model_unavailable_records_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_CHAT_MODEL_IDS", "gpt-4o-mini")
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        for _ in range(10):
            snap = (await client.get("/snapshot")).json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                payload = executions[-1]["payload"]
                assert "error" in payload
                assert payload["error"]["code"] == "model_unavailable"
                return
            await asyncio.sleep(0.05)
        assert False, "execution model_unavailable event not emitted"

    run_with_client(app, scenario)


def test_digest_determinism_via_dbl_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> tuple[dict[str, object], str, int]:
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        snap = (await client.get("/snapshot")).json()
        event = snap["events"][0]
        expected_digest, expected_len = event_digest(
            "INTENT",
            event["correlation_id"],
            event["payload"],
        )
        return event, expected_digest, expected_len

    event, expected_digest, expected_len = run_with_client(app, scenario)
    assert event["digest"] == expected_digest
    assert event["canon_len"] == expected_len


def test_raw_il_not_stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        payload = _intent_envelope("hello")
        payload["payload"]["payload"]["raw_il"] = "should_drop"
        resp = await client.post("/ingress/intent", json=payload)
        assert resp.status_code == 202
        snap = (await client.get("/snapshot")).json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        stored_payload = intent["payload"]
        assert "raw_il" not in stored_payload

    run_with_client(app, scenario)


def test_forbidden_fields_not_in_intent_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        snap = (await client.get("/snapshot")).json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        payload = intent["payload"]
        forbidden = {"boundary_version", "boundary_config_hash", "intent_digest", "_digest_ref"}
        assert forbidden.isdisjoint(set(payload.keys()))

    run_with_client(app, scenario)


def test_chat_message_preserves_inputs_for_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        payload = _intent_envelope("hello")
        payload["payload"]["inputs"] = {
            "principal_id": "user-1",
            "capability": "chat",
            "model_id": "gpt-4o-mini",
            "provider": "openai",
            "max_output_tokens": 64,
            "input_chars": 5,
        }
        resp = await client.post("/ingress/intent", json=payload)
        assert resp.status_code == 202
        snap = (await client.get("/snapshot")).json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        inputs = intent["payload"].get("inputs")
        assert isinstance(inputs, dict)
        assert inputs["principal_id"] == "user-1"
        assert inputs["capability"] == "chat"
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]
        assert "reason_codes" in payload
        assert "admission.missing_required" not in payload["reason_codes"]

    run_with_client(app, scenario)


def test_policy_context_is_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    authoritative = {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "correlation_id": "c-1",
        "payload": {
            "message": "hi",
            "inputs": {
                "principal_id": "user-1",
                "capability": "chat",
                "correlation_id": "c-1",
            },
        },
        "extra_key": "should_not_pass",
    }
    context = governance._build_policy_context(authoritative)
    assert "correlation_id" not in context.inputs
    assert "message" not in context.inputs
    assert set(context.inputs.keys()) == {"principal_id", "capability"}


def test_policy_context_rejects_nested_shapes() -> None:
    authoritative = {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "correlation_id": "c-1",
        "payload": {
            "message": "hi",
            "inputs": {
                "principal_id": "user-1",
                "extensions": {"secret": "nope"},
            },
        },
    }
    adapter = governance.DblPolicyAdapter()
    decision = adapter.decide(authoritative)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ["context.invalid_shape"]


@pytest.mark.parametrize("bad_value", [[], {}, b"bytes"])
def test_policy_context_rejects_non_scalar(bad_value) -> None:
    authoritative = {
        "stream_id": "default",
        "lane": "user_chat",
        "actor": "user",
        "intent_type": "chat.message",
        "correlation_id": "c-1",
        "payload": {
            "message": "hi",
            "inputs": {
                "principal_id": bad_value,
            },
        },
    }
    adapter = governance.DblPolicyAdapter()
    decision = adapter.decide(authoritative)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ["context.invalid_shape"]


def test_digest_excludes_obs_fields() -> None:
    correlation_id = "c-obs"
    payload = {"a": 1, "b": {"x": "y"}}
    payload_with_obs = {"a": 1, "b": {"x": "y"}, "_obs": {"ip": "1.2.3.4", "ua": "x"}}

    d1, l1 = event_digest("INTENT", correlation_id, payload)
    d2, l2 = event_digest("INTENT", correlation_id, payload_with_obs)

    assert d1 == d2
    assert l1 == l2


def test_digest_is_key_order_invariant() -> None:
    correlation_id = "c-order"
    p1 = {"a": 1, "b": 2, "c": {"x": 1, "y": 2}}
    p2 = {"c": {"y": 2, "x": 1}, "b": 2, "a": 1}

    d1, l1 = event_digest("INTENT", correlation_id, p1)
    d2, l2 = event_digest("INTENT", correlation_id, p2)

    assert d1 == d2
    assert l1 == l2


def test_snapshot_v_digest_is_paging_invariant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("GATEWAY_EXEC_MODE", "external")
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap_a = (await client.get("/snapshot", params={"limit": 1, "offset": 0})).json()
        snap_b = (await client.get("/snapshot", params={"limit": 1, "offset": 1})).json()
        snap_all = (await client.get("/snapshot", params={"limit": 2000, "offset": 0})).json()

        assert snap_a["v_digest"] == snap_b["v_digest"] == snap_all["v_digest"]
        assert snap_all["length"] == 2

    run_with_client(app, scenario)


def test_snapshot_interface_version_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = (await client.get("/snapshot")).json()
        assert "interface_version" not in snap

    run_with_client(app, scenario)


def test_v_digest_changes_on_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("one"))
        v1 = (await client.get("/snapshot")).json()["v_digest"]
        await client.post("/ingress/intent", json=_intent_envelope("two"))
        v2 = (await client.get("/snapshot")).json()["v_digest"]
        assert v1 != v2

    run_with_client(app, scenario)


def test_normalize_trace_is_json_safe_and_stable() -> None:
    psi = kl_kernel_logic.PsiDefinition(psi_type="test", name="t", metadata={})
    kernel = kl_kernel_logic.Kernel(deterministic_mode=True)

    trace = kernel.execute(psi=psi, task=lambda: {"k": "v"})
    trace_dict_1, digest_1 = normalize_trace(trace)

    json.dumps(trace_dict_1, ensure_ascii=True, sort_keys=True)

    trace2 = kernel.execute(psi=psi, task=lambda: {"k": "v"})
    trace_dict_2, digest_2 = normalize_trace(trace2)

    assert digest_1 == digest_2
    assert trace_dict_1 == trace_dict_2


def test_decision_payload_contains_policy_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = (await client.get("/snapshot")).json()
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]

        assert payload["decision"] in {"ALLOW", "DENY"}
        assert "reason_codes" in payload
        assert "policy_id" in payload
        assert "policy_version" in payload

    run_with_client(app, scenario)


def test_all_emitted_events_have_digest_label_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = (await client.get("/snapshot")).json()
        for event in snap["events"]:
            digest = event.get("digest")
            assert isinstance(digest, str)
            assert digest.startswith("sha256:")

    run_with_client(app, scenario)


def test_decision_policy_version_is_string(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = (await client.get("/snapshot")).json()
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]
        assert isinstance(payload.get("policy_version"), str)

    run_with_client(app, scenario)


def test_decision_normative_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = (await client.get("/snapshot")).json()
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]
        assert "policy" in payload and isinstance(payload["policy"], dict)
        assert "assembly_digest" in payload and isinstance(payload["assembly_digest"], str)
        assert payload["assembly_digest"] != "sha256:" + ("0" * 64)
        assert "context_digest" in payload
        if payload["result"] == "ALLOW":
            assert isinstance(payload["context_digest"], str)
            assert payload["context_digest"] != "sha256:" + ("0" * 64)
        else:
            assert payload["context_digest"] is None
        assert "result" in payload and payload["result"] in {"ALLOW", "DENY"}
        assert "reasons" in payload and isinstance(payload["reasons"], list)
        assert "transforms" in payload and isinstance(payload["transforms"], list)

    run_with_client(app, scenario)


def test_policy_evaluation_error_sets_error_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("DBL_GATEWAY_POLICY_MODULE", "policy_raises")
    monkeypatch.setenv("DBL_GATEWAY_POLICY_OBJECT", "policy")
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        decision = None
        snap = None
        for _ in range(40):
            snap = (await client.get("/snapshot")).json()
            decisions = [event for event in snap["events"] if event["kind"] == "DECISION"]
            if decisions:
                decision = decisions[-1]
                break
            await asyncio.sleep(0.05)
        assert decision is not None
        payload = decision["payload"]
        assert payload["decision"] == "DENY"
        assert payload["reason_codes"] == ["evaluation_error"]
        assert payload["context_digest"] is None
        assert isinstance(payload.get("assembly_digest"), str)
        assert payload.get("assembly_digest") != "sha256:" + ("0" * 64)
        error_ref = payload.get("error_ref")
        assert isinstance(error_ref, str) and error_ref
        assert snap is not None
        artifact_events = [
            event for event in snap["events"]
            if event["kind"] == "PROOF" and event.get("payload", {}).get("artifact_id") == error_ref
        ]
        assert artifact_events
        artifact_payload = artifact_events[-1]["payload"]
        assert artifact_payload.get("stage") == "policy"

    run_with_client(app, scenario)


def test_status_surface_projects_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)

    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("hello"))
        status = (await client.get("/status")).json()

        assert "phase" in status
        assert "runner_status" in status
        assert "t_index" in status

    run_with_client(app, scenario)


def test_openai_error_message_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 401
        text = "unauthorized"

        def json(self):
            return {"error": {"message": "Incorrect API key provided"}}

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(openai_provider.httpx, "Client", DummyClient)

    output_text, trace, trace_digest, error = asyncio.run(
        _call_kernel([{"role": "user", "content": "hello"}], "gpt-4o-mini", "openai", openai_provider.execute, offload=False)
    )
    assert error is not None
    assert "Incorrect API key provided" in str(error.get("message"))


def test_capabilities_response_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_CHAT_MODEL_IDS", "gpt-4o-mini")
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> dict[str, object]:
        resp = await client.get("/capabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_version"] == INTERFACE_VERSION
        assert data["surfaces"]["tail"] is True
        assert data["surfaces"]["snapshot"] is True
        assert data["surfaces"]["events"] is False
        assert data["surfaces"]["ingress_intent"] is True
        providers = data["providers"]
        assert isinstance(providers, list)
        assert providers and providers[0]["id"] == "openai"
        model = providers[0]["models"][0]
        assert "id" in model
        assert "display_name" in model
        assert "features" in model
        assert "limits" in model
        return model

    model = run_with_client(app, scenario)
    assert "health" in model


def test_v_state_init_and_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "trail.sqlite"
    monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("one"))
        await client.post("/ingress/intent", json=_intent_envelope("two"))

    run_with_client(app, scenario)
    store = SQLiteStore(db_path)
    store._conn.execute("DELETE FROM v_state")  # simulate pre-v_state db
    store._conn.commit()
    store._ensure_v_state()
    v_digest_before, last_index_before = store._get_v_state()
    recomputed = store.recompute_v_digest()
    assert v_digest_before == recomputed
    assert last_index_before >= 1
    store.close()


def test_rolling_v_digest_matches_full_recompute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "trail.sqlite"
    monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        await client.post("/ingress/intent", json=_intent_envelope("one"))
        await client.post("/ingress/intent", json=_intent_envelope("two"))
        await client.post("/ingress/intent", json=_intent_envelope("three"))

    run_with_client(app, scenario)
    store = SQLiteStore(db_path)
    rolling, _ = store._get_v_state()
    recomputed = store.recompute_v_digest()
    assert rolling == recomputed
    store.close()


def test_tail_since_semantics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(start_workers=True)
    async def scenario(client: httpx.AsyncClient) -> None:
        resp = await client.post("/ingress/intent", json=_intent_envelope("one"))
        assert resp.status_code == 202
        resp = await client.post("/ingress/intent", json=_intent_envelope("two", model_id="gpt-4o-mini"))
        assert resp.status_code == 202
        tail_route = [r for r in app.router.routes if getattr(r, "path", "") == "/tail"][0]

        async def _read_tail_once() -> dict[str, object]:
            async def _receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": "GET",
                "path": "/tail",
                "query_string": b"since=0",
                "headers": [(b"x-dev-roles", b"gateway.snapshot.read")],
                "client": ("testclient", 123),
                "server": ("testserver", 80),
                "scheme": "http",
            }
            request = Request(scope, _receive)
            response = await tail_route.endpoint(request, stream_id=None, since=0, lanes=None)
            body_iter = response.body_iterator
            try:
                async for chunk in body_iter:
                    if not chunk:
                        continue
                    if isinstance(chunk, bytes):
                        text = chunk.decode("utf-8", errors="replace")
                    else:
                        text = str(chunk)
                    for line in text.splitlines():
                        if line.startswith("data:"):
                            return json.loads(line.replace("data:", "", 1).strip())
            finally:
                if hasattr(body_iter, "aclose"):
                    await body_iter.aclose()
            raise AssertionError("tail did not emit data")

        data = await asyncio.wait_for(_read_tail_once(), timeout=2.0)
        assert data["index"] > 0

    run_with_client(app, scenario)


def test_replay_determinism_decision_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def run_once(db_path: Path) -> dict[str, object]:
        monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
        app = create_app(start_workers=True)

        async def scenario(client: httpx.AsyncClient) -> dict[str, object]:
            resp = await client.post("/ingress/intent", json=_intent_envelope("hello"))
            assert resp.status_code == 202
            for _ in range(10):
                snap = (await client.get("/snapshot")).json()
                decisions = [event for event in snap["events"] if event["kind"] == "DECISION"]
                if decisions:
                    payload = decisions[-1]["payload"]
                    return {
                        "decision": payload.get("decision"),
                        "reason_codes": payload.get("reason_codes"),
                        "policy_id": payload.get("policy_id"),
                        "policy_version": payload.get("policy_version"),
                    }
                await asyncio.sleep(0.05)
            raise AssertionError("decision not emitted")

        return run_with_client(app, scenario)

    a = run_once(tmp_path / "trail_a.sqlite")
    b = run_once(tmp_path / "trail_b.sqlite")
    assert a == b
