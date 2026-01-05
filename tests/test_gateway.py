from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
import sys
from fastapi.testclient import TestClient
from starlette.requests import Request

from dbl_gateway.app import create_app
from dbl_gateway.ports.execution_port import ExecutionResult
from dbl_gateway.wire_contract import INTERFACE_VERSION
from dbl_gateway.digest import event_digest
from dbl_gateway import governance
from dbl_core import normalize_trace
import kl_kernel_logic
from dbl_gateway.adapters.execution_adapter_kl import KlExecutionAdapter
from dbl_gateway.providers import openai as openai_provider
from dbl_gateway.store.sqlite import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))


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
    app = create_app()
    with TestClient(app) as client:
        resp = client.post(
            "/ingress/intent",
            json=_intent_envelope(
                "noop",
                intent_type="other.intent",
                payload_override={"value": 1.5},
            ),
        )
        assert resp.status_code == 400
        assert resp.json()["reason_code"] == "admission.invalid_input"
        snap = client.get("/snapshot").json()
        assert snap["length"] == 0


def test_admission_rejects_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        payload = _intent_envelope("hello")
        payload["payload"]["payload"]["api_key"] = "secret"
        resp = client.post("/ingress/intent", json=payload)
        assert resp.status_code == 400
        assert resp.json()["reason_code"] == "admission.secrets_present"
        snap = client.get("/snapshot").json()
        assert snap["length"] == 0


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
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        time.sleep(0.1)
        snap = client.get("/snapshot").json()
        kinds = [event["kind"] for event in snap["events"]]
        assert kinds == ["INTENT", "DECISION"]


def test_ingress_returns_immediately_without_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))

    async def slow_execution(self, _intent):
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
    app = create_app()
    with TestClient(app) as client:
        start = time.monotonic()
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        elapsed = time.monotonic() - start
        assert resp.status_code == 202
        ack = resp.json()
        assert ack["accepted"] is True
        assert ack["queued"] is True
        assert ack["correlation_id"] == "c-1"
        assert isinstance(ack["index"], int)
        assert elapsed < 0.2
        for _ in range(10):
            snap = client.get("/snapshot").json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                return
            time.sleep(0.05)
        assert False, "execution event not emitted"


def test_execution_error_captured_as_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))

    async def error_execution(self, _intent):
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
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        for _ in range(10):
            snap = client.get("/snapshot").json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                payload = executions[-1]["payload"]
                assert "error" in payload
                assert payload["error"]["status_code"] == 401
                assert "api_key" not in str(payload)
                return
            time.sleep(0.05)
        assert False, "execution error event not emitted"


def test_execution_model_unavailable_records_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_CHAT_MODEL_IDS", "gpt-4o-mini")
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        for _ in range(10):
            snap = client.get("/snapshot").json()
            executions = [event for event in snap["events"] if event["kind"] == "EXECUTION"]
            if executions:
                payload = executions[-1]["payload"]
                assert "error" in payload
                assert payload["error"]["code"] == "model_unavailable"
                return
            time.sleep(0.05)
        assert False, "execution model_unavailable event not emitted"


def test_digest_determinism_via_dbl_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        snap = client.get("/snapshot").json()
        event = snap["events"][0]
        expected_digest, expected_len = event_digest(
            "INTENT",
            event["correlation_id"],
            event["payload"],
        )
    assert event["digest"] == expected_digest
    assert event["canon_len"] == expected_len


def test_raw_il_not_stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        payload = _intent_envelope("hello")
        payload["payload"]["payload"]["raw_il"] = "should_drop"
        resp = client.post("/ingress/intent", json=payload)
        assert resp.status_code == 202
        snap = client.get("/snapshot").json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        stored_payload = intent["payload"]
        assert "raw_il" not in stored_payload


def test_forbidden_fields_not_in_intent_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
        assert resp.status_code == 202
        snap = client.get("/snapshot").json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        payload = intent["payload"]
        forbidden = {"boundary_version", "boundary_config_hash", "intent_digest", "_digest_ref"}
        assert forbidden.isdisjoint(set(payload.keys()))


def test_chat_message_preserves_inputs_for_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        payload = _intent_envelope("hello")
        payload["payload"]["inputs"] = {
            "principal_id": "user-1",
            "capability": "chat",
            "model_id": "gpt-4o-mini",
            "provider": "openai",
            "max_output_tokens": 64,
            "input_chars": 5,
        }
        resp = client.post("/ingress/intent", json=payload)
        assert resp.status_code == 202
        snap = client.get("/snapshot").json()
        intent = [event for event in snap["events"] if event["kind"] == "INTENT"][-1]
        inputs = intent["payload"].get("inputs")
        assert isinstance(inputs, dict)
        assert inputs["principal_id"] == "user-1"
        assert inputs["capability"] == "chat"
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]
        assert "reason_codes" in payload
        assert "admission.missing_required" not in payload["reason_codes"]


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
    app = create_app()

    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap_a = client.get("/snapshot", params={"limit": 1, "offset": 0}).json()
        snap_b = client.get("/snapshot", params={"limit": 1, "offset": 1}).json()
        snap_all = client.get("/snapshot", params={"limit": 2000, "offset": 0}).json()

        assert snap_a["v_digest"] == snap_b["v_digest"] == snap_all["v_digest"]
        assert snap_all["length"] == 2


def test_snapshot_interface_version_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = client.get("/snapshot").json()
        assert "interface_version" not in snap


def test_v_digest_changes_on_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()

    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("one"))
        v1 = client.get("/snapshot").json()["v_digest"]
        client.post("/ingress/intent", json=_intent_envelope("two"))
        v2 = client.get("/snapshot").json()["v_digest"]
        assert v1 != v2


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
    app = create_app()

    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = client.get("/snapshot").json()
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]

        assert payload["decision"] in {"ALLOW", "DENY"}
        assert "reason_codes" in payload
        assert "policy_id" in payload
        assert "policy_version" in payload


def test_all_emitted_events_have_digest_label_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = client.get("/snapshot").json()
        for event in snap["events"]:
            digest = event.get("digest")
            assert isinstance(digest, str)
            assert digest.startswith("sha256:")


def test_decision_policy_version_is_string(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        snap = client.get("/snapshot").json()
        decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
        payload = decision["payload"]
        assert isinstance(payload.get("policy_version"), str)


def test_status_surface_projects_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()

    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("hello"))
        status = client.get("/status").json()

        assert "phase" in status
        assert "runner_status" in status
        assert "t_index" in status


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

    intent_event = {
        "payload": {"message": "hello", "requested_model_id": "gpt-4o-mini"},
    }
    result = asyncio.run(KlExecutionAdapter().run(intent_event))
    assert result.error is not None
    assert "Incorrect API key provided" in str(result.error.get("message"))


def test_capabilities_response_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_CHAT_MODEL_IDS", "gpt-4o-mini")
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/capabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_version"] == 1
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
    assert "health" in model


def test_v_state_init_and_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "trail.sqlite"
    monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
    app = create_app()
    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("one"))
        client.post("/ingress/intent", json=_intent_envelope("two"))
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
    app = create_app()
    with TestClient(app) as client:
        client.post("/ingress/intent", json=_intent_envelope("one"))
        client.post("/ingress/intent", json=_intent_envelope("two"))
        client.post("/ingress/intent", json=_intent_envelope("three"))
    store = SQLiteStore(db_path)
    rolling, _ = store._get_v_state()
    recomputed = store.recompute_v_digest()
    assert rolling == recomputed
    store.close()


def test_tail_since_semantics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/ingress/intent", json=_intent_envelope("one"))
        assert resp.status_code == 202
        resp = client.post("/ingress/intent", json=_intent_envelope("two", model_id="gpt-4o-mini"))
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

        data = asyncio.run(asyncio.wait_for(_read_tail_once(), timeout=2.0))
        assert data["index"] > 0


def test_replay_determinism_decision_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def run_once(db_path: Path) -> dict[str, object]:
        monkeypatch.setenv("DBL_GATEWAY_DB", str(db_path))
        app = create_app()
        with TestClient(app) as client:
            resp = client.post("/ingress/intent", json=_intent_envelope("hello"))
            assert resp.status_code == 202
            snap = client.get("/snapshot").json()
            decision = [event for event in snap["events"] if event["kind"] == "DECISION"][-1]
            payload = decision["payload"]
            return {
                "decision": payload.get("decision"),
                "reason_codes": payload.get("reason_codes"),
                "policy_id": payload.get("policy_id"),
                "policy_version": payload.get("policy_version"),
            }

    a = run_once(tmp_path / "trail_a.sqlite")
    b = run_once(tmp_path / "trail_b.sqlite")
    assert a == b
