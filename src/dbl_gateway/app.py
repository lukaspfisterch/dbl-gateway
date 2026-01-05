from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from dbl_core.normalize.trace import sanitize_trace
from dbl_core.events.trace_digest import trace_digest

from .admission import admit_and_shape_intent, AdmissionFailure
from .capabilities import CapabilitiesResponse, get_capabilities, resolve_model, resolve_provider
from .adapters.execution_adapter_kl import KlExecutionAdapter
from .adapters.policy_adapter_dbl_policy import DblPolicyAdapter, _load_policy
from .ports.execution_port import ExecutionResult
from .ports.policy_port import DecisionResult
from .models import EventRecord
from .projection import project_runner_state, state_payload
from .store.factory import create_store
from .wire_contract import parse_intent_envelope
from .auth import (
    Actor,
    AuthError,
    ForbiddenError,
    authenticate_request,
    require_roles,
    require_tenant,
    load_auth_config,
)


_LOGGER = logging.getLogger("dbl_gateway")


def _configure_logging() -> None:
    if _LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(logging.INFO)


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _configure_logging()
        _audit_env()
        policy = _load_policy_with_fallback()
        app.state.store = create_store()
        app.state.policy = DblPolicyAdapter(policy=policy)
        app.state.execution = KlExecutionAdapter()
        app.state.work_queue = asyncio.Queue(maxsize=_work_queue_max())
        app.state.worker_task = asyncio.create_task(_work_queue_loop(app))
        app.state.start_time = time.monotonic()
        try:
            yield
        finally:
            app.state.worker_task.cancel()
            app.state.store.close()

    app = FastAPI(title="DBL Gateway", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8787", "http://localhost:8787"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_logging(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "").strip() or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.monotonic()
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        latency_ms = int((time.monotonic() - start) * 1000)
        _LOGGER.info(
            '{"message":"request.completed","request_id":"%s","method":"%s","path":"%s","status_code":%d,"latency_ms":%d}',
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            latency_ms,
        )
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/capabilities", response_model=CapabilitiesResponse)
    async def capabilities(request: Request) -> dict[str, object]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        return get_capabilities()

    @app.post("/ingress/intent")
    async def ingress_intent(request: Request, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.intent.write"])
        try:
            envelope = parse_intent_envelope(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        trace_id = uuid.uuid4().hex
        intent_payload = envelope["payload"]
        raw_payload = intent_payload["payload"]
        payload_for_shape = raw_payload
        outer_inputs = intent_payload.get("inputs")
        if isinstance(outer_inputs, Mapping):
            payload_for_shape = dict(raw_payload)
            payload_for_shape["inputs"] = dict(outer_inputs)
        shaped_payload = _shape_payload(intent_payload["intent_type"], payload_for_shape)
        try:
            admission_record = admit_and_shape_intent(
                {
                    "correlation_id": envelope["correlation_id"],
                    "deterministic": {
                        "stream_id": intent_payload["stream_id"],
                        "lane": intent_payload["lane"],
                        "actor": intent_payload["actor"],
                        "intent_type": intent_payload["intent_type"],
                        "payload": shaped_payload,
                    },
                    "observational": {},
                },
                raw_payload=payload_for_shape,
            )
        except AdmissionFailure as exc:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "reason_code": exc.reason_code, "detail": exc.detail},
            )
        authoritative = _thaw_json(admission_record.deterministic)
        authoritative["correlation_id"] = admission_record.correlation_id
        if intent_payload.get("requested_model_id"):
            authoritative["payload"]["requested_model_id"] = intent_payload["requested_model_id"]
        if isinstance(outer_inputs, Mapping) and isinstance(authoritative.get("payload"), Mapping):
            payload_map = dict(authoritative["payload"])
            payload_map.setdefault("inputs", dict(outer_inputs))
            authoritative["payload"] = payload_map
        _attach_obs_trace_id(authoritative["payload"], trace_id)
        intent_event = app.state.store.append(
            kind="INTENT",
            lane=authoritative["lane"],
            actor=authoritative["actor"],
            intent_type=authoritative["intent_type"],
            stream_id=authoritative["stream_id"],
            correlation_id=envelope["correlation_id"],
            payload=authoritative["payload"],
        )

        try:
            app.state.work_queue.put_nowait((intent_event, envelope["correlation_id"], trace_id))
        except asyncio.QueueFull:
            return JSONResponse(
                status_code=503,
                content={"accepted": False, "reason_code": "queue.full", "detail": "work queue full"},
            )

        return JSONResponse(
            status_code=202,
            content={
                "accepted": True,
                "stream_id": authoritative["stream_id"],
                "index": intent_event["index"],
                "correlation_id": envelope["correlation_id"],
                "queued": True,
            },
        )

    @app.get("/snapshot")
    async def snapshot(
        request: Request,
        limit: int = Query(200, ge=1, le=2000),
        offset: int = Query(0, ge=0),
        stream_id: str | None = Query(None),
        lane: str | None = Query(None),
    ) -> dict[str, Any]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        return app.state.store.snapshot(
            limit=limit,
            offset=offset,
            stream_id=_normalize_optional_str(stream_id, "stream_id"),
            lane=_normalize_optional_str(lane, "lane"),
        )

    @app.get("/tail")
    async def tail(
        request: Request,
        stream_id: str | None = Query(None),
        since: int = Query(-1, ge=-1),
        lanes: str | None = Query(None),
    ) -> StreamingResponse:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])

        last_event_id = request.headers.get("last-event-id")
        if last_event_id and last_event_id.isdigit():
            since = max(since, int(last_event_id))

        lane_filter: set[str] | None = None
        if lanes:
            lane_filter = {lane.strip() for lane in lanes.split(",") if lane.strip()}
            if not lane_filter:
                lane_filter = None

        async def event_stream():
            cursor = max(since + 1, 0)
            while True:
                if await request.is_disconnected():
                    break
                snap = app.state.store.snapshot(
                    limit=2000,
                    offset=cursor,
                    stream_id=_normalize_optional_str(stream_id, "stream_id") if stream_id else None,
                )
                events = snap.get("events", [])
                if not events:
                    await asyncio.sleep(0.5)
                    continue
                max_index = cursor - 1
                for event in events:
                    idx = event.get("index")
                    if isinstance(idx, int) and idx > max_index:
                        max_index = idx
                    if lane_filter and event.get("lane") not in lane_filter:
                        continue
                    data = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
                    event_id = str(idx) if isinstance(idx, int) else ""
                    if event_id:
                        yield f"id: {event_id}\n"
                    yield "event: envelope\n"
                    yield f"data: {data}\n\n"
                if max_index >= cursor:
                    cursor = max_index + 1

        headers = {
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)

    @app.get("/status")
    async def status_surface(
        request: Request,
        stream_id: str | None = Query(None),
    ) -> dict[str, object]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        snap = app.state.store.snapshot(limit=2000, offset=0, stream_id=stream_id)
        state = project_runner_state(snap["events"])
        return state_payload(state)

    @app.post("/execution/event")
    async def execution_event(request: Request, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.execution.write"])
        if _get_exec_mode() != "external":
            raise HTTPException(status_code=403, detail="execution events disabled in embedded mode")
        correlation_id = body.get("correlation_id")
        payload = body.get("payload")
        if not isinstance(correlation_id, str) or not correlation_id:
            raise HTTPException(status_code=400, detail="correlation_id must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=400, detail="payload must be an object")
        lane = str(body.get("lane", ""))
        actor = str(body.get("actor", ""))
        intent_type = str(body.get("intent_type", ""))
        stream_id = str(body.get("stream_id", ""))
        if not all([lane, actor, intent_type, stream_id]):
            raise HTTPException(status_code=400, detail="lane, actor, intent_type, stream_id required")
        if not _decision_allows_execution(app, correlation_id):
            raise HTTPException(status_code=409, detail="no ALLOW decision for correlation_id")
        p = dict(payload)
        trace_value = p.get("trace")
        if isinstance(trace_value, Mapping):
            trace, trace_digest_value = make_trace_bundle(trace_value)
        else:
            trace, trace_digest_value = make_trace_bundle(
                {
                    "trace_id": correlation_id,
                    "lane": lane,
                    "intent_type": intent_type,
                    "stream_id": stream_id,
                }
            )
        p["trace"] = trace
        p["trace_digest"] = trace_digest_value
        event = app.state.store.append(
            kind="EXECUTION",
            lane=lane,
            actor=actor,
            intent_type=intent_type,
            stream_id=stream_id,
            correlation_id=correlation_id,
            payload=p,
        )
        return {"ok": True, "execution_index": event["index"]}

    return app


async def _process_intent(
    app: FastAPI,
    intent_event: EventRecord,
    correlation_id: str,
    trace_id: str,
) -> None:
    decision_emitted = False
    try:
        authoritative = _authoritative_from_event(intent_event, correlation_id)
        try:
            decision = app.state.policy.decide(authoritative)
        except Exception as exc:
            _LOGGER.exception("policy decision failed: %s", exc)
            app.state.store.append(
                kind="DECISION",
                lane=authoritative["lane"],
                actor="policy",
                intent_type=authoritative["intent_type"],
                stream_id=authoritative["stream_id"],
                correlation_id=correlation_id,
                payload=_decision_payload(
                    DecisionResult(decision="DENY", reason_codes=["evaluation_error"]),
                    trace_id,
                    requested_model_id=None,
                    resolved_model_id=None,
                    provider=None,
                ),
            )
            return

        requested_model = ""
        if isinstance(authoritative.get("payload"), Mapping):
            requested_model = str(authoritative["payload"].get("requested_model_id", "") or "")
        resolved_model = None
        provider = None
        resolution_reason = None
        try:
            resolved_model, _reason = resolve_model(requested_model)
            if resolved_model is None or _reason:
                resolution_reason = _reason or "model.unavailable"
            else:
                provider, _provider_reason = resolve_provider(resolved_model)
                if provider is None or _provider_reason:
                    resolution_reason = _provider_reason or "provider.unavailable"
                    resolved_model = None
                    provider = None
        except Exception as exc:
            _LOGGER.exception("model resolution failed: %s", exc)
            resolution_reason = "resolution.error"

        app.state.store.append(
            kind="DECISION",
            lane=authoritative["lane"],
            actor="policy",
            intent_type=authoritative["intent_type"],
            stream_id=authoritative["stream_id"],
            correlation_id=correlation_id,
            payload=_decision_payload(
                decision,
                trace_id,
                requested_model_id=requested_model or None,
                resolved_model_id=resolved_model or None,
                provider=provider,
                resolution_reason=resolution_reason,
            ),
        )
        decision_emitted = True

        if decision.decision != "ALLOW" or _get_exec_mode() != "embedded":
            return

        try:
            result = await app.state.execution.run(intent_event)
            payload = _execution_payload(
                result,
                trace_id,
                requested_model_id=requested_model or None,
                resolved_model_id=resolved_model or None,
            )
        except Exception as exc:
            trace, trace_digest_value = make_trace_bundle(
                {
                    "trace_id": trace_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "lane": intent_event.get("lane"),
                    "actor": intent_event.get("actor"),
                    "intent_type": intent_event.get("intent_type"),
                    "stream_id": intent_event.get("stream_id"),
                }
            )
            payload = {
                "provider": provider,
                "model_id": resolved_model or "",
                "requested_model_id": requested_model or None,
                "resolved_model_id": resolved_model or None,
                "error": {
                    "code": "execution_failed",
                    "message": f"{type(exc).__name__}: {exc}",
                },
                "trace": trace,
                "trace_digest": trace_digest_value,
            }

        app.state.store.append(
            kind="EXECUTION",
            lane=intent_event["lane"],
            actor="executor",
            intent_type=intent_event["intent_type"],
            stream_id=intent_event["stream_id"],
            correlation_id=correlation_id,
            payload=payload,
        )
    except Exception as exc:
        _LOGGER.exception("intent processing failed: %s", exc)
        if decision_emitted:
            return
        app.state.store.append(
            kind="DECISION",
            lane=intent_event["lane"],
            actor="policy",
            intent_type=intent_event["intent_type"],
            stream_id=intent_event["stream_id"],
            correlation_id=correlation_id,
            payload=_decision_payload(
                DecisionResult(decision="DENY", reason_codes=["evaluation_error"]),
                trace_id,
                requested_model_id=None,
                resolved_model_id=None,
                provider=None,
            ),
        )


def _decision_payload(
    decision: DecisionResult,
    trace_id: str,
    *,
    requested_model_id: str | None,
    resolved_model_id: str | None,
    provider: str | None,
    resolution_reason: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "decision": decision.decision,
        "reason_codes": decision.reason_codes,
    }
    if requested_model_id:
        payload["requested_model_id"] = requested_model_id
    if resolved_model_id:
        payload["resolved_model_id"] = resolved_model_id
    if provider:
        payload["provider"] = provider
    if decision.policy_id:
        payload["policy_id"] = decision.policy_id
    if decision.policy_version is not None:
        payload["policy_version"] = str(decision.policy_version)
    _attach_obs_trace_id(payload, trace_id)
    if resolution_reason:
        obs = payload.get("_obs")
        if not isinstance(obs, dict):
            obs = {}
            payload["_obs"] = obs
        obs["resolution_reason"] = resolution_reason
    return payload


def _execution_payload(
    result: ExecutionResult,
    trace_id: str,
    *,
    requested_model_id: str | None,
    resolved_model_id: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider": result.provider,
        "model_id": result.model_id,
    }
    if requested_model_id:
        payload["requested_model_id"] = requested_model_id
    if resolved_model_id:
        payload["resolved_model_id"] = resolved_model_id

    if result.error:
        payload["error"] = result.error
    else:
        payload["output_text"] = result.output_text or ""

    if isinstance(result.trace, Mapping):
        raw_trace = dict(result.trace)
        raw_trace.setdefault("trace_id", trace_id)
    elif result.trace is not None:
        raw_trace = {"trace_id": trace_id, "value": result.trace}
    else:
        raw_trace = {
            "trace_id": trace_id,
            "provider": result.provider,
            "model_id": result.model_id,
            "has_error": bool(result.error),
        }
    trace, trace_digest_value = make_trace_bundle(raw_trace)
    payload["trace"] = trace
    payload["trace_digest"] = trace_digest_value
    return payload


def _decision_allows_execution(app: FastAPI, correlation_id: str) -> bool:
    snap = app.state.store.snapshot(limit=2000, offset=0)
    events = [e for e in snap["events"] if e["correlation_id"] == correlation_id]
    for event in reversed(events):
        if event["kind"] == "DECISION":
            payload = event["payload"]
            if isinstance(payload, Mapping):
                return payload.get("decision") == "ALLOW"
            return False
    return False


def _normalize_optional_str(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if value.strip() == "":
        raise HTTPException(status_code=400, detail=f"{name} must be a non-empty string")
    return value.strip()


def _get_exec_mode() -> str:
    import os

    return os.getenv("GATEWAY_EXEC_MODE", "embedded").strip().lower()


def _get_gateway_mode() -> str:
    import os

    return os.getenv("GATEWAY_MODE", "").strip().lower()


def _work_queue_max() -> int:
    import os

    raw = os.getenv("DBL_GATEWAY_WORK_QUEUE_MAX", "").strip()
    if raw:
        try:
            value = int(raw)
            return max(1, value)
        except ValueError:
            return 100
    return 100


async def _work_queue_loop(app: FastAPI) -> None:
    while True:
        intent_event, correlation_id, trace_id = await app.state.work_queue.get()
        try:
            await _process_intent(app, intent_event, correlation_id, trace_id)
        except Exception as exc:
            _LOGGER.exception("worker task failed: %s", exc)


def _audit_env() -> None:
    import os

    def present(name: str) -> str:
        return "FOUND" if os.getenv(name, "").strip() else "MISSING"

    _LOGGER.info("CONFIG AUDIT")
    _LOGGER.info("Policy:")
    _LOGGER.info("  DBL_GATEWAY_POLICY_MODULE: %s", present("DBL_GATEWAY_POLICY_MODULE"))
    policy_obj = os.getenv("DBL_GATEWAY_POLICY_OBJECT", "").strip()
    policy_obj_status = "not set (default: POLICY)" if policy_obj == "" else "FOUND"
    _LOGGER.info("  DBL_GATEWAY_POLICY_OBJECT: %s", policy_obj_status)
    _LOGGER.info("  GATEWAY_MODE: %s", present("GATEWAY_MODE"))

    _LOGGER.info("Providers:")
    for name in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "MISTRAL_API_KEY",
        "COHERE_API_KEY",
        "AI21_API_KEY",
        "XAI_API_KEY",
        "PERPLEXITY_API_KEY",
        "OPENROUTER_API_KEY",
        "OLLAMA_HOST",
        "VLLM_ENDPOINT",
        "LMSTUDIO_API_KEY",
        "ANY_API_KEY",
    ]:
        _LOGGER.info("  %s: %s", name, present(name))

    _LOGGER.info("Cloud:")
    for name in [
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
    ]:
        _LOGGER.info("  %s: %s", name, present(name))

    _LOGGER.info("Storage:")
    for name in [
        "DATABASE_URL",
        "REDIS_URL",
    ]:
        _LOGGER.info("  %s: %s", name, present(name))


def _load_policy_with_fallback() -> object:
    import os

    try:
        policy = _load_policy()
        module_path = os.getenv("DBL_GATEWAY_POLICY_MODULE", "").strip()
        obj_name = os.getenv("DBL_GATEWAY_POLICY_OBJECT", "POLICY").strip() or "POLICY"
        _LOGGER.info("Policy: resolved %s:%s", module_path, obj_name)
        return policy
    except Exception as exc:
        if _get_gateway_mode() == "dev":
            from dbl_policy.deny_all import POLICY as DENY_POLICY

            _LOGGER.warning("Policy: load failed (%s); using dbl_policy.deny_all", exc)
            return DENY_POLICY
        raise RuntimeError("policy load failed") from exc

async def _require_actor(request: Request) -> Actor:
    cfg = load_auth_config()
    try:
        actor = await authenticate_request(request.headers, cfg)
        require_tenant(actor, cfg)
        return actor
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ForbiddenError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _require_role(actor: Actor, roles: list[str]) -> None:
    try:
        require_roles(actor, roles)
    except ForbiddenError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _attach_obs_trace_id(payload: dict[str, Any], trace_id: str) -> None:
    obs = payload.get("_obs")
    if not isinstance(obs, dict):
        obs = {}
        payload["_obs"] = obs
    obs["trace_id"] = trace_id


def _shape_payload(intent_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if intent_type == "chat.message":
        shaped: dict[str, Any] = {}
        message = payload.get("message")
        if isinstance(message, str):
            shaped["message"] = message
        client_msg_id = payload.get("client_msg_id")
        if isinstance(client_msg_id, str) and client_msg_id.strip():
            shaped["client_msg_id"] = client_msg_id
        inputs = payload.get("inputs")
        if isinstance(inputs, Mapping):
            shaped["inputs"] = dict(inputs)
        return shaped
    return dict(payload)


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw_json(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _extract_trace_id(intent_event: EventRecord) -> str:
    payload = intent_event.get("payload")
    if isinstance(payload, Mapping):
        obs = payload.get("_obs")
        if isinstance(obs, Mapping):
            trace_id = obs.get("trace_id")
            if isinstance(trace_id, str) and trace_id.strip():
                return trace_id
    return uuid.uuid4().hex


def _authoritative_from_event(intent_event: EventRecord, correlation_id: str) -> dict[str, Any]:
    payload = intent_event.get("payload")
    return {
        "stream_id": intent_event.get("stream_id"),
        "lane": intent_event.get("lane"),
        "actor": intent_event.get("actor"),
        "intent_type": intent_event.get("intent_type"),
        "correlation_id": correlation_id,
        "payload": payload,
    }


def make_trace_bundle(raw_trace: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    trace = sanitize_trace(raw_trace)
    return trace, trace_digest(trace)


def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(prog="dbl-gateway")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8010)
    serve.add_argument("--db", default=".\\data\\trail.sqlite")
    args = parser.parse_args()

    if args.db:
        import os

        os.environ["DBL_GATEWAY_DB"] = str(args.db)
    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, reload=False)


app = create_app()
