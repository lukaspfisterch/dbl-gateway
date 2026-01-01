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
from .capabilities import get_capabilities
from .adapters.execution_adapter_kl import KlExecutionAdapter, schedule_execution
from .adapters.policy_adapter_dbl_policy import DblPolicyAdapter
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
        app.state.store = create_store()
        app.state.policy = DblPolicyAdapter()
        app.state.execution = KlExecutionAdapter()
        app.state.start_time = time.monotonic()
        try:
            yield
        finally:
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

    @app.get("/capabilities")
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
        shaped_payload = _shape_payload(intent_payload["intent_type"], raw_payload)
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
                raw_payload=raw_payload,
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

        decision = app.state.policy.decide(authoritative)
        decision_event = app.state.store.append(
            kind="DECISION",
            lane=authoritative["lane"],
            actor="policy",
            intent_type=authoritative["intent_type"],
            stream_id=authoritative["stream_id"],
            correlation_id=envelope["correlation_id"],
            payload=_decision_payload(decision, trace_id),
        )

        if decision.decision == "ALLOW" and _get_exec_mode() == "embedded":
            schedule_execution(_execute_background(app, intent_event, envelope["correlation_id"]))

        return JSONResponse(
            status_code=202,
            content={
                "ok": True,
                "index": intent_event["index"],
                "correlation_id": envelope["correlation_id"],
                "stream_id": authoritative["stream_id"],
                "lane": authoritative["lane"],
                "intent_type": authoritative["intent_type"],
                "accepted_at": datetime.now(timezone.utc).isoformat(),
                "expected_next": "DECISION",
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
        since: int = Query(0, ge=0),
        lanes: str | None = Query(None),
    ) -> StreamingResponse:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])

        last_event_id = request.headers.get("last-event-id")
        if last_event_id and last_event_id.isdigit():
            since = max(since, int(last_event_id) + 1)

        lane_filter: set[str] | None = None
        if lanes:
            lane_filter = {lane.strip() for lane in lanes.split(",") if lane.strip()}
            if not lane_filter:
                lane_filter = None

        async def event_stream():
            cursor = since
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


async def _execute_background(app: FastAPI, intent_event: EventRecord, correlation_id: str) -> None:
    trace_id = _extract_trace_id(intent_event)
    try:
        result = await app.state.execution.run(intent_event)
        payload = _execution_payload(result, trace_id)
    except Exception as exc:
        requested_model = ""
        intent_payload = intent_event.get("payload")
        if isinstance(intent_payload, Mapping):
            requested_model = str(intent_payload.get("requested_model_id", "") or "")
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
            "provider": "kl",
            "model_id": requested_model or "unknown",
            "error": f"{type(exc).__name__}: {exc}",
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


def _decision_payload(decision: DecisionResult, trace_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "decision": decision.decision,
        "reason_codes": decision.reason_codes,
    }
    if decision.policy_id:
        payload["policy_id"] = decision.policy_id
    if decision.policy_version is not None:
        payload["policy_version"] = decision.policy_version
    _attach_obs_trace_id(payload, trace_id)
    return payload


def _execution_payload(result: ExecutionResult, trace_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider": result.provider,
        "model_id": result.model_id,
    }

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
