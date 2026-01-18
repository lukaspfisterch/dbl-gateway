from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from dbl_core.normalize.trace import sanitize_trace
from dbl_core.events.trace_digest import trace_digest

from .admission import admit_and_shape_intent, AdmissionFailure
from .capabilities import CapabilitiesResponse, get_capabilities, resolve_model, resolve_provider
from .adapters.execution_adapter_kl import KlExecutionAdapter
from .adapters.policy_adapter_dbl_policy import DblPolicyAdapter, _load_policy
from .context_builder import build_context_with_refs
from .config import get_context_config
from .decision_builder import build_normative_decision
from .ports.execution_port import ExecutionResult
from .ports.policy_port import DecisionResult
from .models import EventRecord
from .projection import project_runner_state, state_payload
from .store.factory import create_store
from .store.sqlite import ParentValidationError
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


def create_app(*, start_workers: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _configure_logging()
        _audit_env()
        policy = _load_policy_with_fallback()
        store = create_store()
        work_queue = asyncio.Queue(maxsize=_work_queue_max()) if start_workers else None
        app.state.store = store
        app.state.policy = DblPolicyAdapter(policy=policy)
        app.state.execution = KlExecutionAdapter()
        app.state.work_queue = work_queue
        app.state.worker_tasks: list[asyncio.Task] = []
        app.state.start_time = time.monotonic()
        if start_workers and work_queue is not None:
            worker = asyncio.create_task(_work_queue_loop(app, work_queue))
            app.state.worker_tasks.append(worker)
        try:
            yield
        finally:
            for task in getattr(app.state, "worker_tasks", []):
                task.cancel()
            for task in getattr(app.state, "worker_tasks", []):
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            store.close()

    app = FastAPI(title="DBL Gateway", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ],
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
        payload_for_shape = dict(raw_payload)
        payload_for_shape.update(_shape_identity(intent_payload))
        outer_inputs = intent_payload.get("inputs")
        if isinstance(outer_inputs, Mapping):
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
        thread_id, turn_id, parent_turn_id = _require_anchors(authoritative.get("payload", {}))
        try:
            intent_event = app.state.store.append(
                kind="INTENT",
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
                lane=authoritative["lane"],
                actor=authoritative["actor"],
                intent_type=authoritative["intent_type"],
                stream_id=authoritative["stream_id"],
                correlation_id=envelope["correlation_id"],
                payload=authoritative["payload"],
            )
        except ParentValidationError as exc:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "reason_code": "admission.invalid_parent", "detail": str(exc)},
            )

        work_queue = getattr(app.state, "work_queue", None)
        if work_queue is None:
            return JSONResponse(
                status_code=503,
                content={"accepted": False, "reason_code": "workers.stopped", "detail": "work queue unavailable"},
            )
        try:
            work_queue.put_nowait((intent_event, envelope["correlation_id"], trace_id))
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

    @app.get("/threads/{thread_id}/timeline")
    async def thread_timeline(
        request: Request,
        thread_id: str,
        include_payload: bool = Query(False),
    ) -> dict[str, Any]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        thread_id_norm = thread_id.strip()
        if not thread_id_norm:
            raise HTTPException(status_code=400, detail="thread_id must be a non-empty string")
        events = app.state.store.timeline(thread_id=thread_id_norm, include_payload=True)
        turns: dict[str, dict[str, Any]] = {}
        for event in events:
            tid = str(event.get("turn_id") or "")
            parent = event.get("parent_turn_id")
            turn = turns.get(tid)
            if turn is None:
                turn = {"turn_id": tid, "parent_turn_id": parent, "events": [], "_first_idx": event["index"]}
                turns[tid] = turn
            turn["_first_idx"] = min(turn["_first_idx"], event["index"])
            payload = event.get("payload") or {}
            entry: dict[str, Any] = {
                "idx": event["index"],
                "kind": event["kind"],
                "correlation_id": event.get("correlation_id"),
            }
            ctx_digest = payload.get("context_digest")
            if isinstance(ctx_digest, str):
                entry["context_digest"] = ctx_digest
            if event.get("kind") == "DECISION" and isinstance(event.get("digest"), str):
                entry["decision_digest"] = event["digest"]
            if include_payload:
                entry["payload"] = payload
            turn["events"].append(entry)
        ordered_turns = sorted(turns.values(), key=lambda t: (t["_first_idx"], t["turn_id"]))
        for turn in ordered_turns:
            turn.pop("_first_idx", None)
            turn["events"] = sorted(turn["events"], key=lambda e: (e["idx"], e["kind"], e["correlation_id"]))
        return {"thread_id": thread_id_norm, "turns": ordered_turns}

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
        thread_id, turn_id, parent_turn_id = _require_anchors(p)
        try:
            event = app.state.store.append(
                kind="EXECUTION",
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
                lane=lane,
                actor=actor,
                intent_type=intent_type,
                stream_id=stream_id,
                correlation_id=correlation_id,
                payload=p,
            )
        except ParentValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True, "execution_index": event["index"]}

    return app


async def _process_intent(
    app: FastAPI,
    intent_event: EventRecord,
    correlation_id: str,
    trace_id: str,
) -> None:
    thread_id, turn_id, parent_turn_id = _anchors_for_event(intent_event)
    decision_emitted = False
    context_digest: str | None = None
    context_config_digest: str | None = None  # NEW: Config digest for DECISION
    boundary_context: dict[str, Any] | None = None
    context_transforms: list[dict[str, Any]] = []
    context_spec: Mapping[str, Any] | None = None
    assembled_context: Mapping[str, Any] | None = None
    try:
        authoritative = _authoritative_from_event(intent_event, correlation_id)
        
        # Fetch thread events for ref resolution
        thread_events = app.state.store.timeline(thread_id=thread_id)
        
        context_artifacts = build_context_with_refs(
            authoritative.get("payload"),
            intent_type=str(authoritative.get("intent_type") or ""),
            thread_events=thread_events,
        )
        context_digest = context_artifacts.context_digest
        context_config_digest = context_artifacts.config_digest  # NEW: Extract config digest
        context_transforms = list(context_artifacts.transforms)
        context_spec = context_artifacts.context_spec
        assembled_context = context_artifacts.assembled_context
        boundary_context = {
            "context_digest": context_digest,
            "context_spec": context_spec,
            "assembled_context": assembled_context,
            "admitted_model_messages": assembled_context.get("model_messages", []),
            "meta": context_artifacts.boundary_meta,
        }
        try:
            decision = app.state.policy.decide(authoritative)
        except Exception as exc:
            _LOGGER.exception("policy decision failed: %s", exc)
            app.state.store.append(
                kind="DECISION",
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
                lane=authoritative["lane"],
                actor="policy",
                intent_type=authoritative["intent_type"],
                stream_id=authoritative["stream_id"],
                correlation_id=correlation_id,
                payload=_decision_payload(
                    DecisionResult(decision="DENY", reason_codes=["evaluation_error"]),
                    trace_id,
                    context_digest=context_digest,
                    context_config_digest=context_config_digest,
                    boundary=boundary_context,
                    requested_model_id=None,
                    resolved_model_id=None,
                    provider=None,
                    transforms=context_transforms,
                    context_spec=context_spec,
                    assembled_context=assembled_context,
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
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
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
                context_digest=context_digest,
                context_config_digest=context_config_digest,
                boundary=boundary_context,
                resolution_reason=resolution_reason,
                transforms=context_transforms,
                context_spec=context_spec,
                assembled_context=assembled_context,
            ),
        )
        decision_emitted = True

        if decision.decision != "ALLOW" or _get_exec_mode() != "embedded":
            return

        try:
            # Pass model_messages from context builder to execution
            # This ensures declared_refs content flows into the LLM prompt
            model_messages = None
            if assembled_context:
                model_messages = assembled_context.get("model_messages")
            
            result = await app.state.execution.run(
                intent_event,
                model_messages=model_messages,
            )
            payload = _execution_payload(
                result,
                trace_id,
                requested_model_id=requested_model or None,
                resolved_model_id=resolved_model or None,
                context_digest=context_digest,
                boundary=boundary_context,
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
            if context_digest:
                payload["context_digest"] = context_digest
            _attach_boundary_obs(payload, boundary_context, trace_id)

        app.state.store.append(
            kind="EXECUTION",
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
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
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
            lane=intent_event["lane"],
            actor="policy",
            intent_type=intent_event["intent_type"],
            stream_id=intent_event["stream_id"],
            correlation_id=correlation_id,
            payload=_decision_payload(
                DecisionResult(decision="DENY", reason_codes=["evaluation_error"]),
                trace_id,
                context_digest=context_digest,
                context_config_digest=context_config_digest,
                boundary=boundary_context,
                requested_model_id=None,
                resolved_model_id=None,
                provider=None,
                transforms=context_transforms,
                context_spec=context_spec,
                assembled_context=assembled_context,
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
    context_digest: str | None = None,
    context_config_digest: str | None = None,  # NEW: Config digest for replay
    boundary: Mapping[str, Any] | None = None,
    transforms: Sequence[Mapping[str, Any]] | None = None,
    context_spec: Mapping[str, Any] | None = None,
    assembled_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    normative = build_normative_decision(
        decision,
        context_digest=context_digest,
        transforms=transforms,
    )
    payload: dict[str, Any] = {
        "decision": decision.decision,
        "reason_codes": decision.reason_codes or [],
        "policy_id": normative["policy"]["policy_id"],
        "policy_version": normative["policy"]["policy_version"],
        **normative,
    }
    if context_spec is not None:
        payload["context_spec"] = context_spec
    if assembled_context is not None:
        payload["assembled_context"] = assembled_context
    # NEW: Boundary block with config_digest for replay verification
    if context_config_digest:
        payload["boundary"] = {
            "context_config_digest": context_config_digest,
            "boundary_version": "1",
        }
    if requested_model_id:
        payload.setdefault("_obs", {})  # keep out of normative digest
        payload["_obs"]["requested_model_id"] = requested_model_id
    if resolved_model_id:
        payload.setdefault("_obs", {})
        payload["_obs"]["resolved_model_id"] = resolved_model_id
    if provider:
        payload.setdefault("_obs", {})
        payload["_obs"]["provider"] = provider
    _attach_obs_trace_id(payload, trace_id)
    _attach_boundary_obs(payload, boundary, trace_id)
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
    context_digest: str | None = None,
    boundary: Mapping[str, Any] | None = None,
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
    if context_digest:
        payload["context_digest"] = context_digest

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
    _attach_boundary_obs(payload, boundary, trace_id)
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


async def _work_queue_loop(app: FastAPI, work_queue: asyncio.Queue) -> None:
    try:
        while True:
            intent_event, correlation_id, trace_id = await work_queue.get()
            try:
                await _process_intent(app, intent_event, correlation_id, trace_id)
            except Exception as exc:
                _LOGGER.exception("worker task failed: %s", exc)
    except asyncio.CancelledError:
        raise


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


def _attach_boundary_obs(payload: dict[str, Any], boundary: Mapping[str, Any] | None, trace_id: str) -> None:
    if not boundary:
        return
    _attach_obs_trace_id(payload, trace_id)
    obs = payload.get("_obs")
    if isinstance(obs, dict):
        obs["boundary"] = boundary


def _shape_payload(intent_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if intent_type == "chat.message":
        shaped: dict[str, Any] = _shape_identity(payload)
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


def _shape_identity(source: Mapping[str, Any]) -> dict[str, str]:
    shaped: dict[str, str] = {}
    thread_id = source.get("thread_id")
    turn_id = source.get("turn_id")
    parent_turn_id = source.get("parent_turn_id")
    if isinstance(thread_id, str) and thread_id.strip():
        shaped["thread_id"] = thread_id.strip()
    if isinstance(turn_id, str) and turn_id.strip():
        shaped["turn_id"] = turn_id.strip()
    if isinstance(parent_turn_id, str) and parent_turn_id.strip():
        shaped["parent_turn_id"] = parent_turn_id.strip()
    return shaped


def _require_anchors(payload: Mapping[str, Any]) -> tuple[str, str, str | None]:
    thread_id = payload.get("thread_id")
    turn_id = payload.get("turn_id")
    parent_turn_id = payload.get("parent_turn_id")
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise HTTPException(status_code=400, detail="thread_id is required")
    if not isinstance(turn_id, str) or not turn_id.strip():
        raise HTTPException(status_code=400, detail="turn_id is required")
    parent_value: str | None = None
    if parent_turn_id is not None:
        if not isinstance(parent_turn_id, str):
            raise HTTPException(status_code=400, detail="parent_turn_id must be a string when provided")
        parent_value = parent_turn_id.strip()
    return thread_id.strip(), turn_id.strip(), parent_value


def _anchors_for_event(event: EventRecord) -> tuple[str, str, str | None]:
    thread_id = event.get("thread_id")
    turn_id = event.get("turn_id")
    parent_turn_id = event.get("parent_turn_id")
    if isinstance(thread_id, str) and thread_id.strip() and isinstance(turn_id, str) and turn_id.strip():
        parent_value = parent_turn_id if parent_turn_id is None else str(parent_turn_id)
        return thread_id.strip(), turn_id.strip(), parent_value
    payload = event.get("payload")
    if isinstance(payload, Mapping):
        return _require_anchors(payload)
    raise HTTPException(status_code=400, detail="event missing identity anchors")


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
