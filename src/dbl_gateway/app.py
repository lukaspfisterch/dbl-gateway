from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from fastapi import Body, FastAPI, HTTPException, Query, Request
import os
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from dbl_core.normalize.trace import sanitize_trace
from dbl_core.events.trace_digest import trace_digest

from .admission import admit_and_shape_intent, AdmissionFailure
from .capabilities import (
    CapabilitiesResponse,
    get_capabilities_cached,
    get_intent_catalog,
    get_surface_catalog,
    resolve_model,
    resolve_provider,
    get_capabilities,
    surface_access_payload,
)
from .adapters.execution_adapter_kl import KlExecutionAdapter
from .adapters.policy_adapter_dbl_policy import DblPolicyAdapter, ObserverPolicy, _load_policy
from .context_builder import build_context_with_refs, RefResolutionError
from .config import (
    allowed_tool_families_for_mode,
    economic_policy_rule_for_mode,
    get_boundary_config,
    get_context_config,
    context_resolution_enabled,
    get_job_runtime_config,
    request_policy_rule_for_mode,
    reset_boundary_config_cache,
)
from .contracts import canonical_json_bytes
from .decision_builder import build_normative_decision
from .demo_agent import DEMO_SCENARIO_DESCRIPTION, DEMO_SCENARIO_NAME, DEMO_SCENARIO_VERSION, active_provider_model, build_envelope, default_steps, scenario_metadata
from .digest import compute_release_digest
from .ports.execution_port import ExecutionResult
from .rendering import render_provider_payload
from .ports.policy_port import DecisionResult
from .models import EventRecord
from .projection import project_runner_state, state_payload
from .store.factory import create_store
from .store.sqlite import OrderViolationError, ParentValidationError
from .wire_contract import parse_intent_envelope
from .auth import (
    Actor,
    AuthError,
    ForbiddenError,
    authenticate_request,
    identity_fields_for_actor,
    require_roles,
    require_tenant,
    load_auth_config,
    trust_class_for_actor,
)


_LOGGER = logging.getLogger("dbl_gateway")

# I-GOV-INPUT-1: Governance input must be derived exclusively from I_L.
# These are the only top-level keys allowed in the authoritative input dict
# passed to PolicyPort.decide(). Observational data (O_obs) — provider
# responses, execution results, timing, traces — is structurally excluded.
_GOVERNANCE_ALLOWED_KEYS: frozenset[str] = frozenset({
    "stream_id",
    "lane",
    "actor",
    "intent_type",
    "correlation_id",
    "payload",
    "tenant_id",
})


class GovernanceInputViolation(RuntimeError):
    """I-GOV-INPUT-1: Observational data detected in governance input."""


_TOOL_FAMILY_ORDER: tuple[str, ...] = (
    "web_read",
    "retrieval",
    "llm_assist",
    "exec_like",
)


@dataclass(frozen=True)
class ToolPolicyEvaluation:
    trust_class: str
    scope: str | None
    declared_tools: list[str]
    denied_tools: list[str]
    denied_families: list[str]
    denied_reason: str | None
    permitted_tools: list[str]
    declared_families: list[str]
    allowed_families: list[str]
    permitted_families: list[str]


@dataclass(frozen=True)
class RequestPolicyEvaluation:
    trust_class: str
    request_class: str
    budget_class: str
    request_semantic_reason: str
    request_constraints_applied: list[str]
    budget_source: str | None
    declared_budget: dict[str, int] | None
    policy_budget: dict[str, int] | None
    permitted_budget: dict[str, int] | None
    denied_reason: str | None
    was_clamped: bool


@dataclass(frozen=True)
class EconomicPolicyEvaluation:
    trust_class: str
    request_class: str
    slot_class: str
    cost_class: str
    reservation_required: bool
    economic_policy_reason: str


@dataclass(frozen=True)
class IdentityEvaluation:
    actor_id: str | None
    trust_class: str
    identity_issuer: str | None
    identity_verified: bool


def _assert_governance_input(authoritative: Mapping[str, Any]) -> None:
    """I-GOV-INPUT-1: Assert governance input contains only I_L keys."""
    unexpected = set(authoritative.keys()) - _GOVERNANCE_ALLOWED_KEYS
    if unexpected:
        raise GovernanceInputViolation(
            f"I-GOV-INPUT-1: observational keys in governance input: {sorted(unexpected)}"
        )


# ── SSE helpers ──────────────────────────────────────────────────────


def _parse_lane_filter(lanes: str | None) -> set[str] | None:
    """Parse comma-separated lane string into a filter set."""
    if not lanes:
        return None
    result = {lane.strip() for lane in lanes.split(",") if lane.strip()}
    return result or None


def _sse_poll_interval_s() -> float:
    raw = os.getenv("DBL_GATEWAY_SSE_POLL_INTERVAL_S", "").strip()
    if raw:
        try:
            value = float(raw)
            if value >= 0.01:
                return value
        except ValueError:
            pass
    return 0.1


def _should_log_request(path: str, method: str) -> bool:
    verbose_ui = os.getenv("DBL_GATEWAY_LOG_UI_POLLING", "").strip().lower()
    if verbose_ui in {"1", "true", "yes"}:
        return True
    if method.upper() != "GET":
        return True
    return path not in {
        "/ui/capabilities",
        "/ui/demo/status",
        "/ui/snapshot",
    }


async def _sse_event_stream(
    store: Any,
    stream_id: str | None,
    since: int,
    lane_filter: set[str] | None,
    is_disconnected: Callable[[], Any],
) -> AsyncGenerator[str, None]:
    """Shared SSE generator for /tail and /ui/tail."""
    cursor = max(since + 1, 0)
    while True:
        if await is_disconnected():
            break
        snap = store.snapshot(
            limit=2000,
            offset=cursor,
            stream_id=stream_id,
        )
        events = snap.get("events", [])
        if not events:
            await asyncio.sleep(_sse_poll_interval_s())
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
                yield f"id: {event_id}\nevent: envelope\ndata: {data}\n\n"
            else:
                yield f"event: envelope\ndata: {data}\n\n"
        if max_index >= cursor:
            cursor = max_index + 1


def _sse_response(generator: AsyncGenerator[str, None]) -> StreamingResponse:
    """Wrap an SSE generator in a StreamingResponse with correct headers."""
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


_POLICY_DESCRIBE_STRUCTURAL_KEYS: frozenset[str] = frozenset({
    "describe_version",
    "type",
    "label",
    "root",
    "gates",
    "inner",
})


def _policy_structure_payload(policy_obj: object | None) -> dict[str, Any]:
    if policy_obj is None:
        return {
            "available": False,
            "detail": "No policy loaded.",
        }
    describe = getattr(policy_obj, "describe", None)
    if not callable(describe):
        policy_module = type(policy_obj).__module__
        policy_class = type(policy_obj).__name__
        policy_id = _policy_identity_value(getattr(policy_obj, "policy_id", None))
        policy_version = _policy_identity_value(getattr(policy_obj, "policy_version", None))
        opaque_description = {
            "type": "opaque_policy",
            "label": policy_id or policy_class,
            "policy_module": policy_module,
            "policy_class": policy_class,
            "policy_id": policy_id,
            "policy_version": policy_version,
        }
        digest = hashlib.sha256(
            json.dumps(opaque_description, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        return {
            "available": True,
            "source": "opaque",
            "policy_id": policy_id,
            "policy_version": policy_version,
            "digest": digest,
            "tree": _policy_tree_node(opaque_description, path="root"),
            "detail": "Current policy does not expose describe(); showing opaque metadata only.",
        }
    try:
        description = describe()
    except Exception as exc:
        return {
            "available": False,
            "detail": f"Policy describe() failed: {exc}",
        }
    if not isinstance(description, Mapping):
        return {
            "available": False,
            "detail": "Policy describe() must return a mapping.",
        }
    digest = hashlib.sha256(
        json.dumps(description, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {
        "available": True,
        "source": "describe",
        "policy_id": _policy_identity_value(getattr(policy_obj, "policy_id", None)) or _mapping_str(description.get("policy_id")),
        "policy_version": _policy_identity_value(getattr(policy_obj, "policy_version", None)) or _mapping_str(description.get("policy_version")),
        "digest": digest,
        "tree": _policy_tree_node(dict(description), path="root"),
    }


def _policy_identity_value(value: object) -> str | None:
    if value is None:
        return None
    nested = getattr(value, "value", None)
    if nested is not None:
        return str(nested)
    return str(value)


def _mapping_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _policy_tree_node(description: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    return {
        "path": path,
        "kind": description["type"],
        "label": description.get("label"),
        "meta": {
            key: value
            for key, value in description.items()
            if key not in _POLICY_DESCRIBE_STRUCTURAL_KEYS
        },
        "children": _policy_tree_children(description, path=path),
    }


def _policy_tree_children(description: Mapping[str, Any], *, path: str) -> list[dict[str, Any]]:
    kind = description["type"]
    if kind == "root_policy":
        return [_policy_tree_node(description["root"], path=f"{path}.root")]
    if kind in {"chain", "any_of"}:
        return [
            _policy_tree_node(child, path=f"{path}.gates[{index}]")
            for index, child in enumerate(description["gates"])
        ]
    if kind == "invert":
        return [_policy_tree_node(description["inner"], path=f"{path}.inner")]
    return []


def _configure_logging() -> None:
    if _LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(logging.INFO)


def create_app(*, start_workers: bool = True) -> FastAPI:
    _maybe_activate_demo_mode()
    reset_boundary_config_cache()
    boundary_cfg = get_boundary_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _configure_logging()
        _audit_env()
        policy = _load_policy_with_fallback()
        if policy is None:
            policy = ObserverPolicy()  # type: ignore
        store = create_store()
        work_queue = asyncio.Queue(maxsize=_work_queue_max()) if start_workers else None
        app.state.store = store
        app.state.policy = DblPolicyAdapter(policy=policy)
        app.state.execution = KlExecutionAdapter()
        app.state.work_queue = work_queue
        app.state.worker_tasks: list[asyncio.Task] = []
        app.state.demo_agent = _new_demo_state()
        app.state.boundary_config = boundary_cfg
        app.state.start_time = time.monotonic()
        if start_workers and work_queue is not None:
            worker = asyncio.create_task(_work_queue_loop(app, work_queue))
            app.state.worker_tasks.append(worker)
        try:
            yield
        finally:
            demo_task = getattr(app.state, "demo_agent", {}).get("task")
            if demo_task is not None:
                demo_task.cancel()
                try:
                    await demo_task
                except asyncio.CancelledError:
                    pass
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
        denied = surface_access_payload(request.url.path, boundary_config=boundary_cfg)
        if denied is None:
            response = await call_next(request)
        else:
            status_code = int(denied["status_code"])
            response = JSONResponse(
                {
                    "detail": denied["detail"],
                    "surface_id": denied["surface_id"],
                    "exposure_mode": denied["exposure_mode"],
                    "required_exposure_mode": denied["required_exposure_mode"],
                },
                status_code=status_code,
            )
        response.headers["x-request-id"] = request_id
        latency_ms = int((time.monotonic() - start) * 1000)
        if _should_log_request(request.url.path, request.method):
            _LOGGER.info(
                '{"message":"request.completed","request_id":"%s","method":"%s","path":"%s","status_code":%d,"latency_ms":%d}',
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                latency_ms,
            )
        return response

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/ui/", status_code=302)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/capabilities", response_model=CapabilitiesResponse)
    async def capabilities(request: Request) -> dict[str, object]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        return await run_in_threadpool(
            get_capabilities_cached,
            boundary_cfg,
            trust_class=trust_class_for_actor(actor),
        )

    @app.get("/surfaces")
    async def surfaces(request: Request) -> dict[str, object]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        caps = await run_in_threadpool(
            get_capabilities_cached,
            boundary_cfg,
            trust_class=trust_class_for_actor(actor),
        )
        return {
            "gateway_version": caps.get("gateway_version"),
            "interface_version": caps.get("interface_version"),
            "surfaces": get_surface_catalog(boundary_cfg),
        }

    @app.get("/intent-template")
    async def intent_template(
        request: Request,
        intent_type: str = Query("chat.message"),
        example: str = Query("minimal"),
    ) -> dict[str, object]:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.snapshot.read"])
        return _intent_template_payload(
            intent_type=intent_type,
            example=example,
            boundary_config=boundary_cfg,
        )

    @app.post("/ingress/intent", response_model=dict[str, object])
    async def ingress_intent(request: Request, body: dict[str, Any] = Body(...)) -> JSONResponse:
        actor = await _require_actor(request)
        _require_role(actor, ["gateway.intent.write"])
        try:
            envelope = parse_intent_envelope(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        trace_id = uuid.uuid4().hex
        return await _ingest_envelope(app, envelope, trace_id, actor=actor)

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

        lane_filter = _parse_lane_filter(lanes)
        norm_stream = _normalize_optional_str(stream_id, "stream_id") if stream_id else None

        return _sse_response(
            _sse_event_stream(app.state.store, norm_stream, since, lane_filter, request.is_disconnected),
        )

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

    # ── Observer UI ──────────────────────────────────────────────────
    @app.get("/ui/tail", include_in_schema=False)
    async def ui_tail(
        request: Request,
        stream_id: str = Query("default"),
        since: int = Query(-1, ge=-1),
        lanes: str | None = Query(None),
    ) -> StreamingResponse:
        """SSE proxy for observer UI — read-only, no auth required."""
        lane_filter = _parse_lane_filter(lanes)
        norm_stream = _normalize_optional_str(stream_id, "stream_id") if stream_id else None
        return _sse_response(
            _sse_event_stream(app.state.store, norm_stream, since, lane_filter, request.is_disconnected),
        )

    @app.get("/ui/capabilities", include_in_schema=False)
    async def ui_capabilities() -> JSONResponse:
        """Capabilities proxy for observer UI — no auth."""
        data = get_capabilities_cached(boundary_cfg, trust_class="internal")
        return JSONResponse(data, headers={"Cache-Control": "max-age=30"})

    @app.get("/ui/snapshot", include_in_schema=False)
    async def ui_snapshot(
        stream_id: str = Query("default"),
        limit: int = Query(1, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> dict[str, object]:
        """Snapshot proxy for observer UI — no auth."""
        return app.state.store.snapshot(limit=limit, offset=offset, stream_id=stream_id)

    @app.get("/ui/policy-structure", include_in_schema=False)
    async def ui_policy_structure() -> JSONResponse:
        """Policy structure proxy for observer UI — no auth."""
        policy_obj = getattr(app.state.policy, "policy", None)
        return JSONResponse(
            _policy_structure_payload(policy_obj),
            headers={"Cache-Control": "max-age=30"},
        )

    @app.post("/ui/intent", include_in_schema=False)
    async def ui_intent(body: dict[str, Any] = Body(...)) -> JSONResponse:
        """Intent ingest proxy for the observer UI — no auth."""
        try:
            envelope = parse_intent_envelope(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return await _ingest_envelope(app, envelope, uuid.uuid4().hex, trust_class="internal")

    @app.get("/ui/verify-chain", include_in_schema=False)
    async def ui_verify_chain(
        stream_id: str = Query("default"),
    ) -> dict[str, object]:
        """Recompute v_digest from all events and compare to rolling digest."""
        store = app.state.store
        snap = store.snapshot(limit=1, offset=0, stream_id=stream_id)
        rolling = snap.get("v_digest", "")
        event_count = snap.get("length", 0)
        recomputed = store.recompute_v_digest()
        return {
            "rolling_digest": rolling,
            "recomputed_digest": recomputed,
            "match": rolling == recomputed,
            "event_count": event_count,
            "warning": "large event store" if event_count > 10000 else None,
        }

    @app.get("/ui/replay", include_in_schema=False)
    async def ui_replay(
        thread_id: str = Query(...),
        turn_id: str = Query(...),
    ) -> JSONResponse:
        """Replay a decision for a specific turn — no auth."""
        from .replay import DecisionReplayError, replay_decision_for_turn

        store = app.state.store
        try:
            result = replay_decision_for_turn(
                store,
                thread_id=thread_id,
                turn_id=turn_id,
                policy=app.state.policy,
            )
            return JSONResponse({
                "match": result.recomputed_decision_digest == result.stored_decision_digest,
                "recomputed_digest": result.recomputed_decision_digest,
                "stored_digest": result.stored_decision_digest,
                "assembly_digest": result.assembly_digest,
                "context_digest": result.context_digest,
                "decision_index": result.decision_event.get("index"),
                "intent_index": result.intent_event.get("index"),
            })
        except DecisionReplayError as exc:
            return JSONResponse(
                {"error": exc.reason, "detail": exc.detail},
                status_code=422,
            )

    @app.get("/ui/demo/status", include_in_schema=False)
    async def ui_demo_status() -> JSONResponse:
        """Status proxy for the integrated demo agent — no auth."""
        return JSONResponse(await _demo_status_payload(app))

    @app.post("/ui/demo/start", include_in_schema=False)
    async def ui_demo_start() -> JSONResponse:
        """Start the integrated demo scenario — no auth."""
        demo = app.state.demo_agent
        if demo.get("running"):
            return JSONResponse(await _demo_status_payload(app), status_code=409)

        capabilities = get_capabilities_cached(boundary_cfg, trust_class="internal")
        active = active_provider_model(capabilities)
        if active is None:
            return JSONResponse(
                {
                    **await _demo_status_payload(app),
                    "error": "demo.provider_unavailable",
                    "detail": "No active provider/model found in GET /capabilities",
                },
                status_code=422,
            )

        demo["running"] = True
        demo["completed_at"] = None
        demo["last_error"] = None
        demo["logs"] = []
        task = asyncio.create_task(_run_demo_agent(app))
        demo["task"] = task
        return JSONResponse(await _demo_status_payload(app), status_code=202)

    _static_dir = Path(__file__).parent / "static"
    if _static_dir.is_dir():
        from starlette.staticfiles import StaticFiles

        app.mount("/ui", StaticFiles(directory=str(_static_dir), html=True), name="observer-ui")

    return app


async def _process_intent(
    app: FastAPI,
    intent_event: EventRecord,
    correlation_id: str,
    trace_id: str,
) -> None:
    thread_id, turn_id, parent_turn_id = _anchors_for_event(intent_event)
    intent_index: int | None = intent_event.get("index")
    decision_emitted = False
    assembly_digest: str | None = None
    context_digest: str | None = None
    context_config_digest: str | None = None  # NEW: Config digest for DECISION
    boundary_context: dict[str, Any] | None = None
    context_transforms: list[dict[str, Any]] = []
    context_spec: Mapping[str, Any] | None = None
    assembled_context: Mapping[str, Any] | None = None
    try:
        authoritative = _authoritative_from_event(intent_event, correlation_id)
        identity_evaluation = _identity_evaluation(authoritative)

        if context_resolution_enabled():
            # Fetch thread events for ref resolution
            thread_events = app.state.store.timeline(thread_id=thread_id)

            try:
                context_artifacts = await run_in_threadpool(
                    build_context_with_refs,
                    authoritative.get("payload"),
                    intent_type=str(authoritative.get("intent_type") or ""),
                    thread_events=thread_events,
                )
                assembly_digest = context_artifacts.context_digest
                context_config_digest = context_artifacts.config_digest
                context_transforms = list(context_artifacts.transforms)
                context_spec = context_artifacts.context_spec
                assembled_context = context_artifacts.assembled_context
                boundary_context = {
                    "context_digest": assembly_digest,
                    "context_spec": context_spec,
                    "assembled_context": assembled_context,
                    "admitted_model_messages": assembled_context.get("model_messages", []),
                    "meta": context_artifacts.boundary_meta,
                }
            except RefResolutionError as exc:
                _LOGGER.info("context resolution denied: %s", exc)
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
                        DecisionResult(
                            decision="DENY",
                            reason_codes=[exc.code],
                            actor_id=identity_evaluation.actor_id,
                            trust_class=identity_evaluation.trust_class,
                            identity_issuer=identity_evaluation.identity_issuer,
                            identity_verified=identity_evaluation.identity_verified,
                        ),
                        trace_id,
                        assembly_digest=None,
                        context_digest=None,
                        error_ref=None,
                        context_config_digest=None,
                        boundary=None,
                        requested_model_id=None,
                        resolved_model_id=None,
                        provider=None,
                        transforms=[],
                        context_spec=None,
                        assembled_context=None,
                        intent_index=intent_index,
                    ),
                )
                return
            except Exception as exc:
                _LOGGER.exception("context assembly failed: %s", exc)
                error_ref = _emit_policy_error_artifact(
                    app,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    parent_turn_id=parent_turn_id,
                    lane=authoritative["lane"],
                    actor="gateway",
                    intent_type=authoritative["intent_type"],
                    stream_id=authoritative["stream_id"],
                    correlation_id=correlation_id,
                    trace_id=trace_id,
                    stage="assembly",
                    error=exc,
                    stacktrace=traceback.format_exc(),
                    partial_inputs={
                        "thread_id": thread_id,
                        "turn_id": turn_id,
                        "correlation_id": correlation_id,
                    },
                )
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
                        DecisionResult(
                            decision="DENY",
                            reason_codes=["evaluation_error"],
                            actor_id=identity_evaluation.actor_id,
                            trust_class=identity_evaluation.trust_class,
                            identity_issuer=identity_evaluation.identity_issuer,
                            identity_verified=identity_evaluation.identity_verified,
                        ),
                        trace_id,
                        assembly_digest=None,
                        context_digest=None,
                        error_ref=error_ref,
                        context_config_digest=None,
                        boundary=None,
                        requested_model_id=None,
                        resolved_model_id=None,
                        provider=None,
                        transforms=[],
                        context_spec=None,
                        assembled_context=None,
                        intent_index=intent_index,
                    ),
                )
                return
        else:
            # Context resolution OFF: sentinel mode
            # declared_refs already stored in INTENT event payload (audit trail preserved)
            assembly_digest = None
            context_config_digest = "CONTEXT_RESOLUTION_DISABLED"
            context_transforms = []
            context_spec = None
            assembled_context = None
            boundary_context = None

        # --- Tool gating and budget computation (after context, before policy) ---
        auth_payload = authoritative.get("payload") or {}
        _declared_tools = auth_payload.get("declared_tools")
        _tool_scope = auth_payload.get("tool_scope")
        _trust_class = _tool_policy_trust_class(authoritative)
        tool_policy_evaluation = _compute_tool_policy_evaluation(
            _declared_tools if isinstance(_declared_tools, list) else None,
            _tool_scope if isinstance(_tool_scope, str) else None,
            boundary_config=app.state.boundary_config,
            trust_class=_trust_class,
        )
        request_policy_evaluation = _compute_request_policy_evaluation(
            authoritative,
            trust_class=_trust_class,
            boundary_config=app.state.boundary_config,
        )
        economic_policy_evaluation = _compute_economic_policy_evaluation(
            request_class=request_policy_evaluation.request_class,
            trust_class=_trust_class,
            boundary_config=app.state.boundary_config,
        )
        authoritative_for_policy = _authoritative_with_gateway_tool_policy(
            authoritative,
            tool_policy_evaluation,
        )
        authoritative_for_policy = _authoritative_with_gateway_request_policy(
            authoritative_for_policy,
            request_policy_evaluation,
        )
        authoritative_for_policy = _authoritative_with_gateway_economic_policy(
            authoritative_for_policy,
            economic_policy_evaluation,
        )
        identity_evaluation = _identity_evaluation(authoritative_for_policy)

        _assert_governance_input(authoritative_for_policy)
        try:
            decision = app.state.policy.decide(authoritative_for_policy)
        except Exception as exc:
            _LOGGER.exception("policy decision failed: %s", exc)
            error_ref = _emit_policy_error_artifact(
                app,
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
                lane=authoritative["lane"],
                actor="gateway",
                intent_type=authoritative["intent_type"],
                stream_id=authoritative["stream_id"],
                correlation_id=correlation_id,
                trace_id=trace_id,
                stage="policy",
                error=exc,
                stacktrace=traceback.format_exc(),
                partial_inputs={
                    "thread_id": thread_id,
                    "turn_id": turn_id,
                    "correlation_id": correlation_id,
                },
            )
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
                    DecisionResult(
                        decision="DENY",
                        reason_codes=["evaluation_error"],
                        actor_id=identity_evaluation.actor_id,
                        trust_class=identity_evaluation.trust_class,
                        identity_issuer=identity_evaluation.identity_issuer,
                        identity_verified=identity_evaluation.identity_verified,
                    ),
                    trace_id,
                    assembly_digest=assembly_digest,
                    context_digest=None,
                    error_ref=error_ref,
                    context_config_digest=context_config_digest,
                    boundary=boundary_context,
                    requested_model_id=None,
                    resolved_model_id=None,
                    provider=None,
                    transforms=context_transforms,
                    context_spec=context_spec,
                    assembled_context=assembled_context,
                    intent_index=intent_index,
                ),
            )
            return

        # Compute policy config digest from policy rules (gateway owns this)
        _policy_config_digest: str | None = None
        try:
            policy_obj = getattr(app.state.policy, "policy", None)
            config_val = getattr(policy_obj, "config", None) if policy_obj else None
            if config_val is not None:
                _policy_config_digest = f"sha256:{__import__('hashlib').sha256(canonical_json_bytes(config_val)).hexdigest()}"
        except Exception:
            _LOGGER.debug("policy config digest computation skipped")

        # Carry policy_config_digest into DecisionResult
        if _policy_config_digest and decision.policy_config_digest is None:
            decision = DecisionResult(
                decision=decision.decision,
                reason_codes=decision.reason_codes,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                gate_event=decision.gate_event,
                actor_id=decision.actor_id,
                trust_class=decision.trust_class,
                identity_issuer=decision.identity_issuer,
                identity_verified=decision.identity_verified,
                request_class=decision.request_class,
                budget_class=decision.budget_class,
                request_semantic_reason=decision.request_semantic_reason,
                request_constraints_applied=decision.request_constraints_applied,
                budget_policy_reason=decision.budget_policy_reason,
                slot_class=decision.slot_class,
                cost_class=decision.cost_class,
                reservation_required=decision.reservation_required,
                economic_policy_reason=decision.economic_policy_reason,
                declared_tool_families=decision.declared_tool_families,
                allowed_tool_families=decision.allowed_tool_families,
                permitted_tool_families=decision.permitted_tool_families,
                denied_tool_families=decision.denied_tool_families,
                permitted_tools=decision.permitted_tools,
                tool_scope_enforced=decision.tool_scope_enforced,
                tools_denied=decision.tools_denied,
                tools_denied_reason=decision.tools_denied_reason,
                enforced_budget=decision.enforced_budget,
                policy_config_digest=_policy_config_digest,
            )

        decision = DecisionResult(
            decision=decision.decision,
            reason_codes=decision.reason_codes,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            gate_event=decision.gate_event,
            actor_id=identity_evaluation.actor_id,
            trust_class=identity_evaluation.trust_class,
            identity_issuer=identity_evaluation.identity_issuer,
            identity_verified=identity_evaluation.identity_verified,
            request_class=decision.request_class,
            budget_class=decision.budget_class,
            request_semantic_reason=decision.request_semantic_reason,
            request_constraints_applied=decision.request_constraints_applied,
            budget_policy_reason=decision.budget_policy_reason,
            slot_class=economic_policy_evaluation.slot_class,
            cost_class=economic_policy_evaluation.cost_class,
            reservation_required=economic_policy_evaluation.reservation_required,
            economic_policy_reason=economic_policy_evaluation.economic_policy_reason,
            declared_tool_families=list(tool_policy_evaluation.declared_families),
            allowed_tool_families=list(tool_policy_evaluation.allowed_families),
            permitted_tool_families=list(tool_policy_evaluation.permitted_families),
            denied_tool_families=list(tool_policy_evaluation.denied_families),
            permitted_tools=decision.permitted_tools,
            tool_scope_enforced=decision.tool_scope_enforced,
            tools_denied=decision.tools_denied,
            tools_denied_reason=decision.tools_denied_reason,
            enforced_budget=decision.enforced_budget,
            policy_config_digest=decision.policy_config_digest,
        )

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

        # Compute tool gating and budget constraints after policy ALLOW
        if decision.decision == "ALLOW" and request_policy_evaluation.denied_reason is not None:
            decision = DecisionResult(
                decision="DENY",
                reason_codes=[request_policy_evaluation.denied_reason],
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                gate_event=decision.gate_event,
                actor_id=identity_evaluation.actor_id,
                trust_class=identity_evaluation.trust_class,
                identity_issuer=identity_evaluation.identity_issuer,
                identity_verified=identity_evaluation.identity_verified,
                request_class=request_policy_evaluation.request_class,
                budget_class=request_policy_evaluation.budget_class,
                request_semantic_reason=request_policy_evaluation.request_semantic_reason,
                request_constraints_applied=list(request_policy_evaluation.request_constraints_applied),
                budget_policy_reason=request_policy_evaluation.denied_reason,
                slot_class=economic_policy_evaluation.slot_class,
                cost_class=economic_policy_evaluation.cost_class,
                reservation_required=economic_policy_evaluation.reservation_required,
                economic_policy_reason=economic_policy_evaluation.economic_policy_reason,
                declared_tool_families=decision.declared_tool_families,
                allowed_tool_families=decision.allowed_tool_families,
                permitted_tool_families=decision.permitted_tool_families,
                denied_tool_families=decision.denied_tool_families,
                permitted_tools=None,
                tool_scope_enforced=decision.tool_scope_enforced,
                tools_denied=decision.tools_denied,
                tools_denied_reason=decision.tools_denied_reason,
                enforced_budget=None,
                policy_config_digest=decision.policy_config_digest,
            )
        elif decision.decision == "ALLOW":
            runtime_cfg = get_job_runtime_config()
            enforced_budget, runtime_constraints = _compute_enforced_budget(
                request_policy_evaluation.permitted_budget,
                runtime_cfg.llm_wall_clock_s,
                budget_source=request_policy_evaluation.budget_source,
            )
            request_constraints_applied = [
                *request_policy_evaluation.request_constraints_applied,
                *runtime_constraints,
            ]
            decision = DecisionResult(
                decision=decision.decision,
                reason_codes=decision.reason_codes,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                gate_event=decision.gate_event,
                actor_id=identity_evaluation.actor_id,
                trust_class=identity_evaluation.trust_class,
                identity_issuer=identity_evaluation.identity_issuer,
                identity_verified=identity_evaluation.identity_verified,
                request_class=request_policy_evaluation.request_class,
                budget_class=request_policy_evaluation.budget_class,
                request_semantic_reason=request_policy_evaluation.request_semantic_reason,
                request_constraints_applied=request_constraints_applied,
                budget_policy_reason=request_policy_evaluation.denied_reason,
                slot_class=economic_policy_evaluation.slot_class,
                cost_class=economic_policy_evaluation.cost_class,
                reservation_required=economic_policy_evaluation.reservation_required,
                economic_policy_reason=economic_policy_evaluation.economic_policy_reason,
                declared_tool_families=decision.declared_tool_families,
                allowed_tool_families=decision.allowed_tool_families,
                permitted_tool_families=decision.permitted_tool_families,
                denied_tool_families=decision.denied_tool_families,
                permitted_tools=list(tool_policy_evaluation.permitted_tools),
                tool_scope_enforced=tool_policy_evaluation.scope,
                tools_denied=list(tool_policy_evaluation.denied_tools),
                tools_denied_reason=tool_policy_evaluation.denied_reason,
                enforced_budget=enforced_budget,
                policy_config_digest=decision.policy_config_digest,
            )
        else:
            decision = DecisionResult(
                decision=decision.decision,
                reason_codes=decision.reason_codes,
                policy_id=decision.policy_id,
                policy_version=decision.policy_version,
                gate_event=decision.gate_event,
                actor_id=identity_evaluation.actor_id,
                trust_class=identity_evaluation.trust_class,
                identity_issuer=identity_evaluation.identity_issuer,
                identity_verified=identity_evaluation.identity_verified,
                request_class=request_policy_evaluation.request_class,
                budget_class=request_policy_evaluation.budget_class,
                request_semantic_reason=request_policy_evaluation.request_semantic_reason,
                request_constraints_applied=list(request_policy_evaluation.request_constraints_applied),
                budget_policy_reason=request_policy_evaluation.denied_reason,
                slot_class=economic_policy_evaluation.slot_class,
                cost_class=economic_policy_evaluation.cost_class,
                reservation_required=economic_policy_evaluation.reservation_required,
                economic_policy_reason=economic_policy_evaluation.economic_policy_reason,
                declared_tool_families=decision.declared_tool_families,
                allowed_tool_families=decision.allowed_tool_families,
                permitted_tool_families=decision.permitted_tool_families,
                denied_tool_families=decision.denied_tool_families,
                permitted_tools=decision.permitted_tools,
                tool_scope_enforced=decision.tool_scope_enforced,
                tools_denied=decision.tools_denied,
                tools_denied_reason=decision.tools_denied_reason,
                enforced_budget=decision.enforced_budget,
                policy_config_digest=decision.policy_config_digest,
            )

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
                assembly_digest=assembly_digest,
                context_digest=assembly_digest if decision.decision == "ALLOW" else None,
                context_config_digest=context_config_digest,
                boundary=boundary_context,
                resolution_reason=resolution_reason,
                transforms=context_transforms,
                context_spec=context_spec,
                assembled_context=assembled_context,
                intent_index=intent_index,
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
                task_input = None
                if isinstance(context_spec, Mapping):
                    intent = context_spec.get("intent")
                    if isinstance(intent, Mapping):
                        value = intent.get("user_input")
                        if isinstance(value, str):
                            task_input = value
                render_result = render_provider_payload(
                    assembled_context=assembled_context,
                    task=task_input,
                    spec="render.delta_v1",
                )
                model_messages = render_result.provider_payload.get("messages")
            else:
                render_result = None
            
            # Compute effective wall clock from budget
            effective_wall_clock_s: int | None = None
            if decision.enforced_budget and decision.enforced_budget.get("max_duration_ms"):
                effective_wall_clock_s = decision.enforced_budget["max_duration_ms"] // 1000

            # --- Context Release Guard: PROOF event before execution ---
            _release_digest: str | None = None
            if _release_guard_enabled():
                release_obj: dict[str, Any] = {
                    "messages": model_messages or [],
                    "model_id": resolved_model or "",
                    "provider": provider or "",
                }
                if decision.permitted_tools is not None:
                    release_obj["permitted_tools"] = sorted(decision.permitted_tools)
                if decision.enforced_budget:
                    release_obj["enforced_budget"] = decision.enforced_budget
                _release_digest = compute_release_digest(release_obj)
                app.state.store.append(
                    kind="PROOF",
                    thread_id=thread_id,
                    turn_id=turn_id,
                    parent_turn_id=parent_turn_id,
                    lane=authoritative["lane"],
                    actor="gateway",
                    intent_type=authoritative["intent_type"],
                    stream_id=authoritative["stream_id"],
                    correlation_id=correlation_id,
                    payload={
                        "proof_type": "context_release_guard",
                        "payload_digest": _release_digest,
                        "model_id": resolved_model or "",
                        "provider": provider or "",
                        "message_count": len(model_messages or []),
                        "_obs": {"trace_id": trace_id},
                    },
                )

            result = await app.state.execution.run(
                intent_event,
                model_messages=model_messages,
                permitted_tools=decision.permitted_tools,
                tool_scope_enforced=decision.tool_scope_enforced,
                enforced_budget=decision.enforced_budget,
                llm_wall_clock_s=effective_wall_clock_s,
            )
            if render_result is not None:
                result = ExecutionResult(
                    output_text=result.output_text,
                    provider=result.provider,
                    model_id=result.model_id,
                    trace=result.trace,
                    trace_digest=result.trace_digest,
                    error=result.error,
                    render_digest=render_result.render_digest,
                    render_manifest=render_result.render_manifest,
                    tool_calls=result.tool_calls,
                    tool_blocked=result.tool_blocked,
                    usage=result.usage,
                )
            payload = _execution_payload(
                result,
                trace_id,
                requested_model_id=requested_model or None,
                resolved_model_id=resolved_model or None,
                context_digest=assembly_digest,
                boundary=boundary_context,
                release_digest=_release_digest,
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
            if assembly_digest:
                payload["context_digest"] = assembly_digest
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
        error_ref = _emit_policy_error_artifact(
            app,
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
            lane=intent_event["lane"],
            actor="gateway",
            intent_type=intent_event["intent_type"],
            stream_id=intent_event["stream_id"],
            correlation_id=correlation_id,
            trace_id=trace_id,
            stage="processing",
            error=exc,
            stacktrace=traceback.format_exc(),
            partial_inputs={
                "thread_id": thread_id,
                "turn_id": turn_id,
                "correlation_id": correlation_id,
            },
        )
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
                assembly_digest=assembly_digest,
                context_digest=None,
                error_ref=error_ref,
                context_config_digest=context_config_digest,
                boundary=boundary_context,
                requested_model_id=None,
                resolved_model_id=None,
                provider=None,
                transforms=context_transforms,
                context_spec=context_spec,
                assembled_context=assembled_context,
                intent_index=intent_index,
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
    assembly_digest: str | None = None,
    context_digest: str | None = None,
    context_config_digest: str | None = None,  # NEW: Config digest for replay
    boundary: Mapping[str, Any] | None = None,
    transforms: Sequence[Mapping[str, Any]] | None = None,
    context_spec: Mapping[str, Any] | None = None,
    assembled_context: Mapping[str, Any] | None = None,
    error_ref: str | None = None,
    intent_index: int | None = None,
) -> dict[str, Any]:
    normative = build_normative_decision(
        decision,
        assembly_digest=assembly_digest,
        context_digest=context_digest,
        transforms=transforms,
        intent_index=intent_index,
    )
    payload: dict[str, Any] = {
        "decision": decision.decision,
        "reason_codes": decision.reason_codes or [],
        "policy_id": normative["policy"]["policy_id"],
        "policy_version": normative["policy"]["policy_version"],
        **normative,
    }
    if decision.tool_scope_enforced is not None:
        payload["tool_scope_enforced"] = decision.tool_scope_enforced
    if decision.tools_denied is not None:
        payload["tools_denied"] = list(decision.tools_denied)
    if decision.tools_denied_reason is not None:
        payload["tools_denied_reason"] = decision.tools_denied_reason
    if error_ref:
        payload["error_ref"] = error_ref
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


def _emit_policy_error_artifact(
    app: FastAPI,
    *,
    thread_id: str,
    turn_id: str,
    parent_turn_id: str | None,
    lane: str,
    actor: str,
    intent_type: str,
    stream_id: str,
    correlation_id: str,
    trace_id: str,
    stage: str,
    error: Exception,
    stacktrace: str | None,
    partial_inputs: Mapping[str, Any] | None,
) -> str:
    artifact_id = f"err-{uuid.uuid4().hex}"
    payload: dict[str, Any] = {
        "artifact_id": artifact_id,
        "name": "policy.evaluation_error.v1.json",
        "trace_id": trace_id,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "stage": stage,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "partial_inputs": dict(partial_inputs or {}),
    }
    if stacktrace:
        payload["stacktrace"] = stacktrace
    app.state.store.append(
        kind="PROOF",
        thread_id=thread_id,
        turn_id=turn_id,
        parent_turn_id=parent_turn_id,
        lane=lane,
        actor=actor,
        intent_type=intent_type,
        stream_id=stream_id,
        correlation_id=correlation_id,
        payload=payload,
    )
    return artifact_id


def _execution_payload(
    result: ExecutionResult,
    trace_id: str,
    *,
    requested_model_id: str | None,
    resolved_model_id: str | None,
    context_digest: str | None = None,
    boundary: Mapping[str, Any] | None = None,
    release_digest: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider": result.provider,
        "model_id": result.model_id,
    }
    if release_digest:
        payload["release_digest"] = release_digest
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
    if result.tool_calls:
        payload["tool_calls"] = result.tool_calls
    if result.tool_blocked:
        payload["tool_blocked"] = result.tool_blocked
    if result.usage:
        payload["usage"] = result.usage

    if result.render_digest or result.render_manifest:
        _attach_obs_trace_id(payload, trace_id)
        obs = payload.get("_obs")
        if isinstance(obs, dict):
            obs["render"] = {
                "render_digest": result.render_digest,
                "render_manifest": result.render_manifest,
            }

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


def _release_guard_enabled() -> bool:
    return os.getenv("GATEWAY_ENABLE_RELEASE_GUARD", "1").strip().lower() not in ("0", "false", "no")


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


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


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
    _LOGGER.info("CONFIG AUDIT")
    summary = _config_audit_summary()
    _LOGGER.info(
        "  policy=%s object=%s boundary=%s context_resolution=%s exec_mode=%s demo_mode=%s auth_mode=%s db=%s",
        summary["policy_module"],
        summary["policy_object"],
        summary["boundary_mode"],
        summary["context_resolution"],
        summary["exec_mode"],
        summary["demo_mode"],
        summary["auth_mode"],
        summary["db"],
    )
    _LOGGER.info("  providers=%s", ", ".join(summary["providers"]) if summary["providers"] else "none")


def _config_audit_summary() -> dict[str, object]:
    provider_signals: list[tuple[str, bool]] = [
        ("openai", bool(os.getenv("OPENAI_API_KEY", "").strip())),
        ("anthropic", bool(os.getenv("ANTHROPIC_API_KEY", "").strip())),
        ("google", bool(os.getenv("GOOGLE_API_KEY", "").strip() or os.getenv("GOOGLE_GENERATIVE_AI_API_KEY", "").strip())),
        ("mistral", bool(os.getenv("MISTRAL_API_KEY", "").strip())),
        ("cohere", bool(os.getenv("COHERE_API_KEY", "").strip())),
        ("ai21", bool(os.getenv("AI21_API_KEY", "").strip())),
        ("xai", bool(os.getenv("XAI_API_KEY", "").strip())),
        ("perplexity", bool(os.getenv("PERPLEXITY_API_KEY", "").strip())),
        ("openrouter", bool(os.getenv("OPENROUTER_API_KEY", "").strip())),
        ("ollama", bool(os.getenv("OLLAMA_HOST", "").strip() or os.getenv("OLLAMA_BASE_URL", "").strip())),
        ("vllm", bool(os.getenv("VLLM_ENDPOINT", "").strip())),
        ("lmstudio", bool(os.getenv("LMSTUDIO_API_KEY", "").strip())),
        ("any", bool(os.getenv("ANY_API_KEY", "").strip())),
    ]
    active_providers = [name for name, enabled in provider_signals if enabled]
    demo_enabled = os.getenv("GATEWAY_DEMO_MODE", "").strip() in ("1", "true", "yes")
    if demo_enabled:
        active_providers.append("stub-demo")
    return {
        "policy_module": "set" if os.getenv("DBL_GATEWAY_POLICY_MODULE", "").strip() else "missing",
        "policy_object": os.getenv("DBL_GATEWAY_POLICY_OBJECT", "").strip() or "POLICY(default)",
        "boundary_mode": get_boundary_config().exposure_mode,
        "context_resolution": "on" if context_resolution_enabled() else "off",
        "exec_mode": _get_exec_mode(),
        "demo_mode": "on" if demo_enabled else "off",
        "auth_mode": os.getenv("DBL_GATEWAY_AUTH_MODE", "dev").strip() or "dev",
        "db": "set" if os.getenv("DBL_GATEWAY_DB", "").strip() else "default",
        "providers": active_providers,
    }


def _maybe_activate_demo_mode() -> None:
    """Register stub provider and set demo defaults when GATEWAY_DEMO_MODE=1."""
    demo = os.getenv("GATEWAY_DEMO_MODE", "").strip()
    if demo not in ("1", "true", "yes"):
        return

    _LOGGER.info("DEMO MODE active")

    # --- Register stub provider ---
    from .providers import PROVIDER_MODULES
    from .providers import stub

    if "stub" not in PROVIDER_MODULES:
        PROVIDER_MODULES["stub"] = stub
        _LOGGER.info("  stub provider registered")

    # --- Default policy to allow_all when none configured ---
    if not os.getenv("DBL_GATEWAY_POLICY_MODULE", "").strip():
        os.environ["DBL_GATEWAY_POLICY_MODULE"] = "dbl_policy.allow_all"
        _LOGGER.info("  policy defaulted to dbl_policy.allow_all")

    # --- Default DB path ---
    if not os.getenv("DBL_GATEWAY_DB", "").strip():
        os.environ["DBL_GATEWAY_DB"] = "data/demo-trail.sqlite"
        _LOGGER.info("  DB defaulted to data/demo-trail.sqlite")

    # --- Default inline decision (no work queue needed for demo) ---
    if not os.getenv("DBL_GATEWAY_INLINE_DECISION", "").strip():
        os.environ["DBL_GATEWAY_INLINE_DECISION"] = "1"
        _LOGGER.info("  inline decision enabled")

    # --- Default context resolution for replayable demo turns ---
    if not os.getenv("GATEWAY_ENABLE_CONTEXT_RESOLUTION", "").strip():
        os.environ["GATEWAY_ENABLE_CONTEXT_RESOLUTION"] = "1"
        _LOGGER.info("  context resolution enabled")

    if not os.getenv("DBL_GATEWAY_BOUNDARY_CONFIG", "").strip():
        demo_boundary = Path(__file__).resolve().parents[2] / "config" / "boundary.demo.json"
        os.environ["DBL_GATEWAY_BOUNDARY_CONFIG"] = str(demo_boundary)
        _LOGGER.info("  boundary config: %s", demo_boundary)

    stub_mode = os.getenv("STUB_MODE", "echo")
    _LOGGER.info("  stub mode: %s", stub_mode)
    _LOGGER.info("  -> Open http://localhost:8010/ui/")


def _load_policy_with_fallback() -> object | None:
    import os

    module_var = os.getenv("DBL_GATEWAY_POLICY_MODULE", "").strip()
    if not module_var:
        _LOGGER.warning("⚠️  No policy configured.")
        _LOGGER.warning("Gateway started in READ-ONLY / OBSERVER mode.")
        _LOGGER.warning("Required for execution:\n  DBL_GATEWAY_POLICY_MODULE=<module path>")
        _LOGGER.warning("Example:\n  -e DBL_GATEWAY_POLICY_MODULE=dbl_policy.allow_all")
        return None

    try:
        policy = _load_policy()
        obj_name = os.getenv("DBL_GATEWAY_POLICY_OBJECT", "POLICY").strip() or "POLICY"
        _LOGGER.info("Policy: resolved %s:%s", module_var, obj_name)
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
        # Include declared_refs for context building
        declared_refs = payload.get("declared_refs")
        if isinstance(declared_refs, list) and declared_refs:
            shaped["declared_refs"] = declared_refs
        
        # Include declarative context params
        ctx_mode = payload.get("context_mode")
        if isinstance(ctx_mode, str):
            shaped["context_mode"] = ctx_mode
        ctx_n = payload.get("context_n")
        if isinstance(ctx_n, int):
            shaped["context_n"] = ctx_n
        # Include tool gating fields
        declared_tools = payload.get("declared_tools")
        if isinstance(declared_tools, list):
            shaped["declared_tools"] = declared_tools
        tool_scope = payload.get("tool_scope")
        if isinstance(tool_scope, str):
            shaped["tool_scope"] = tool_scope
        # Include budget
        budget = payload.get("budget")
        if isinstance(budget, Mapping):
            shaped["budget"] = dict(budget)

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
    authoritative = {
        "stream_id": intent_event.get("stream_id"),
        "lane": intent_event.get("lane"),
        "actor": intent_event.get("actor"),
        "intent_type": intent_event.get("intent_type"),
        "correlation_id": correlation_id,
        "payload": payload,
    }
    if isinstance(payload, Mapping):
        inputs = payload.get("inputs")
        if isinstance(inputs, Mapping):
            extensions = inputs.get("extensions")
            if isinstance(extensions, Mapping):
                gateway_auth = extensions.get("gateway_auth")
                if isinstance(gateway_auth, Mapping):
                    tenant_id = gateway_auth.get("tenant_id")
                    if isinstance(tenant_id, str) and tenant_id.strip():
                        authoritative["tenant_id"] = tenant_id.strip()
    return authoritative


def make_trace_bundle(raw_trace: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    trace = sanitize_trace(raw_trace)
    return trace, trace_digest(trace)


def _compute_permitted_tools(
    declared_tools: list[str] | None,
    tool_scope: str | None,
    decision: DecisionResult,
    *,
    boundary_config=None,
    trust_class: str = "anonymous",
) -> tuple[list[str] | None, str | None, list[str] | None, str | None]:
    """Compute tool gating fields for DECISION payload.

    Returns (permitted_tools, tool_scope_enforced, tools_denied, tools_denied_reason).
    For v0.7.0, gateway passes through declared_tools as permitted_tools.
    Policy can override via DecisionResult.permitted_tools in future versions.
    """
    if decision.decision != "ALLOW":
        return None, None, None, None
    if declared_tools is None and tool_scope is None:
        return None, None, None, None
    evaluation = _compute_tool_policy_evaluation(
        declared_tools,
        tool_scope,
        boundary_config=boundary_config,
        trust_class=trust_class,
    )
    return (
        evaluation.permitted_tools,
        evaluation.scope,
        evaluation.denied_tools,
        evaluation.denied_reason,
    )


def _compute_tool_policy_evaluation(
    declared_tools: list[str] | None,
    tool_scope: str | None,
    *,
    boundary_config=None,
    trust_class: str = "anonymous",
) -> ToolPolicyEvaluation:
    cfg = boundary_config or get_boundary_config()
    tools = list(declared_tools or [])
    scope = None if declared_tools is None and tool_scope is None else (tool_scope or "strict")
    allowed_families = list(allowed_tool_families_for_mode(cfg, trust_class=trust_class))
    family_by_tool: dict[str, str | None] = {tool: _tool_family(tool, cfg) for tool in tools}
    unknown_tools = [tool for tool in tools if family_by_tool[tool] is None]
    known_tools = [tool for tool in tools if family_by_tool[tool] is not None]
    no_mix_denied, no_mix_reason = _deny_unsafe_tool_mix(known_tools, cfg)
    tools_after_no_mix = [tool for tool in known_tools if tool not in no_mix_denied]

    allow_all_families = "*" in allowed_families
    allowed_family_set = set(allowed_families)
    family_denied = [
        tool for tool in tools_after_no_mix
        if not allow_all_families and family_by_tool[tool] not in allowed_family_set
    ]

    denied_tools = [tool for tool in tools if tool in unknown_tools or tool in no_mix_denied or tool in family_denied]
    denied_reason = None
    if unknown_tools:
        denied_reason = "tool.unknown_family"
    elif no_mix_reason:
        denied_reason = no_mix_reason
    elif family_denied:
        denied_reason = "tool.family_not_allowed"
    permitted_tools = [tool for tool in tools if tool not in denied_tools]

    return ToolPolicyEvaluation(
        trust_class=trust_class,
        scope=scope,
        declared_tools=tools,
        denied_tools=denied_tools,
        denied_families=_ordered_tool_families(
            ["unknown" if family_by_tool[tool] is None else str(family_by_tool[tool]) for tool in denied_tools]
        ),
        denied_reason=denied_reason,
        permitted_tools=permitted_tools,
        declared_families=_ordered_tool_families(
            family for family in (family_by_tool[tool] for tool in tools) if family is not None
        ),
        allowed_families=_ordered_tool_families(allowed_families),
        permitted_families=_ordered_tool_families(
            family for family in (family_by_tool[tool] for tool in permitted_tools) if family is not None
        ),
    )


def _tool_family(tool_name: str, boundary_config=None) -> str | None:
    cfg = boundary_config or get_boundary_config()
    tool = tool_name.strip().lower()
    for family_name, patterns in cfg.tool_policy.families.items():
        for pattern in patterns:
            if fnmatch.fnmatchcase(tool, pattern.strip().lower()):
                return str(family_name)
    return None


def _deny_unsafe_tool_mix(tools: list[str], boundary_config=None) -> tuple[list[str], str | None]:
    if not tools:
        return [], None
    cfg = boundary_config or get_boundary_config()
    family_by_tool = {tool: _tool_family(tool, cfg) for tool in tools}
    families = set(family_by_tool.values())
    if "exec_like" in families and len(families - {"exec_like"}) > 0:
        denied = [tool for tool in tools if family_by_tool[tool] == "exec_like"]
        return denied, "tool.no_mix.exec_like"
    return [], None


def _ordered_tool_families(families: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    wildcard = False
    for family in families:
        name = str(family).strip()
        if not name or name in seen:
            continue
        if name == "*":
            wildcard = True
            seen.add(name)
            continue
        seen.add(name)
        ordered.append(name)
    rank = {name: idx for idx, name in enumerate(_TOOL_FAMILY_ORDER)}
    ordered.sort(key=lambda item: (rank.get(item, len(rank)), item))
    if wildcard:
        ordered.append("*")
    return ordered


def _authoritative_with_gateway_tool_policy(
    authoritative: Mapping[str, Any],
    evaluation: ToolPolicyEvaluation,
) -> dict[str, Any]:
    payload = authoritative.get("payload")
    if not isinstance(payload, Mapping):
        return dict(authoritative)
    inputs_raw = payload.get("inputs")
    inputs = dict(inputs_raw) if isinstance(inputs_raw, Mapping) else {}
    extensions_raw = inputs.get("extensions")
    extensions = dict(extensions_raw) if isinstance(extensions_raw, Mapping) else {}
    extensions["gateway_tool_policy"] = {
        "trust_class": evaluation.trust_class,
        "declared_tool_families": list(evaluation.declared_families),
        "allowed_tool_families": list(evaluation.allowed_families),
        "permitted_tool_families": list(evaluation.permitted_families),
        "denied_tool_families": list(evaluation.denied_families),
    }
    inputs["extensions"] = extensions
    payload_copy = dict(payload)
    payload_copy["inputs"] = inputs
    authoritative_copy = dict(authoritative)
    authoritative_copy["payload"] = payload_copy
    return authoritative_copy


def _inject_gateway_auth_inputs(
    payload: dict[str, Any],
    *,
    actor: Actor | None,
    trust_class: str,
) -> None:
    inputs_raw = payload.get("inputs")
    inputs = dict(inputs_raw) if isinstance(inputs_raw, Mapping) else {}
    extensions_raw = inputs.get("extensions")
    extensions = dict(extensions_raw) if isinstance(extensions_raw, Mapping) else {}
    extensions["gateway_auth"] = identity_fields_for_actor(actor, trust_class=trust_class)
    inputs["extensions"] = extensions
    payload["inputs"] = inputs


def _tool_policy_trust_class(authoritative: Mapping[str, Any]) -> str:
    return _identity_evaluation(authoritative).trust_class


def _identity_evaluation(authoritative: Mapping[str, Any]) -> IdentityEvaluation:
    payload = authoritative.get("payload")
    if not isinstance(payload, Mapping):
        return IdentityEvaluation(
            actor_id=None,
            trust_class="anonymous",
            identity_issuer=None,
            identity_verified=False,
        )
    inputs = payload.get("inputs")
    if not isinstance(inputs, Mapping):
        return IdentityEvaluation(
            actor_id=None,
            trust_class="anonymous",
            identity_issuer=None,
            identity_verified=False,
        )
    extensions = inputs.get("extensions")
    if not isinstance(extensions, Mapping):
        return IdentityEvaluation(
            actor_id=None,
            trust_class="anonymous",
            identity_issuer=None,
            identity_verified=False,
        )
    gateway_auth = extensions.get("gateway_auth")
    if not isinstance(gateway_auth, Mapping):
        return IdentityEvaluation(
            actor_id=None,
            trust_class="anonymous",
            identity_issuer=None,
            identity_verified=False,
        )
    trust_class = gateway_auth.get("trust_class")
    return IdentityEvaluation(
        actor_id=(
            gateway_auth.get("actor_id").strip()
            if isinstance(gateway_auth.get("actor_id"), str) and gateway_auth.get("actor_id").strip()
            else None
        ),
        trust_class=(
            trust_class.strip()
            if isinstance(trust_class, str) and trust_class.strip()
            else "anonymous"
        ),
        identity_issuer=(
            gateway_auth.get("issuer").strip()
            if isinstance(gateway_auth.get("issuer"), str) and gateway_auth.get("issuer").strip()
            else None
        ),
        identity_verified=bool(gateway_auth.get("verified") is True),
    )


def _request_budget(payload: Mapping[str, Any]) -> dict[str, int] | None:
    budget = payload.get("budget")
    if not isinstance(budget, Mapping):
        return None
    parsed: dict[str, int] = {}
    max_tokens = budget.get("max_tokens")
    if isinstance(max_tokens, int) and max_tokens > 0:
        parsed["max_tokens"] = max_tokens
    max_duration_ms = budget.get("max_duration_ms")
    if isinstance(max_duration_ms, int) and max_duration_ms > 0:
        parsed["max_duration_ms"] = max_duration_ms
    return parsed or None


def _classify_budget(
    budget: dict[str, int] | None,
    *,
    boundary_config=None,
) -> str:
    if not budget:
        return "none"
    cfg = boundary_config or get_boundary_config()
    light_budget = cfg.request_policy.light_budget
    max_tokens = budget.get("max_tokens")
    max_duration_ms = budget.get("max_duration_ms")
    if (
        (max_tokens is None or max_tokens <= light_budget.max_tokens)
        and (max_duration_ms is None or max_duration_ms <= light_budget.max_duration_ms)
    ):
        return "light"
    return "heavy"


def _classify_request(
    authoritative: Mapping[str, Any],
    *,
    boundary_config=None,
) -> tuple[str, str, list[str]]:
    payload = authoritative.get("payload")
    if not isinstance(payload, Mapping):
        return "intent", "request.semantic.intent_only", []
    cfg = boundary_config or get_boundary_config()
    intent_type = str(authoritative.get("intent_type") or payload.get("intent_type") or "")
    if intent_type == "artifact.handle":
        return "probe", "request.semantic.artifact_handle", ["intent_type.artifact_handle"]
    declared_refs = payload.get("declared_refs")
    declared_tools = payload.get("declared_tools")
    budget = _request_budget(payload)
    has_refs = isinstance(declared_refs, list) and len(declared_refs) > 0
    tools = declared_tools if isinstance(declared_tools, list) else []
    tool_count = len(tools)
    tool_families = [family for family in (_tool_family(tool, cfg) for tool in tools) if family is not None]
    if not has_refs and tool_count == 0 and budget is None:
        return "intent", "request.semantic.intent_only", []
    if (
        not has_refs
        and budget is None
        and tool_count > 0
        and tool_count <= 1
        and set(tool_families) <= {"web_read"}
    ):
        return "probe", "request.semantic.read_only_tool_probe", ["tool_family.web_read"]

    constraints: list[str] = []
    if has_refs:
        constraints.append("declared_refs.present")
    if tool_count > 1:
        constraints.append("declared_tools.multiple")
    elif any(family in {"exec_like", "llm_assist"} for family in tool_families):
        constraints.append("declared_tools.high_risk_family")
    budget_class = _classify_budget(budget, boundary_config=cfg)
    if budget_class == "heavy":
        constraints.append("budget.heavy")
    if constraints:
        return "execution_heavy", f"request.semantic.{constraints[0].replace('.', '_')}", constraints
    return "execution_light", "request.semantic.bounded_execution", ["budget.light_or_none"]


def _policy_budget_dict(max_tokens: int, max_duration_ms: int) -> dict[str, int]:
    return {
        "max_tokens": max_tokens,
        "max_duration_ms": max_duration_ms,
    }


def _apply_request_policy_budget(
    declared_budget: dict[str, int] | None,
    *,
    policy_budget: dict[str, int] | None,
) -> tuple[dict[str, int] | None, bool, str | None, list[str]]:
    if policy_budget is None and declared_budget is None:
        return None, False, None, []
    if policy_budget is None:
        return dict(declared_budget or {}), False, "client", []
    permitted_budget = dict(policy_budget)
    was_clamped = False
    constraints: list[str] = []
    budget_source = "boundary_default" if declared_budget is None else "client"
    if declared_budget:
        declared_tokens = declared_budget.get("max_tokens")
        if isinstance(declared_tokens, int) and declared_tokens > 0:
            permitted_budget["max_tokens"] = min(policy_budget["max_tokens"], declared_tokens)
            if permitted_budget["max_tokens"] < declared_tokens:
                was_clamped = True
                budget_source = "boundary_cap"
                constraints.append("boundary_cap.max_tokens")
        declared_duration = declared_budget.get("max_duration_ms")
        if isinstance(declared_duration, int) and declared_duration > 0:
            permitted_budget["max_duration_ms"] = min(policy_budget["max_duration_ms"], declared_duration)
            if permitted_budget["max_duration_ms"] < declared_duration:
                was_clamped = True
                budget_source = "boundary_cap"
                constraints.append("boundary_cap.max_duration_ms")
    else:
        constraints.extend(["boundary_default.max_tokens", "boundary_default.max_duration_ms"])
    return permitted_budget, was_clamped, budget_source, constraints


def _compute_request_policy_evaluation(
    authoritative: Mapping[str, Any],
    *,
    trust_class: str,
    boundary_config=None,
) -> RequestPolicyEvaluation:
    cfg = boundary_config or get_boundary_config()
    payload = authoritative.get("payload")
    payload_map = payload if isinstance(payload, Mapping) else {}
    declared_budget = _request_budget(payload_map)
    request_class, request_semantic_reason, semantic_constraints = _classify_request(
        authoritative,
        boundary_config=cfg,
    )
    budget_class = _classify_budget(declared_budget, boundary_config=cfg)
    rule = request_policy_rule_for_mode(
        cfg,
        request_class=request_class,
        trust_class=trust_class,
    )
    policy_budget = (
        _policy_budget_dict(rule.max_budget.max_tokens, rule.max_budget.max_duration_ms)
        if rule.max_budget is not None
        else None
    )
    if rule.decision == "deny":
        return RequestPolicyEvaluation(
            trust_class=trust_class,
            request_class=request_class,
            budget_class=budget_class,
            request_semantic_reason=request_semantic_reason,
            request_constraints_applied=list(semantic_constraints),
            budget_source="boundary_cap" if policy_budget is not None else None,
            declared_budget=declared_budget,
            policy_budget=policy_budget,
            permitted_budget=None,
            denied_reason=rule.reason_code or "request.not_allowed",
            was_clamped=False,
        )
    permitted_budget, was_clamped, budget_source, budget_constraints = _apply_request_policy_budget(
        declared_budget,
        policy_budget=policy_budget,
    )
    applied_constraints = [*semantic_constraints, *budget_constraints]
    return RequestPolicyEvaluation(
        trust_class=trust_class,
        request_class=request_class,
        budget_class=budget_class,
        request_semantic_reason=request_semantic_reason,
        request_constraints_applied=applied_constraints,
        budget_source=budget_source,
        declared_budget=declared_budget,
        policy_budget=policy_budget,
        permitted_budget=permitted_budget,
        denied_reason="request.budget_clamped" if was_clamped else None,
        was_clamped=was_clamped,
    )


def _authoritative_with_gateway_request_policy(
    authoritative: Mapping[str, Any],
    evaluation: RequestPolicyEvaluation,
) -> dict[str, Any]:
    payload = authoritative.get("payload")
    if not isinstance(payload, Mapping):
        return dict(authoritative)
    inputs_raw = payload.get("inputs")
    inputs = dict(inputs_raw) if isinstance(inputs_raw, Mapping) else {}
    extensions_raw = inputs.get("extensions")
    extensions = dict(extensions_raw) if isinstance(extensions_raw, Mapping) else {}
    extensions["gateway_request_policy"] = {
        "trust_class": evaluation.trust_class,
        "request_class": evaluation.request_class,
        "budget_class": evaluation.budget_class,
        "request_semantic_reason": evaluation.request_semantic_reason,
        "request_constraints_applied": list(evaluation.request_constraints_applied),
        "budget_source": evaluation.budget_source,
        "declared_budget": dict(evaluation.declared_budget) if evaluation.declared_budget else None,
        "policy_budget": dict(evaluation.policy_budget) if evaluation.policy_budget else None,
        "permitted_budget": dict(evaluation.permitted_budget) if evaluation.permitted_budget else None,
        "denied_reason": evaluation.denied_reason,
        "was_clamped": evaluation.was_clamped,
    }
    inputs["extensions"] = extensions
    payload_copy = dict(payload)
    payload_copy["inputs"] = inputs
    authoritative_copy = dict(authoritative)
    authoritative_copy["payload"] = payload_copy
    return authoritative_copy


def _economic_policy_reason(slot_class: str, cost_class: str, reservation_required: bool) -> str:
    reason = f"economic.{slot_class}.{cost_class}"
    if reservation_required:
        reason = f"{reason}.reservation_required"
    return reason


def _compute_economic_policy_evaluation(
    *,
    request_class: str,
    trust_class: str,
    boundary_config=None,
) -> EconomicPolicyEvaluation:
    cfg = boundary_config or get_boundary_config()
    rule = economic_policy_rule_for_mode(
        cfg,
        request_class=request_class,
        trust_class=trust_class,
    )
    return EconomicPolicyEvaluation(
        trust_class=trust_class,
        request_class=request_class,
        slot_class=rule.slot_class,
        cost_class=rule.cost_class,
        reservation_required=rule.reservation_required,
        economic_policy_reason=(
            rule.reason_code
            or _economic_policy_reason(rule.slot_class, rule.cost_class, rule.reservation_required)
        ),
    )


def _authoritative_with_gateway_economic_policy(
    authoritative: Mapping[str, Any],
    evaluation: EconomicPolicyEvaluation,
) -> dict[str, Any]:
    payload = authoritative.get("payload")
    if not isinstance(payload, Mapping):
        return dict(authoritative)
    inputs_raw = payload.get("inputs")
    inputs = dict(inputs_raw) if isinstance(inputs_raw, Mapping) else {}
    extensions_raw = inputs.get("extensions")
    extensions = dict(extensions_raw) if isinstance(extensions_raw, Mapping) else {}
    extensions["gateway_economic_policy"] = {
        "trust_class": evaluation.trust_class,
        "request_class": evaluation.request_class,
        "slot_class": evaluation.slot_class,
        "cost_class": evaluation.cost_class,
        "reservation_required": evaluation.reservation_required,
        "economic_policy_reason": evaluation.economic_policy_reason,
    }
    inputs["extensions"] = extensions
    payload_copy = dict(payload)
    payload_copy["inputs"] = inputs
    authoritative_copy = dict(authoritative)
    authoritative_copy["payload"] = payload_copy
    return authoritative_copy


def _compute_enforced_budget(
    budget: dict[str, int] | None,
    llm_wall_clock_s: int,
    *,
    budget_source: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Compute enforced budget for DECISION payload.

    effective_timeout = min(llm_wall_clock_s * 1000, budget.max_duration_ms).
    max_tokens passes through to provider call only.
    """
    if not budget:
        return None, []
    enforced: dict[str, Any] = {}
    applied_constraints: list[str] = []
    max_tokens = budget.get("max_tokens")
    if isinstance(max_tokens, int) and max_tokens > 0:
        enforced["max_tokens"] = max_tokens
    runtime_ms = llm_wall_clock_s * 1000
    client_ms = budget.get("max_duration_ms")
    if isinstance(client_ms, int) and client_ms > 0:
        enforced["max_duration_ms"] = min(runtime_ms, client_ms)
        if client_ms > runtime_ms:
            applied_constraints.append("runtime_cap.max_duration_ms")
    else:
        enforced["max_duration_ms"] = runtime_ms
        applied_constraints.append("runtime_default.max_duration_ms")
    if budget_source:
        enforced["source"] = budget_source
    return (enforced if enforced else None), applied_constraints


def _new_demo_state() -> dict[str, Any]:
    return {
        "running": False,
        "task": None,
        "thread_id": None,
        "provider": None,
        "model": None,
        "started_at": None,
        "completed_at": None,
        "current_step_index": None,
        "current_step_name": None,
        "last_error": None,
        "last_run_id": None,
        "logs": [],
        "step_delay_s": _float_env("DBL_GATEWAY_UI_DEMO_STEP_DELAY_S", 1.5),
        "turn_timeout_s": _float_env("DBL_GATEWAY_UI_DEMO_TURN_TIMEOUT_S", 20.0),
        "poll_interval_s": _float_env("DBL_GATEWAY_UI_DEMO_POLL_INTERVAL_S", 0.25),
    }


def _demo_log(app: FastAPI, message: str, *, level: str = "info") -> None:
    demo = app.state.demo_agent
    logs = demo.setdefault("logs", [])
    logs.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
    )
    if len(logs) > 60:
        del logs[:-60]


def _intent_template_payload(
    *,
    intent_type: str,
    example: str,
    boundary_config=None,
) -> dict[str, object]:
    template_version = "1"
    intent_catalog = get_intent_catalog(boundary_config)

    def envelope(
        *,
        intent_variant: str,
        correlation_id: str,
        actor: str,
        turn_id: str,
        payload: Mapping[str, Any],
        requested_model_id: str = "gpt-4o-mini",
        lane: str = "user_chat",
        thread_id: str = "thread-1",
        parent_turn_id: str | None = None,
        intent_type_value: str = "chat.message",
    ) -> dict[str, object]:
        return {
            "interface_version": 3,
            "intent_variant": intent_variant,
            "correlation_id": correlation_id,
            "payload": {
                "stream_id": "default",
                "lane": lane,
                "actor": actor,
                "intent_type": intent_type_value,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "parent_turn_id": parent_turn_id,
                "requested_model_id": requested_model_id,
                "payload": dict(payload),
            },
        }

    examples: dict[str, dict[str, object]] = {
        "minimal": envelope(
            intent_variant="minimal",
            correlation_id="c-1",
            actor="user@example.com",
            turn_id="turn-1",
            payload={"message": "hello gateway"},
            intent_type_value="chat.message",
        ),
        "tools-budget": envelope(
            intent_variant="tools-budget",
            correlation_id="c-tools-1",
            actor="user@example.com",
            turn_id="turn-2",
            parent_turn_id="turn-1",
            payload={
                "message": "Search the docs if needed, but stay within budget.",
                "declared_tools": ["web.search"],
                "tool_scope": "strict",
                "budget": {"max_tokens": 512, "max_duration_ms": 8000},
            },
            intent_type_value="chat.message",
        ),
        "deny-demo": envelope(
            intent_variant="deny-demo",
            correlation_id="c-deny-1",
            actor="demo-agent",
            turn_id="turn-3",
            parent_turn_id="turn-2",
            payload={
                "message": "This turn should fail governance shape validation.",
                "inputs": {
                    "principal_id": "demo-user",
                    "extensions": {"note": "nested objects are not scalar"},
                },
            },
            intent_type_value="chat.message",
        ),
        "artifact-handle": envelope(
            intent_variant="artifact-handle",
            correlation_id="c-artifact-1",
            actor="user@example.com",
            turn_id="turn-4",
            payload={"message": "Inspect referenced artifact metadata."},
            intent_type_value="artifact.handle",
        ),
    }

    selected_intent = intent_type.strip() or "chat.message"
    selected_example = example.strip() or "minimal"
    key_map = {
        ("chat.message", "minimal"): "minimal",
        ("chat.message", "tools-budget"): "tools-budget",
        ("chat.message", "deny-demo"): "deny-demo",
        ("artifact.handle", "minimal"): "artifact-handle",
        ("artifact.handle", "artifact-handle"): "artifact-handle",
    }
    if selected_intent not in intent_catalog:
        raise HTTPException(
            status_code=403,
            detail="intent_type is not discoverable in the current boundary profile",
        )
    if not bool(intent_catalog[selected_intent].get("admitted")):
        raise HTTPException(
            status_code=403,
            detail="intent_type is not currently admitted in the active boundary/runtime configuration",
        )
    selected_key = key_map.get((selected_intent, selected_example))
    if selected_key is None:
        raise HTTPException(
            status_code=400,
            detail="unsupported intent_type/example combination",
        )

    visible_examples: dict[str, dict[str, dict[str, object]]] = {
        "chat.message": {
            "minimal": examples["minimal"],
            "tools-budget": examples["tools-budget"],
            "deny-demo": examples["deny-demo"],
        },
    }
    if bool(intent_catalog.get("artifact.handle", {}).get("admitted")):
        visible_examples["artifact.handle"] = {
            "minimal": examples["artifact-handle"],
        }

    payload = {
        "path": "/ingress/intent",
        "target_endpoint": "/ingress/intent",
        "method": "POST",
        "content_type": "application/json",
        "interface_version": 3,
        "template_version": template_version,
        "intent_type": selected_intent,
        "example": selected_example,
        "template": examples[selected_key],
        "examples": visible_examples,
        "intent_catalog": intent_catalog,
        "notes": [
            "Change correlation_id for each new intent.",
            "Keep thread_id stable across a thread and increment turn_id per turn.",
            "requested_model_id must resolve to an available model in GET /capabilities.",
        ],
    }
    digest_source = {
        "template_version": template_version,
        "interface_version": payload["interface_version"],
        "target_endpoint": payload["target_endpoint"],
        "examples": payload["examples"],
    }
    payload["template_schema_digest"] = "sha256:" + hashlib.sha256(
        canonical_json_bytes(digest_source)
    ).hexdigest()
    return payload


async def _demo_status_payload(app: FastAPI) -> dict[str, Any]:
    capabilities = get_capabilities_cached(trust_class="internal")
    active = active_provider_model(capabilities)
    demo = app.state.demo_agent
    metadata = scenario_metadata(step_delay=float(demo.get("step_delay_s") or 0.0))
    return {
        "scenario_name": DEMO_SCENARIO_NAME,
        "scenario_version": DEMO_SCENARIO_VERSION,
        "scenario_description": DEMO_SCENARIO_DESCRIPTION,
        "steps": metadata["steps"],
        "running": bool(demo.get("running")),
        "thread_id": demo.get("thread_id"),
        "provider": demo.get("provider"),
        "model": demo.get("model"),
        "started_at": demo.get("started_at"),
        "completed_at": demo.get("completed_at"),
        "current_step_index": demo.get("current_step_index"),
        "current_step_name": demo.get("current_step_name"),
        "last_error": demo.get("last_error"),
        "last_run_id": demo.get("last_run_id"),
        "logs": list(demo.get("logs") or []),
        "active_provider": active[0] if active else None,
        "active_model": active[1] if active else None,
        "step_delay_s": demo.get("step_delay_s"),
        "can_start": not bool(demo.get("running")) and active is not None,
    }


async def _run_demo_agent(app: FastAPI) -> None:
    demo = app.state.demo_agent
    capabilities = get_capabilities_cached(trust_class="internal")
    active = active_provider_model(capabilities)
    if active is None:
        demo["last_error"] = "demo.provider_unavailable"
        return

    provider_id, model_id = active
    run_id = uuid.uuid4().hex
    thread_id = f"demo-thread-{run_id[:8]}"
    step_delay = float(demo.get("step_delay_s") or 0.0)
    turn_timeout_s = float(demo.get("turn_timeout_s") or 20.0)
    poll_interval_s = float(demo.get("poll_interval_s") or 0.25)
    steps = default_steps(step_delay=step_delay)

    demo["running"] = True
    demo["thread_id"] = thread_id
    demo["provider"] = provider_id
    demo["model"] = model_id
    demo["started_at"] = datetime.now(timezone.utc).isoformat()
    demo["completed_at"] = None
    demo["current_step_index"] = None
    demo["current_step_name"] = None
    demo["last_error"] = None
    demo["last_run_id"] = run_id
    demo["logs"] = []
    _demo_log(app, f"Run {run_id[:8]} started on {provider_id}/{model_id}")

    parent_turn_id: str | None = None
    try:
        for idx, step in enumerate(steps, start=1):
            turn_id = f"turn-{idx}"
            demo["current_step_index"] = idx
            demo["current_step_name"] = step.name
            _demo_log(app, f"Step {idx}/{len(steps)} {step.name}: {step.description}")

            envelope = build_envelope(
                step=step,
                requested_model_id=model_id,
                stream_id="default",
                lane="demo",
                actor="demo-agent",
                thread_id=thread_id,
                turn_id=turn_id,
                parent_turn_id=parent_turn_id,
            )
            response = await _ingest_envelope(app, envelope, uuid.uuid4().hex, trust_class="internal")
            payload = json.loads(response.body.decode("utf-8"))
            if response.status_code >= 400:
                raise RuntimeError(payload.get("detail") or payload.get("reason_code") or "demo ingress failed")
            correlation_id = str(payload.get("correlation_id") or envelope["correlation_id"])
            _demo_log(app, f"accepted turn {turn_id} correlation_id={correlation_id}")

            decision = await _wait_for_demo_turn(
                app,
                thread_id=thread_id,
                turn_id=turn_id,
                correlation_id=correlation_id,
                timeout_s=turn_timeout_s,
                poll_interval=poll_interval_s,
            )
            _demo_log(app, f"turn {turn_id} result={decision}")
            parent_turn_id = turn_id
            await asyncio.sleep(max(0.0, step.pause_s))
    except Exception as exc:
        demo["last_error"] = str(exc)
        _demo_log(app, f"demo failed: {exc}", level="error")
    finally:
        demo["running"] = False
        demo["task"] = None
        demo["current_step_index"] = None
        demo["current_step_name"] = None
        demo["completed_at"] = datetime.now(timezone.utc).isoformat()
        if demo.get("last_error") is None:
            _demo_log(app, "demo completed")


async def _wait_for_demo_turn(
    app: FastAPI,
    *,
    thread_id: str,
    turn_id: str,
    correlation_id: str,
    timeout_s: float,
    poll_interval: float,
) -> str:
    started = time.monotonic()
    while (time.monotonic() - started) < timeout_s:
        events = [
            event
            for event in app.state.store.timeline(thread_id=thread_id, include_payload=True)
            if event.get("turn_id") == turn_id and event.get("correlation_id") == correlation_id
        ]
        decision = None
        for event in events:
            if event.get("kind") == "DECISION":
                payload = event.get("payload") or {}
                decision = str(payload.get("result") or payload.get("decision") or "")
        if decision == "DENY":
            return "DENY"
        if any(event.get("kind") == "EXECUTION" for event in events):
            return decision or "ALLOW"
        await asyncio.sleep(poll_interval)
    raise RuntimeError(f"turn timeout for correlation_id={correlation_id}")


async def _ingest_envelope(
    app: FastAPI,
    envelope: Mapping[str, Any],
    trace_id: str,
    *,
    actor: Actor | None = None,
    trust_class: str | None = None,
) -> JSONResponse:
    intent_payload = envelope["payload"]
    raw_payload = intent_payload["payload"]
    payload_for_shape = dict(raw_payload)
    payload_for_shape.update(_shape_identity(intent_payload))
    outer_inputs = intent_payload.get("inputs")
    if isinstance(outer_inputs, Mapping):
        payload_for_shape["inputs"] = dict(outer_inputs)
    if intent_payload.get("declared_refs"):
        payload_for_shape["declared_refs"] = intent_payload["declared_refs"]
    if intent_payload.get("declared_tools") is not None:
        payload_for_shape["declared_tools"] = intent_payload["declared_tools"]
    if intent_payload.get("tool_scope") is not None:
        payload_for_shape["tool_scope"] = intent_payload["tool_scope"]
    if intent_payload.get("budget") is not None:
        payload_for_shape["budget"] = intent_payload["budget"]
    if intent_payload.get("intent_type") == "artifact.handle" and not context_resolution_enabled():
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "reason_code": "intent_type.disabled",
                "detail": "artifact.handle requires GATEWAY_ENABLE_CONTEXT_RESOLUTION=true",
            },
        )
    shaped_payload = _shape_payload(intent_payload["intent_type"], payload_for_shape)
    resolved_trust_class = trust_class or trust_class_for_actor(actor)
    _inject_gateway_auth_inputs(
        shaped_payload,
        actor=actor,
        trust_class=resolved_trust_class,
    )
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
            boundary_config=app.state.boundary_config,
        )
    except AdmissionFailure as exc:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "reason_code": exc.reason_code, "detail": exc.detail},
        )
    authoritative = _thaw_json(admission_record.deterministic)
    authoritative["correlation_id"] = admission_record.correlation_id
    if actor is not None:
        authoritative["tenant_id"] = actor.tenant_id
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

    if authoritative["intent_type"] in {"artifact.handle"}:
        _assert_governance_input(authoritative)
        decision = app.state.policy.decide(authoritative)
        app.state.store.append(
            kind="DECISION",
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
            lane=authoritative["lane"],
            actor="policy",
            intent_type=authoritative["intent_type"],
            stream_id=authoritative["stream_id"],
            correlation_id=envelope["correlation_id"],
            payload=_decision_payload(
                decision,
                trace_id,
                assembly_digest=None,
                context_digest=None,
                error_ref=None,
                context_config_digest=None,
                boundary=None,
                requested_model_id=None,
                resolved_model_id=None,
                provider=None,
                transforms=[],
                context_spec=None,
                assembled_context=None,
            ),
        )
        return JSONResponse(
            status_code=202,
            content={
                "accepted": True,
                "stream_id": authoritative["stream_id"],
                "index": intent_event["index"],
                "correlation_id": envelope["correlation_id"],
                "queued": False,
            },
        )

    inline_flag = os.getenv("DBL_GATEWAY_INLINE_DECISION", "").strip().lower()
    if inline_flag in {"1", "true", "yes"} or (
        os.getenv("PYTEST_CURRENT_TEST") and inline_flag not in {"0", "false", "no"}
    ):
        await _process_intent(app, intent_event, envelope["correlation_id"], trace_id)
        return JSONResponse(
            status_code=202,
            content={
                "accepted": True,
                "stream_id": authoritative["stream_id"],
                "index": intent_event["index"],
                "correlation_id": envelope["correlation_id"],
                "queued": False,
            },
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
    browser_host = args.host
    if browser_host in {"0.0.0.0", "::"}:
        browser_host = "localhost"
    boundary = get_boundary_config()
    _LOGGER.info(
        '{"message":"startup.boundary","exposure_mode":"%s","boundary_version":"%s","boundary_config_digest":"%s"}',
        boundary.exposure_mode,
        boundary.boundary_version,
        boundary.config_digest,
    )
    if boundary.exposure_mode == "demo":
        _LOGGER.info('{"message":"startup.surface","observer_ui":"http://%s:%d/ui/"}', browser_host, args.port)
    else:
        _LOGGER.info('{"message":"startup.surface","ingress":"http://%s:%d/ingress/intent"}', browser_host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, reload=False)


app = create_app()
