from __future__ import annotations

import argparse
import json
import hashlib
import logging
import os
import time
import uuid
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping

import uvicorn
from contextlib import asynccontextmanager
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi import Path as PathParam
from fastapi.responses import JSONResponse

from .auth import (
    Actor,
    AuthConfig,
    AuthError,
    ForbiddenError,
    authenticate_request,
    load_auth_config,
    require_roles,
    require_tenant,
)
from .store.factory import create_store
from .store.base import IdempotencyConflictError
from .digest import canonical_bytes, event_digest
from .wire_contract import (
    INTERFACE_VERSION,
    StackFingerprint,
    validate_digest_ref,
    validate_unknown_or_digest_ref,
    validate_unknown_or_opaque,
    validate_interface_version,
    validate_wire_event,
    validate_wire_snapshot,
)

_LOGGER = logging.getLogger("dbl_gateway")
_ALLOWED_EVENT_KINDS = {
    "INTENT",
    "DECISION",
    "POLICY_UPDATE_DECISION",
    "BOUNDARY_UPDATE_DECISION",
    "EXECUTION",
    "PROOF",
}


def _configure_logging() -> None:
    if _LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(logging.INFO)


def _log_json(level: int, message: str, **fields: Any) -> None:
    payload = {"message": message, **fields}
    _LOGGER.log(level, json.dumps(payload, ensure_ascii=True))


def _get_version() -> str:
    try:
        return version("dbl-gateway")
    except PackageNotFoundError:
        return "unknown"


def build_stack_fingerprint() -> StackFingerprint:
    policy_pack_digest = os.getenv("DBL_GATEWAY_POLICY_PACK_DIGEST", "unknown").strip()
    boundary_config_hash = os.getenv("DBL_GATEWAY_BOUNDARY_CONFIG_HASH", "unknown").strip()
    if policy_pack_digest == "":
        policy_pack_digest = "unknown"
    if boundary_config_hash == "":
        boundary_config_hash = "unknown"
    validate_unknown_or_digest_ref(policy_pack_digest, "policy_pack_digest")
    validate_unknown_or_opaque(boundary_config_hash, "boundary_config_hash")
    return {
        "main_version": _get_version(),
        "policy_pack_digest": policy_pack_digest,
        "boundary_config_hash": boundary_config_hash,
    }


def create_app(db_path: Path | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _configure_logging()
        app.state.store = create_store(db_path=db_path)
        app.state.start_time = time.monotonic()
        try:
            yield
        finally:
            app.state.store.close()

    app = FastAPI(title="DBL Gateway", lifespan=lifespan)

    @app.middleware("http")
    async def request_logging(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "").strip() or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            latency_ms = int((time.monotonic() - start) * 1000)
            _log_json(
                logging.ERROR,
                "request.failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                latency_ms=latency_ms,
            )
            raise
        latency_ms = int((time.monotonic() - start) * 1000)
        response.headers["x-request-id"] = request_id
        _log_json(
            logging.INFO,
            "request.completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
        )
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/status")
    async def status_surface(
        actor: Actor = Depends(guard(["gateway.snapshot.read"])),
    ) -> dict[str, Any]:
        stack_fingerprint = build_stack_fingerprint()
        length, v_digest_value = app.state.store.stream_status()
        return {
            "interface_version": INTERFACE_VERSION,
            "main_version": stack_fingerprint["main_version"],
            "stack_fingerprint": stack_fingerprint,
            "length": length,
            "v_digest": v_digest_value,
        }

    @app.get("/debug/config")
    async def debug_config(
        actor: Actor = Depends(guard(["gateway.admin.read"])),
    ) -> dict[str, Any]:
        return _build_debug_config(app)

    @app.post("/ingress/intent")
    async def ingress_intent(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.intent.write"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("INTENT", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="INTENT",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/governance/decision")
    async def governance_decision(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.decision.write"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("DECISION", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="DECISION",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/governance/policy-update")
    async def policy_update(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.policy.update"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("POLICY_UPDATE_DECISION", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="POLICY_UPDATE_DECISION",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/governance/boundary-update")
    async def boundary_update(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.boundary.update"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("BOUNDARY_UPDATE_DECISION", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="BOUNDARY_UPDATE_DECISION",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/execution/event")
    async def execution_event(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.execution.write"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("EXECUTION", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="EXECUTION",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/proof/artifact")
    async def proof_artifact(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(guard(["gateway.proof.write"])),
    ) -> dict[str, Any]:
        correlation_id, payload = _parse_write_body(body)
        payload = _attach_obs(payload, actor, _get_auth_cfg(request))
        _validate_identity("PROOF", correlation_id, payload)
        idempotency_key = _get_idempotency_key(request)
        return _append_event(
            app,
            kind="PROOF",
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/llm/call")
    async def llm_call(
        request: Request,
        body: dict[str, Any] = Body(...),
        _mode_check: None = Depends(require_leader),
        actor: Actor = Depends(get_actor),
    ) -> dict[str, Any]:
        try:
            require_tenant(actor)
        except ForbiddenError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        correlation_id = _resolve_correlation_id(request, body.get("correlation_id"))
        normalized = _normalize_llm_input(body, actor, request.state.request_id)
        intent_digest = _digest_ref_for_value(normalized)
        intent_payload = {
            "boundary_version": normalized["boundary_version"],
            "boundary_config_hash": build_stack_fingerprint()["boundary_config_hash"],
            "intent_digest": intent_digest,
            "input_digest": intent_digest,
            "input": normalized,
        }
        intent_payload = _attach_obs(intent_payload, actor, _get_auth_cfg(request))
        _validate_identity("INTENT", correlation_id, intent_payload)
        intent_event = _append_event(
            app,
            kind="INTENT",
            correlation_id=correlation_id,
            payload=intent_payload,
        )

        decision = _decide_llm(normalized)
        decision_payload = {
            "policy_version": normalized["policy_version"],
            "decision": decision["decision"],
            "reason_codes": decision["reason_codes"],
        }
        decision_payload = _attach_obs(decision_payload, actor, _get_auth_cfg(request))
        _validate_identity("DECISION", correlation_id, decision_payload)
        decision_event = _append_event(
            app,
            kind="DECISION",
            correlation_id=correlation_id,
            payload=decision_payload,
        )

        trail_ref = _build_trail_ref(intent_event, decision_event, None)
        if decision["decision"] == "DENY":
            return JSONResponse(
                status_code=403,
                content={
                    "trail_ref": trail_ref,
                    "decision": "DENY",
                    "reason_codes": decision["reason_codes"],
                },
            )

        output_text = await _execute_llm(normalized)
        output_text, output_truncated = _cap_output(output_text)
        store_output_text = _should_store_output_text()
        execution_payload = {
            "execution_digest": _digest_ref_for_value(output_text),
            "decision_digest": decision_event["digest"],
            "output_ref": None,
        }
        if store_output_text:
            execution_payload["output_text"] = output_text
            execution_payload["output_truncated"] = output_truncated
        execution_payload = _attach_obs(execution_payload, actor, _get_auth_cfg(request))
        _validate_identity("EXECUTION", correlation_id, execution_payload)
        execution_event = _append_event(
            app,
            kind="EXECUTION",
            correlation_id=correlation_id,
            payload=execution_payload,
        )
        trail_ref = _build_trail_ref(intent_event, decision_event, execution_event)
        return {
            "trail_ref": trail_ref,
            "output_text": output_text,
            "output_digest": execution_payload["execution_digest"],
        }

    @app.get("/snapshot")
    async def snapshot(
        limit: int = Query(200, ge=0, le=2000),
        offset: int = Query(0, ge=0),
        correlation_id: str | None = Query(None),
        actor: Actor = Depends(guard(["gateway.snapshot.read"])),
    ) -> dict[str, Any]:
        correlation_id = _normalize_optional_str(correlation_id, "correlation_id")
        result = app.state.store.snapshot(
            limit=limit,
            offset=offset,
            stack_fingerprint=build_stack_fingerprint(),
            correlation_id=correlation_id,
        )
        _add_paging_metadata(result, limit=limit, offset=offset)
        _verify_stream_integrity(result)
        _ensure_wire_snapshot(result)
        return result

    @app.get("/snapshot/norm")
    async def snapshot_norm(
        limit: int = Query(200, ge=0, le=2000),
        offset: int = Query(0, ge=0),
        correlation_id: str | None = Query(None),
        actor: Actor = Depends(guard(["gateway.snapshot.read"])),
    ) -> dict[str, Any]:
        correlation_id = _normalize_optional_str(correlation_id, "correlation_id")
        result = app.state.store.snapshot_norm(
            limit=limit,
            offset=offset,
            stack_fingerprint=build_stack_fingerprint(),
            correlation_id=correlation_id,
        )
        _add_paging_metadata(result, limit=limit, offset=offset)
        _verify_stream_integrity(result)
        _ensure_wire_snapshot(result)
        return result

    @app.get("/event/{index}")
    async def event_by_index(
        index: int = PathParam(..., ge=0),
        actor: Actor = Depends(guard(["gateway.snapshot.read"])),
    ) -> dict[str, Any]:
        event = app.state.store.get_event(index=index)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        _verify_event_integrity(event)
        _ensure_wire_event(event)
        return event

    return app


def _parse_write_body(body: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    interface_version = body.get("interface_version")
    if not isinstance(interface_version, int):
        raise HTTPException(status_code=400, detail="interface_version must be an int")
    try:
        validate_interface_version(interface_version)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    correlation_id = body.get("correlation_id")
    payload = body.get("payload")
    if not isinstance(correlation_id, str) or correlation_id == "":
        raise HTTPException(status_code=400, detail="correlation_id must be a non-empty string")
    if not isinstance(payload, Mapping):
        raise HTTPException(status_code=400, detail="payload must be an object")
    payload_out = dict(payload)
    for key in payload_out:
        if key.startswith("_") and key != "_obs":
            raise HTTPException(status_code=400, detail=f"unsupported reserved field: {key}")
    return correlation_id, payload_out


def _attach_obs(payload: dict[str, Any], actor: Actor, auth_cfg: AuthConfig | None = None) -> dict[str, Any]:
    out = dict(payload)
    obs = out.get("_obs")
    obs_dict = obs if isinstance(obs, dict) else {}
    cfg = auth_cfg or load_auth_config()
    auth_mode = cfg.mode
    obs_dict.setdefault("auth_mode", auth_mode)
    obs_dict.setdefault("roles", list(actor.roles))
    obs_dict.setdefault("actor_id", actor.actor_id)
    obs_dict.setdefault("actor_tenant_id", actor.tenant_id)
    obs_dict.setdefault("actor_client_id", actor.client_id)
    out["_obs"] = obs_dict
    return out


def _resolve_correlation_id(request: Request, payload_value: object) -> str:
    if isinstance(payload_value, str) and payload_value.strip():
        return payload_value.strip()
    request_id = getattr(request.state, "request_id", "").strip()
    if request_id:
        return request_id
    return uuid.uuid4().hex


def _normalize_llm_input(body: Mapping[str, Any], actor: Actor, request_id: str) -> dict[str, Any]:
    prompt = body.get("prompt")
    if not isinstance(prompt, str) or prompt.strip() == "":
        raise HTTPException(status_code=400, detail="prompt must be a non-empty string")
    boundary_version = body.get("boundary_version")
    if not isinstance(boundary_version, int):
        raise HTTPException(status_code=400, detail="boundary_version must be an int")
    policy_version = body.get("policy_version")
    if policy_version is None:
        policy_version = _get_env_int("GATEWAY_POLICY_VERSION", 1)
    if not isinstance(policy_version, int):
        raise HTTPException(status_code=400, detail="policy_version must be an int")
    params = body.get("parameters", {})
    if not isinstance(params, Mapping):
        raise HTTPException(status_code=400, detail="parameters must be an object")
    normalized_params = _normalize_llm_params(params)
    return {
        "request_id": request_id,
        "tenant_id": actor.tenant_id,
        "actor_id": actor.actor_id,
        "actor_roles": sorted(actor.roles),
        "prompt": prompt.strip(),
        "parameters": normalized_params,
        "boundary_version": boundary_version,
        "policy_version": policy_version,
    }


def _normalize_llm_params(params: Mapping[str, Any]) -> dict[str, Any]:
    default_model = os.getenv("GATEWAY_LLM_MODEL", "").strip()
    model = params.get("model", default_model)
    if model is None:
        model = ""
    if not isinstance(model, str):
        raise HTTPException(status_code=400, detail="parameters.model must be a string")
    temperature = params.get("temperature", 0.0)
    if isinstance(temperature, bool):
        raise HTTPException(status_code=400, detail="parameters.temperature must be a number")
    if isinstance(temperature, int):
        temperature = float(temperature)
    if not isinstance(temperature, float):
        raise HTTPException(status_code=400, detail="parameters.temperature must be a number")
    max_tokens = params.get("max_tokens", 1)
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise HTTPException(status_code=400, detail="parameters.max_tokens must be an int")
    tools_enabled = params.get("tools_enabled", False)
    if not isinstance(tools_enabled, bool):
        raise HTTPException(status_code=400, detail="parameters.tools_enabled must be a bool")
    return {
        "model": model.strip(),
        "temperature": temperature,
        "max_tokens": max_tokens,
        "tools_enabled": tools_enabled,
    }


def _decide_llm(input_data: Mapping[str, Any]) -> dict[str, Any]:
    required_role = os.getenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call").strip() or "gateway.llm.call"
    tenant_allowlist = _parse_csv_env("GATEWAY_TENANT_ALLOWLIST")
    model_allowlist = _parse_csv_env("GATEWAY_LLM_MODEL_ALLOWLIST")
    temp_max = _get_env_float("GATEWAY_LLM_TEMP_MAX", 1.0)
    max_tokens_max = _get_env_int("GATEWAY_LLM_MAX_TOKENS_MAX", 1024)
    tools_allowed = os.getenv("GATEWAY_LLM_TOOLS_ALLOWED", "false").strip().lower() in {"1", "true", "yes"}

    reason_codes: list[str] = []
    actor_roles = input_data.get("actor_roles", [])
    if required_role not in actor_roles:
        reason_codes.append("missing_role")
    tenant_id = str(input_data.get("tenant_id", ""))
    if tenant_allowlist and tenant_id not in tenant_allowlist:
        reason_codes.append("tenant_not_allowed")
    params = input_data.get("parameters", {})
    model = str(params.get("model", ""))
    if model_allowlist and model not in model_allowlist:
        reason_codes.append("model_not_allowed")
    temperature = float(params.get("temperature", 0.0))
    if temperature < 0 or temperature > temp_max:
        reason_codes.append("temperature_out_of_range")
    max_tokens = int(params.get("max_tokens", 0))
    if max_tokens < 1 or max_tokens > max_tokens_max:
        reason_codes.append("max_tokens_out_of_range")
    tools_enabled = bool(params.get("tools_enabled", False))
    if tools_enabled and not tools_allowed:
        reason_codes.append("tools_not_allowed")

    decision = "ALLOW" if not reason_codes else "DENY"
    return {"decision": decision, "reason_codes": reason_codes}


def _execute_stub(input_data: Mapping[str, Any]) -> str:
    digest_ref = _digest_ref_for_value(input_data)
    return f"stub_response:{digest_ref.split(':', 1)[1][:12]}"


async def _execute_llm(input_data: Mapping[str, Any]) -> str:
    mode = os.getenv("GATEWAY_LLM_EXEC_MODE", "stub").strip().lower()
    if mode == "stub":
        return _execute_stub(input_data)
    if mode == "openai":
        return await _execute_openai(input_data)
    if mode == "http":
        provider = os.getenv("GATEWAY_LLM_PROVIDER", "generic_http").strip().lower()
        if provider == "generic_http":
            return await _execute_generic_http(input_data)
        if provider == "openai":
            return await _execute_openai(input_data)
        if provider == "azure_openai":
            raise HTTPException(status_code=501, detail="azure_openai provider not implemented")
        raise HTTPException(status_code=400, detail="unsupported GATEWAY_LLM_PROVIDER")
    raise HTTPException(status_code=501, detail="llm exec mode not implemented")


async def _execute_generic_http(input_data: Mapping[str, Any]) -> str:
    base_url = os.getenv("GATEWAY_LLM_HTTP_BASE_URL", "").strip()
    if base_url == "":
        raise HTTPException(status_code=500, detail="GATEWAY_LLM_HTTP_BASE_URL required")
    timeout_s = _get_env_float("GATEWAY_LLM_TIMEOUT_S", 30.0)
    api_key = os.getenv("GATEWAY_LLM_API_KEY", "").strip()
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    payload = {"input": input_data}
    try:
        import httpx
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="httpx required for http exec mode") from exc
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(base_url, json=payload, headers=headers)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"llm http error: {exc}") from exc
    data = resp.json()
    output_text = data.get("output_text")
    if not isinstance(output_text, str):
        raise HTTPException(status_code=502, detail="llm http response missing output_text")
    return output_text


async def _execute_openai(input_data: Mapping[str, Any]) -> str:
    api_key = os.getenv("GATEWAY_LLM_API_KEY", "").strip()
    if api_key == "":
        raise HTTPException(status_code=500, detail="GATEWAY_LLM_API_KEY required")
    base_url = os.getenv("GATEWAY_LLM_HTTP_BASE_URL", "https://api.openai.com/v1").strip()
    timeout_s = _get_env_float("GATEWAY_LLM_TIMEOUT_S", 30.0)
    params = input_data.get("parameters", {})
    tools_enabled = bool(params.get("tools_enabled", False))
    if tools_enabled:
        raise HTTPException(status_code=501, detail="tools not implemented for openai")
    model = str(params.get("model") or os.getenv("GATEWAY_LLM_MODEL", "gpt-4o-mini")).strip()
    if model == "":
        raise HTTPException(status_code=500, detail="model required for openai")
    temperature = float(params.get("temperature", 0.0))
    max_tokens = int(params.get("max_tokens", 1))
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": input_data.get("prompt", "")}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {"authorization": f"Bearer {api_key}"}
    try:
        import httpx
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="httpx required for openai") from exc
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"openai http error: {exc}") from exc
    data = resp.json()
    try:
        return str(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="openai response missing content") from exc


def _cap_output(output_text: str) -> tuple[str, bool]:
    max_chars = _get_env_int("GATEWAY_LLM_OUTPUT_MAX_CHARS", 8192)
    if max_chars < 1:
        max_chars = 1
    if len(output_text) <= max_chars:
        return output_text, False
    return output_text[:max_chars], True


def _should_store_output_text() -> bool:
    raw = os.getenv("GATEWAY_LLM_STORE_OUTPUT_TEXT", "").strip().lower()
    if raw in {"1", "true", "yes"}:
        return True
    if raw in {"0", "false", "no"}:
        return False
    mode = os.getenv("GATEWAY_LLM_EXEC_MODE", "stub").strip().lower()
    return mode == "stub"


def _digest_ref_for_value(value: Any) -> str:
    canon = canonical_bytes(value)
    digest_bytes = hashlib.sha256(canon).digest()
    return f"sha256:{digest_bytes.hex()}"


def _build_trail_ref(
    intent_event: Mapping[str, Any],
    decision_event: Mapping[str, Any],
    execution_event: Mapping[str, Any] | None,
) -> dict[str, Any]:
    trail = {
        "intent_index": intent_event["index"],
        "intent_digest": intent_event["digest"],
        "decision_index": decision_event["index"],
        "decision_digest": decision_event["digest"],
    }
    if execution_event is not None:
        trail["execution_index"] = execution_event["index"]
        trail["execution_digest"] = execution_event["digest"]
    return trail


def _parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "").strip()
    if raw == "":
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def _get_env_int(key: str, default: int) -> int:
    raw = os.getenv(key, "").strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_env_float(key: str, default: float) -> float:
    raw = os.getenv(key, "").strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_idempotency_key(request: Request | None) -> str | None:
    if request is None:
        return None
    enabled = os.getenv("DBL_GATEWAY_IDEMPOTENCY", "0").strip().lower()
    if enabled not in {"1", "true", "yes"}:
        return None
    key = request.headers.get("idempotency-key")
    if key is None:
        return None
    key = key.strip()
    if key == "":
        raise HTTPException(status_code=400, detail="idempotency-key must be a non-empty string")
    return key


async def get_actor(request: Request) -> Actor:
    try:
        headers = {k.lower(): v for k, v in request.headers.items()}
        cfg = _get_auth_cfg(request)
        return await authenticate_request(headers, cfg=cfg)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


def guard(required_roles: list[str]):
    async def _guard(request: Request, actor: Actor = Depends(get_actor)) -> Actor:
        try:
            require_roles(actor, required_roles)
            require_tenant(actor, cfg=_get_auth_cfg(request))
            return actor
        except ForbiddenError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return _guard


def _get_auth_cfg(request: Request) -> AuthConfig:
    cfg = getattr(request.state, "auth_cfg", None)
    if cfg is None:
        cfg = load_auth_config()
        request.state.auth_cfg = cfg
    return cfg



def _validate_identity(kind: str, correlation_id: str, payload: Mapping[str, Any]) -> None:
    if kind == "INTENT":
        _require_fields(payload, ["boundary_version", "boundary_config_hash"])
        _require_int_fields(payload, ["boundary_version"])
        _require_unknown_or_opaque(payload, "boundary_config_hash")
        if "input_digest" not in payload and "intent_digest" not in payload:
            raise HTTPException(status_code=400, detail="INTENT requires input_digest or intent_digest")
        if "input_digest" in payload:
            _require_digest_ref(payload, "input_digest")
        if "intent_digest" in payload:
            _require_digest_ref(payload, "intent_digest")
    elif kind == "DECISION":
        if "policy_version" not in payload:
            raise HTTPException(status_code=400, detail="DECISION requires policy_version")
        _require_int_fields(payload, ["policy_version"])
        if "policy_digest" in payload:
            _require_digest_ref(payload, "policy_digest")
    elif kind == "POLICY_UPDATE_DECISION":
        _require_fields(payload, ["policy_version", "policy_digest"])
        _require_int_fields(payload, ["policy_version"])
        _require_digest_ref(payload, "policy_digest")
    elif kind == "BOUNDARY_UPDATE_DECISION":
        _require_fields(payload, ["boundary_version", "boundary_config_hash"])
        _require_int_fields(payload, ["boundary_version"])
        _require_unknown_or_opaque(payload, "boundary_config_hash")
    elif kind == "EXECUTION":
        _require_fields(payload, ["execution_digest"])
        _require_digest_ref(payload, "execution_digest")
        if "decision_digest" in payload:
            _require_digest_ref(payload, "decision_digest")
    elif kind == "PROOF":
        _require_fields(payload, ["proof_digest"])
        _require_digest_ref(payload, "proof_digest")
        if "decision_digest" in payload:
            _require_digest_ref(payload, "decision_digest")
        if "proof_kind" in payload:
            _require_non_empty_str(payload, "proof_kind")


def _require_fields(payload: Mapping[str, Any], fields: list[str]) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        missing_str = ", ".join(missing)
        raise HTTPException(status_code=400, detail=f"missing identity fields: {missing_str}")


def _require_int_fields(payload: Mapping[str, Any], fields: list[str]) -> None:
    for field in fields:
        value = payload.get(field)
        if not isinstance(value, int):
            raise HTTPException(status_code=400, detail=f"{field} must be an int")


def _require_digest_ref(payload: Mapping[str, Any], field: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    try:
        validate_digest_ref(value, field)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _require_unknown_or_opaque(payload: Mapping[str, Any], field: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    try:
        validate_unknown_or_opaque(value, field)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _require_non_empty_str(payload: Mapping[str, Any], field: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or value.strip() == "":
        raise HTTPException(status_code=400, detail=f"{field} must be a non-empty string")


def _ensure_wire_snapshot(snapshot: Mapping[str, Any]) -> None:
    try:
        validate_wire_snapshot(snapshot)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=f"invalid wire snapshot: {exc}") from exc


def _ensure_wire_event(event: Mapping[str, Any]) -> None:
    try:
        validate_wire_event(event)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=f"invalid wire event: {exc}") from exc


def _normalize_optional_str(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if value.strip() == "":
        raise HTTPException(status_code=400, detail=f"{name} must be a non-empty string")
    return value


def _add_paging_metadata(snapshot: dict[str, Any], *, limit: int, offset: int) -> None:
    events = snapshot.get("events")
    returned = len(events) if isinstance(events, list) else 0
    length = snapshot.get("length")
    has_more = False
    if isinstance(length, int):
        has_more = (offset + returned) < length
    snapshot["offset"] = offset
    snapshot["limit"] = limit
    snapshot["returned"] = returned
    snapshot["has_more"] = has_more


def _verify_stream_integrity(snapshot: Mapping[str, Any]) -> None:
    if os.getenv("DBL_GATEWAY_STRICT_READ_VERIFY", "0").strip() not in {"1", "true", "yes"}:
        return
    events = snapshot.get("events")
    if not isinstance(events, list):
        return
    for event in events:
        if not isinstance(event, Mapping):
            continue
        try:
            idx = int(event.get("index"))
            kind = str(event.get("kind"))
            correlation_id = str(event.get("correlation_id"))
            payload = event.get("payload")
            stored_digest = str(event.get("digest"))
            stored_canon_len = event.get("canon_len")
        except Exception:
            continue
        if not isinstance(payload, Mapping):
            continue
        recomputed_digest, recomputed_len = event_digest(
            kind, correlation_id, dict(payload)
        )
        if stored_digest != recomputed_digest or stored_canon_len != recomputed_len:
            _log_json(
                logging.ERROR,
                "store.integrity_violation",
                index=idx,
                expected_digest=recomputed_digest,
                actual_digest=stored_digest,
            )
            raise HTTPException(status_code=500, detail="store integrity violation")


def _verify_event_integrity(event: Mapping[str, Any]) -> None:
    if os.getenv("DBL_GATEWAY_STRICT_READ_VERIFY", "0").strip() not in {"1", "true", "yes"}:
        return
    if not isinstance(event, Mapping):
        return
    try:
        kind = str(event.get("kind"))
        correlation_id = str(event.get("correlation_id"))
        payload = event.get("payload")
        stored_digest = str(event.get("digest"))
        stored_canon_len = event.get("canon_len")
    except Exception:
        return
    if not isinstance(payload, Mapping):
        return
    recomputed_digest, recomputed_len = event_digest(kind, correlation_id, dict(payload))
    if stored_digest != recomputed_digest or stored_canon_len != recomputed_len:
        _log_json(
            logging.ERROR,
            "store.integrity_violation",
            expected_digest=recomputed_digest,
            actual_digest=stored_digest,
        )
        raise HTTPException(status_code=500, detail="store integrity violation")


def _append_event(
    app: FastAPI,
    *,
    kind: str,
    correlation_id: str,
    payload: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if kind not in _ALLOWED_EVENT_KINDS:
        raise HTTPException(status_code=400, detail="unsupported event kind")
    try:
        return app.state.store.append(
            kind=kind,
            correlation_id=correlation_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        _log_json(
            logging.ERROR,
            "append.non_canonical",
            kind=kind,
            correlation_id=correlation_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=400, detail="payload must be JSON-serializable and canonical"
        ) from exc


def _build_debug_config(app: FastAPI) -> dict[str, Any]:
    backend = os.getenv("DBL_GATEWAY_STORE", "sqlite").strip().lower()
    db_path = os.getenv("DBL_GATEWAY_DB", ".\\data\\trail.sqlite")
    db_url = os.getenv("DBL_GATEWAY_DB_URL", "")
    mode = os.getenv("DBL_GATEWAY_MODE", "leader").strip().lower()
    leader_lock_enabled = os.getenv("DBL_GATEWAY_LEADER_LOCK", "1").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    idempotency_enabled = os.getenv("DBL_GATEWAY_IDEMPOTENCY", "0").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    strict_read_verify = os.getenv("DBL_GATEWAY_STRICT_READ_VERIFY", "0").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    uptime_s = int(time.monotonic() - app.state.start_time)
    return {
        "interface_version": INTERFACE_VERSION,
        "mode": mode,
        "store_backend": backend or "sqlite",
        "db_path": _redact_db_path(db_path),
        "db_url_set": bool(db_url),
        "auth_mode": load_auth_config().mode,
        "leader_lock_enabled": leader_lock_enabled,
        "idempotency_enabled": idempotency_enabled,
        "strict_read_verify": strict_read_verify,
        "uptime_s": uptime_s,
    }


def _redact_db_path(db_path: str) -> str:
    try:
        path = Path(db_path)
        return path.name
    except Exception:
        return "unknown"


def require_leader() -> None:
    mode = os.getenv("DBL_GATEWAY_MODE", "leader").strip().lower()
    if mode == "follower":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="writes disabled in follower mode",
        )


def main() -> None:
    args = _parse_args()
    os.environ["DBL_GATEWAY_DB"] = str(args.db)
    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, reload=False)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="dbl-gateway")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8010)
    serve.add_argument("--db", default=".\\data\\trail.sqlite")
    return parser.parse_args()


app = create_app()
