from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from dbl_ingress import (
    AdmissionError,
    InvalidInputError,
    AdmissionRecord,
    shape_input,
    ADMISSION_INVALID_INPUT,
    ADMISSION_SECRETS_PRESENT,
)

from .config import BoundaryConfig


SECRET_KEYS = {"api_key", "authorization", "token", "secret", "bearer"}
ADMISSION_INTENT_TYPE_DENIED = "admission.intent_type_denied"
ADMISSION_CONTEXT_REFS_DENIED = "admission.context_refs_denied"
ADMISSION_DECLARED_TOOLS_DENIED = "admission.declared_tools_denied"


@dataclass(frozen=True)
class AdmissionFailure(Exception):
    reason_code: str
    detail: str


def admit_and_shape_intent(
    payload: Mapping[str, Any],
    *,
    raw_payload: Mapping[str, Any] | None = None,
    boundary_config: BoundaryConfig | None = None,
) -> AdmissionRecord:
    if raw_payload is not None and _contains_secrets(raw_payload):
        raise AdmissionFailure(reason_code=ADMISSION_SECRETS_PRESENT, detail="secrets detected in payload")
    if _contains_secrets(payload):
        raise AdmissionFailure(reason_code=ADMISSION_SECRETS_PRESENT, detail="secrets detected in payload")

    correlation_id = payload.get("correlation_id")
    deterministic = payload.get("deterministic")
    observational = payload.get("observational")

    if not isinstance(correlation_id, str) or not correlation_id.strip():
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="correlation_id must be a non-empty string")
    if not isinstance(deterministic, Mapping):
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="deterministic must be an object")
    if observational is not None and not isinstance(observational, Mapping):
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="observational must be an object if provided")

    deterministic_payload = deterministic.get("payload")
    _require_identity_anchors(deterministic_payload)
    if boundary_config is not None:
        _enforce_boundary_admission(
            deterministic,
            payload=deterministic_payload,
            boundary_config=boundary_config,
        )

    try:
        record = shape_input(
            correlation_id=correlation_id,
            deterministic=deterministic,
            observational=observational,
        )
    except InvalidInputError as exc:
        raise AdmissionFailure(reason_code=exc.reason_code, detail=str(exc)) from exc
    except AdmissionError as exc:
        reason = getattr(exc, "reason_code", ADMISSION_INVALID_INPUT)
        raise AdmissionFailure(reason_code=reason, detail=str(exc)) from exc
    return record


def _contains_secrets(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in SECRET_KEYS:
                if isinstance(item, str) and item.strip():
                    return True
            if _contains_secrets(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secrets(item) for item in value)
    return False


def _require_identity_anchors(payload: object) -> None:
    if not isinstance(payload, Mapping):
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="payload must be an object")
    for key in ("thread_id", "turn_id"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail=f"{key} must be a non-empty string")
    parent = payload.get("parent_turn_id")
    if parent is not None and not isinstance(parent, str):
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="parent_turn_id must be a string when provided")


def _enforce_boundary_admission(
    deterministic: Mapping[str, Any],
    *,
    payload: object,
    boundary_config: BoundaryConfig,
) -> None:
    if boundary_config.exposure_mode != "public":
        return
    if not isinstance(payload, Mapping):
        raise AdmissionFailure(reason_code=ADMISSION_INVALID_INPUT, detail="payload must be an object")

    admission = boundary_config.admission
    raw_intent_type = deterministic.get("intent_type")
    intent_type = raw_intent_type if isinstance(raw_intent_type, str) else payload.get("intent_type")
    if (
        intent_type == "artifact.handle"
        and not admission.public_allow_artifact_handle
    ):
        raise AdmissionFailure(
            reason_code=ADMISSION_INTENT_TYPE_DENIED,
            detail="artifact.handle is not admitted in public exposure mode",
        )

    declared_refs = payload.get("declared_refs")
    if declared_refs and not admission.public_allow_declared_refs:
        raise AdmissionFailure(
            reason_code=ADMISSION_CONTEXT_REFS_DENIED,
            detail="declared_refs are not admitted in public exposure mode",
        )

    declared_tools = payload.get("declared_tools")
    if isinstance(declared_tools, list) and len(declared_tools) > admission.public_max_declared_tools:
        raise AdmissionFailure(
            reason_code=ADMISSION_DECLARED_TOOLS_DENIED,
            detail=(
                "declared_tools exceed public exposure limit "
                f"({len(declared_tools)} > {admission.public_max_declared_tools})"
            ),
        )
