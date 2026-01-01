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


SECRET_KEYS = {"api_key", "authorization", "token", "secret", "bearer"}


@dataclass(frozen=True)
class AdmissionFailure(Exception):
    reason_code: str
    detail: str


def admit_and_shape_intent(payload: Mapping[str, Any], *, raw_payload: Mapping[str, Any] | None = None) -> AdmissionRecord:
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
