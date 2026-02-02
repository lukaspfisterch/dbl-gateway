from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping, TypedDict

from dbl_core.events.canonical import canonicalize_value, json_dumps


# Event envelope with mandatory identity anchors.
class EventEnvelope(TypedDict, total=False):
    kind: str
    thread_id: str
    turn_id: str
    parent_turn_id: str | None
    correlation_id: str
    payload: dict[str, Any]
    _obs: dict[str, Any]


class PolicyIdent(TypedDict):
    policy_id: str
    policy_version: str


class DecisionReason(TypedDict, total=False):
    code: str
    params: Mapping[str, Any]


class DecisionTransform(TypedDict, total=False):
    op: str
    target: str
    params: Mapping[str, Any]


class DecisionNormative(TypedDict):
    policy: PolicyIdent
    assembly_digest: str | None
    context_digest: str | None
    result: str
    reasons: list[DecisionReason]
    transforms: list[DecisionTransform]


class ContextIdentity(TypedDict, total=False):
    thread_id: str
    turn_id: str
    parent_turn_id: str | None


class IntentSpec(TypedDict):
    intent_type: str
    user_input: str


class DeclaredRef(TypedDict, total=False):
    ref_type: str
    ref_id: str
    version: str | None


class ResolvedRef(TypedDict, total=False):
    """A resolved reference with validation metadata."""
    ref_type: str
    ref_id: str
    version: str | None
    event_index: int           # Position in stream (for ordering)
    event_digest: str          # Digest of referenced event (for replay verification)
    event_kind: str            # Kind of resolved event (INTENT, EXECUTION, etc.)
    admitted_for: str          # "governance" | "execution_only"
    content: str               # Extracted content from event (for prompt building)


class NormalizationRecord(TypedDict, total=False):
    """Record of boundary normalization applied to context request."""
    applied_rules: list[str]           # Rules that were applied
    boundary_version: str              # Gateway boundary version
    config_digest: str                 # Digest of context config (for replay)
    expansion_reason: str | None       # Why expansion occurred (if any)


class RetrievalSpec(TypedDict, total=False):
    declared_refs: list[DeclaredRef]           # What client requested
    resolved_refs: list[ResolvedRef]           # What boundary resolved (NEW)
    normalization: NormalizationRecord         # What boundary did (NEW)


class AssemblyRules(TypedDict, total=False):
    schema_version: str
    ordering: str
    limits: Mapping[str, Any]


class ContextSpec(TypedDict):
    identity: ContextIdentity
    intent: IntentSpec
    retrieval: RetrievalSpec
    assembly_rules: AssemblyRules


class AssembledContext(TypedDict, total=False):
    model_messages: list[dict[str, Any]]
    assembled_from: list[ResolvedRef]          # Changed from DeclaredRef to ResolvedRef
    normative_input_digests: list[str]         # Digests of INTENT payloads used (NEW)
    warnings: list[str]


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonical_json_bytes(value: Any) -> bytes:
    """
    Canonical JSON: sorted keys, stable separators, UTF-8 bytes, NaN/Infinity rejected,
    non-JSON types rejected via canonicalize_value.
    """
    canonical = canonicalize_value(value)
    return json_dumps(canonical).encode("utf-8")


def normalize_sha256_hex(value: str) -> str:
    return value if value.startswith("sha256:") else f"sha256:{value}"


def decision_digest(decision: Mapping[str, Any]) -> str:
    # Only normative fields count toward the digest.
    required_fields = {
        "policy",
        "assembly_digest",
        "context_digest",
        "result",
        "reasons",
        "transforms",
    }
    missing = [f for f in required_fields if f not in decision]
    if missing:
        raise ValueError(f"DecisionNormative missing fields: {', '.join(missing)}")
    filtered = _strip_obs(decision)
    normative = _normalize_decision(filtered)
    canonical_bytes = canonical_json_bytes(normative)
    return normalize_sha256_hex(_sha256_hex(canonical_bytes))


def context_digest(spec: Mapping[str, Any], assembled: Mapping[str, Any]) -> str:
    normalized_spec = _normalize_context_spec(_strip_obs(spec))
    normalized_assembled = _normalize_assembled_context(_strip_obs(assembled))
    payload = {"context_spec": normalized_spec, "assembled_context": normalized_assembled}
    canonical_bytes = canonical_json_bytes(payload)
    return normalize_sha256_hex(_sha256_hex(canonical_bytes))


def canonical_json_without_obs(value: Mapping[str, Any]) -> str:
    if "_obs" in value:
        filtered = dict(value)
        filtered.pop("_obs", None)
    else:
        filtered = value
    canonical = canonicalize_value(filtered)
    return json_dumps(canonical)


def _sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


@dataclass(frozen=True)
class DecisionDigests:
    decision_digest: str
    canonical_json: str


def _strip_obs(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if "_obs" not in value:
        return value
    filtered = dict(value)
    filtered.pop("_obs", None)
    return filtered


def _normalize_decision(decision: Mapping[str, Any]) -> DecisionNormative:
    policy = decision.get("policy")
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be an object with policy_id and policy_version")
    policy_id = policy.get("policy_id")
    policy_version = policy.get("policy_version")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError("policy.policy_id must be a non-empty string")
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise ValueError("policy.policy_version must be a non-empty string")
    assembly_digest_value = decision.get("assembly_digest")
    if assembly_digest_value is not None:
        if not isinstance(assembly_digest_value, str) or not assembly_digest_value.strip():
            raise ValueError("assembly_digest must be a non-empty string or null")
        assembly_digest_value = normalize_sha256_hex(assembly_digest_value.strip())

    context_digest_value = decision.get("context_digest")
    if context_digest_value is not None:
        if not isinstance(context_digest_value, str) or not context_digest_value.strip():
            raise ValueError("context_digest must be a non-empty string or null")
        context_digest_value = normalize_sha256_hex(context_digest_value.strip())
    result = decision.get("result")
    if result not in ("ALLOW", "DENY"):
        raise ValueError("result must be ALLOW or DENY")

    reasons_raw = decision.get("reasons") or []
    if not isinstance(reasons_raw, list):
        raise ValueError("reasons must be a list")
    norm_reasons: list[DecisionReason] = []
    for item in reasons_raw:
        if not isinstance(item, Mapping):
            raise ValueError("reason entries must be objects")
        code = item.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("reason.code must be a non-empty string")
        reason: DecisionReason = {"code": code.strip()}
        params = item.get("params")
        if params is not None:
            if not isinstance(params, Mapping):
                raise ValueError("reason.params must be an object")
            reason["params"] = dict(params)
        norm_reasons.append(reason)
    # Canonical ordering for digest determinism.
    norm_reasons.sort(key=lambda r: (r["code"], json_dumps(canonicalize_value(r.get("params", {})))))

    transforms_raw = decision.get("transforms") or []
    if not isinstance(transforms_raw, list):
        raise ValueError("transforms must be a list")
    norm_transforms: list[DecisionTransform] = []
    for item in transforms_raw:
        if not isinstance(item, Mapping):
            raise ValueError("transform entries must be objects")
        op = item.get("op")
        target = item.get("target")
        if not isinstance(op, str) or not op.strip():
            raise ValueError("transform.op must be a non-empty string")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("transform.target must be a non-empty string")
        transform: DecisionTransform = {"op": op.strip(), "target": target.strip()}
        params = item.get("params")
        if params is not None:
            if not isinstance(params, Mapping):
                raise ValueError("transform.params must be an object")
            transform["params"] = dict(params)
        norm_transforms.append(transform)
    # Canonical ordering for digest determinism.
    norm_transforms.sort(
        key=lambda t: (t["op"], t["target"], json_dumps(canonicalize_value(t.get("params", {})))))

    return {
        "policy": {"policy_id": policy_id.strip(), "policy_version": policy_version.strip()},
        "assembly_digest": assembly_digest_value,
        "context_digest": context_digest_value,
        "result": result,
        "reasons": norm_reasons,
        "transforms": norm_transforms,
    }


def _normalize_declared_refs(refs: list[Mapping[str, Any]]) -> list[DeclaredRef]:
    normalized: list[DeclaredRef] = []
    for item in refs:
        if not isinstance(item, Mapping):
            raise ValueError("declared_refs entries must be objects")
        ref_type = item.get("ref_type")
        ref_id = item.get("ref_id")
        version = item.get("version")
        if not isinstance(ref_type, str) or not ref_type.strip():
            raise ValueError("ref_type must be a non-empty string")
        if not isinstance(ref_id, str) or not ref_id.strip():
            raise ValueError("ref_id must be a non-empty string")
        norm: DeclaredRef = {"ref_type": ref_type.strip(), "ref_id": ref_id.strip()}
        if version is not None:
            norm["version"] = str(version)
        normalized.append(norm)
    normalized.sort(key=lambda r: (r["ref_type"], r["ref_id"], r.get("version") or ""))
    return normalized


def _normalize_resolved_refs(refs: list[Mapping[str, Any]]) -> list[ResolvedRef]:
    """Normalize resolved refs with additional metadata fields."""
    normalized: list[ResolvedRef] = []
    for item in refs:
        if not isinstance(item, Mapping):
            continue
        ref_type = item.get("ref_type")
        ref_id = item.get("ref_id")
        if not isinstance(ref_type, str) or not isinstance(ref_id, str):
            continue
        norm: ResolvedRef = {
            "ref_type": ref_type.strip(),
            "ref_id": ref_id.strip(),
        }
        if item.get("version") is not None:
            norm["version"] = str(item["version"])
        if isinstance(item.get("event_index"), int):
            norm["event_index"] = item["event_index"]
        if isinstance(item.get("event_digest"), str):
            norm["event_digest"] = item["event_digest"].strip()
        if isinstance(item.get("admitted_for"), str):
            norm["admitted_for"] = item["admitted_for"].strip()
        normalized.append(norm)
    # Sort by event_index if present, otherwise by ref_id
    normalized.sort(key=lambda r: (r.get("event_index", 0), r["ref_type"], r["ref_id"]))
    return normalized


def _normalize_normalization_record(record: Mapping[str, Any] | None) -> NormalizationRecord:
    """Normalize the normalization record for canonical digest."""
    if not isinstance(record, Mapping):
        return {"applied_rules": [], "boundary_version": "unknown", "config_digest": "unknown"}
    
    applied_rules = record.get("applied_rules") or []
    if not isinstance(applied_rules, list):
        applied_rules = []
    
    boundary_version = record.get("boundary_version")
    if not isinstance(boundary_version, str):
        boundary_version = "unknown"
    
    config_digest = record.get("config_digest")
    if not isinstance(config_digest, str):
        config_digest = "unknown"
    
    normalized: NormalizationRecord = {
        "applied_rules": sorted([str(r).strip() for r in applied_rules]),
        "boundary_version": boundary_version.strip(),
        "config_digest": config_digest.strip(),
    }
    
    expansion_reason = record.get("expansion_reason")
    if isinstance(expansion_reason, str) and expansion_reason.strip():
        normalized["expansion_reason"] = expansion_reason.strip()
    
    return normalized


def _normalize_context_spec(spec: Mapping[str, Any]) -> ContextSpec:
    identity = spec.get("identity")
    intent = spec.get("intent")
    retrieval = spec.get("retrieval")
    rules = spec.get("assembly_rules")
    if not isinstance(identity, Mapping):
        raise ValueError("identity must be an object")
    if not isinstance(intent, Mapping):
        raise ValueError("intent must be an object")
    if not isinstance(retrieval, Mapping):
        raise ValueError("retrieval must be an object")
    if not isinstance(rules, Mapping):
        raise ValueError("assembly_rules must be an object")

    declared_refs_raw = retrieval.get("declared_refs") or []
    if not isinstance(declared_refs_raw, list):
        raise ValueError("declared_refs must be a list")
    declared_refs = _normalize_declared_refs(declared_refs_raw)

    thread_id = identity.get("thread_id")
    turn_id = identity.get("turn_id")
    parent_turn_id = identity.get("parent_turn_id")
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise ValueError("identity.thread_id must be a non-empty string")
    if not isinstance(turn_id, str) or not turn_id.strip():
        raise ValueError("identity.turn_id must be a non-empty string")
    intent_type = intent.get("intent_type")
    user_input = intent.get("user_input")
    if not isinstance(intent_type, str) or not intent_type.strip():
        raise ValueError("intent.intent_type must be a non-empty string")
    if not isinstance(user_input, str) or not user_input.strip():
        raise ValueError("intent.user_input must be a non-empty string")

    schema_version = rules.get("schema_version")
    ordering = rules.get("ordering")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise ValueError("assembly_rules.schema_version must be a non-empty string")
    if not isinstance(ordering, str) or not ordering.strip():
        raise ValueError("assembly_rules.ordering must be a non-empty string")

    normalized: ContextSpec = {
        "identity": {
            "thread_id": thread_id.strip(),
            "turn_id": turn_id.strip(),
            "parent_turn_id": parent_turn_id if parent_turn_id is None else str(parent_turn_id),
        },
        "intent": {
            "intent_type": intent_type.strip(),
            "user_input": user_input,
        },
        "retrieval": {
            "declared_refs": declared_refs,
            "resolved_refs": _normalize_resolved_refs(retrieval.get("resolved_refs") or []),
            "normalization": _normalize_normalization_record(retrieval.get("normalization")),
        },
        "assembly_rules": {
            "schema_version": schema_version.strip(),
            "ordering": ordering.strip(),
        },
    }
    limits = rules.get("limits")
    if limits is not None:
        if not isinstance(limits, Mapping):
            raise ValueError("assembly_rules.limits must be an object when provided")
        normalized["assembly_rules"]["limits"] = dict(limits)
    return normalized


def _normalize_assembled_context(assembled: Mapping[str, Any]) -> AssembledContext:
    model_messages = assembled.get("model_messages")
    assembled_from = assembled.get("assembled_from") or []
    warnings = assembled.get("warnings")
    if model_messages is None:
        model_messages = []
    if not isinstance(model_messages, list):
        raise ValueError("assembled_context.model_messages must be a list")
    if not isinstance(assembled_from, list):
        raise ValueError("assembled_context.assembled_from must be a list")
    normalized_from = _normalize_resolved_refs(assembled_from)
    
    normative_input_digests = assembled.get("normative_input_digests") or []
    if not isinstance(normative_input_digests, list):
        normative_input_digests = []
    
    normalized: AssembledContext = {
        "model_messages": list(model_messages),
        "assembled_from": normalized_from,
        "normative_input_digests": sorted([str(d).strip() for d in normative_input_digests]),
    }
    if warnings is not None:
        if not isinstance(warnings, list):
            raise ValueError("assembled_context.warnings must be a list when provided")
        normalized["warnings"] = list(warnings)
    return normalized
