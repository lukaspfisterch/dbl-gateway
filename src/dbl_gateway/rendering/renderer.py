from __future__ import annotations

import hashlib
from typing import Any

from ..contracts import AssembledContext, canonical_json_bytes
from .models import RenderResult
from .specs.delta_v1 import render_delta_v1, build_manifest_delta_v1


def render_provider_payload(
    *,
    assembled_context: AssembledContext,
    task: str | None,
    spec: str = "render.delta_v1",
) -> RenderResult:
    if spec == "render.delta_v1":
        provider_payload = render_delta_v1(assembled_context=assembled_context, task=task)
        manifest = build_manifest_delta_v1(assembled_context=assembled_context, task=task)
    else:
        raise ValueError(f"unsupported render spec: {spec}")

    digest = hashlib.sha256(canonical_json_bytes(provider_payload)).hexdigest()
    render_digest = f"sha256:{digest}"
    return RenderResult(
        provider_payload=provider_payload,
        render_digest=render_digest,
        render_manifest=manifest,
    )
