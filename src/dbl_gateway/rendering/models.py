from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RenderResult:
    provider_payload: dict[str, Any]
    render_digest: str
    render_manifest: dict[str, Any]
