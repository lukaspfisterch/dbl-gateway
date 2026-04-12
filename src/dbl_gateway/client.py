from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx


class GatewayClient:
    """Small typed wrapper over the raw gateway HTTP surfaces."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.Client(base_url=self.base_url, timeout=timeout)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def send_intent(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        response = self._client.post("/ingress/intent", json=dict(envelope))
        response.raise_for_status()
        return response.json()

    def get_snapshot(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        stream_id: str = "default",
        lane: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "stream_id": stream_id,
        }
        if lane is not None:
            params["lane"] = lane
        response = self._client.get("/snapshot", params=params)
        response.raise_for_status()
        return response.json()

    def replay(self, *, thread_id: str, turn_id: str) -> dict[str, Any]:
        response = self._client.get(
            "/ui/replay",
            params={"thread_id": thread_id, "turn_id": turn_id},
        )
        response.raise_for_status()
        return response.json()
