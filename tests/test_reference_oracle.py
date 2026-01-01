from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from dbl_gateway.app import create_app
from dbl_gateway.wire_contract import INTERFACE_VERSION
from dbl_reference.canon import canon_bytes
from dbl_reference.digest import sha256_label

sys.path.insert(0, str(Path(__file__).parent))


def _authoritative_digest(authoritative_input: dict) -> str:
    return sha256_label(canon_bytes(authoritative_input))


def _to_reference_event(event: dict, intents: dict[str, dict]) -> dict:
    kind = event.get("kind")
    correlation_id = event.get("correlation_id")
    payload = event.get("payload")
    if kind == "DECISION" and isinstance(payload, dict):
        intent_payload = intents.get(correlation_id, {})
        policy_version_raw = payload.get("policy_version", 0)
        try:
            policy_version = int(policy_version_raw)
        except (TypeError, ValueError):
            policy_version = 0
        payload = {
            "decision": payload.get("decision"),
            "policy_version": policy_version,
            "authoritative_digest": _authoritative_digest(intent_payload),
            "rationale": {},
        }
    return {
        "event_id": event.get("index"),
        "kind": kind,
        "correlation_id": correlation_id,
        "payload": payload,
    }


def _write_jsonl(path: Path, events: list[dict]) -> None:
    intents = {}
    for event in events:
        if event.get("kind") == "INTENT" and event.get("correlation_id"):
            payload = event.get("payload")
            if isinstance(payload, dict):
                intents[str(event.get("correlation_id"))] = payload
    mapped = [
        _to_reference_event(e, intents) for e in events if e.get("index") is not None
    ]
    lines = [
        json.dumps(e, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        for e in mapped
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _python_executable() -> str:
    venv = os.getenv("VIRTUAL_ENV", "")
    if venv:
        candidate = Path(venv) / "Scripts" / "python.exe"
        if candidate.exists():
            return str(candidate)
    return sys.executable


def test_snapshot_is_reference_replayable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    monkeypatch.setenv("DBL_GATEWAY_POLICY_MODULE", "policy_stub")
    monkeypatch.setenv("DBL_GATEWAY_POLICY_OBJECT", "policy")
    app = create_app()
    with TestClient(app) as client:
        r = client.post(
            "/ingress/intent",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {
                    "stream_id": "default",
                    "lane": "user_chat",
                    "actor": "user",
                    "intent_type": "chat.message",
                    "payload": {"message": "hello"},
                },
            },
        )
        assert r.status_code in (200, 201, 202)

        snap = client.get("/snapshot", params={"limit": 500, "offset": 0})
        assert snap.status_code == 200
        events = snap.json().get("events", [])

    path = tmp_path / "events.jsonl"
    _write_jsonl(path, events)

    proc = subprocess.run(
        [
            _python_executable(),
            "-m",
            "dbl_reference.cli",
            "--mode",
            "validate",
            "--input",
            str(path),
            "--digest",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("sha256:")
    assert proc.stderr == ""
