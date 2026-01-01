from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from dbl_gateway.app import create_app
from dbl_gateway.wire_contract import INTERFACE_VERSION, validate_wire_snapshot


def test_healthz_ok(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_status_requires_role(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DEV_ROLES", "")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/status")
        assert resp.status_code == 403


def test_status_matches_snapshot(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        assert resp.status_code == 200
        status = client.get("/status", headers=headers).json()
        snap = client.get("/snapshot", headers=headers).json()
        assert status["interface_version"] == INTERFACE_VERSION
        assert status["length"] == snap["length"]
        assert status["v_digest"] == snap["v_digest"]
        assert snap["offset"] == 0
        assert snap["limit"] == 200
        assert snap["returned"] == len(snap["events"])
        assert snap["has_more"] is False


def test_snapshot_v_digest_independent_of_paging(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-2", "payload": payload},
            headers=headers,
        )
        snap_a = client.get("/snapshot?limit=1&offset=0", headers=headers).json()
        snap_b = client.get("/snapshot?limit=1&offset=1", headers=headers).json()
        assert snap_a["v_digest"] == snap_b["v_digest"]
        assert snap_a["returned"] == 1
        assert snap_b["returned"] == 1
        assert snap_a["has_more"] is True


def test_snapshot_filters_by_correlation_id(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-2", "payload": payload},
            headers=headers,
        )
        snap = client.get("/snapshot?correlation_id=c-1", headers=headers).json()
        assert snap["length"] == 2
        assert [event["correlation_id"] for event in snap["events"]] == ["c-1"]


def test_snapshot_rejects_blank_correlation_id(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.snapshot.read"}
        resp = client.get("/snapshot?correlation_id= ", headers=headers)
        assert resp.status_code == 400


def test_llm_call_orders_events_and_denies_without_execution(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read"}
        payload = {
            "correlation_id": "llm-1",
            "boundary_version": 1,
            "prompt": " hello ",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10},
        }
        resp = client.post("/llm/call", json=payload, headers=headers)
        assert resp.status_code == 200
        snap = client.get("/snapshot?correlation_id=llm-1", headers=headers).json()
        kinds = [event["kind"] for event in snap["events"]]
        assert kinds == ["INTENT", "DECISION", "EXECUTION"]

        deny_payload = {
            "correlation_id": "llm-2",
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10, "tools_enabled": True},
        }
        deny_resp = client.post("/llm/call", json=deny_payload, headers=headers)
        assert deny_resp.status_code == 403
        deny_snap = client.get("/snapshot?correlation_id=llm-2", headers=headers).json()
        deny_kinds = [event["kind"] for event in deny_snap["events"]]
        assert deny_kinds == ["INTENT", "DECISION"]


def test_llm_call_policy_tenant_allowlist_denies_after_intent(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("GATEWAY_TENANT_ALLOWLIST", "tenant-allowed")
    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read"}
        payload = {
            "correlation_id": "llm-tenant-policy",
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10},
        }
        resp = client.post("/llm/call", json=payload, headers=headers)
        assert resp.status_code == 403
        snap = client.get("/snapshot?correlation_id=llm-tenant-policy", headers=headers).json()
        kinds = [event["kind"] for event in snap["events"]]
        assert kinds == ["INTENT", "DECISION"]


def test_llm_decision_does_not_depend_on_execution_output(tmp_path: Path, monkeypatch) -> None:
    import dbl_gateway.app as gateway_app

    outputs = ["stub_response:first", "stub_response:second"]

    def fake_execute(_input):
        return outputs.pop(0)

    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    monkeypatch.setattr(gateway_app, "_execute_stub", fake_execute)
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10},
        }
        payload["correlation_id"] = "llm-a"
        resp_a = client.post("/llm/call", json=payload, headers=headers)
        assert resp_a.status_code == 200
        payload["correlation_id"] = "llm-b"
        resp_b = client.post("/llm/call", json=payload, headers=headers)
        assert resp_b.status_code == 200
        snap_a = client.get("/snapshot?correlation_id=llm-a", headers=headers).json()
        snap_b = client.get("/snapshot?correlation_id=llm-b", headers=headers).json()
        decision_a = next(e for e in snap_a["events"] if e["kind"] == "DECISION")["payload"]
        decision_b = next(e for e in snap_b["events"] if e["kind"] == "DECISION")["payload"]
        decision_a.pop("_obs", None)
        decision_b.pop("_obs", None)
        assert decision_a == decision_b


def test_llm_intent_digest_stable_for_same_input(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read", "x-request-id": "req-llm-1"}
        payload = {
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10},
        }
        payload["correlation_id"] = "llm-r1"
        resp_a = client.post("/llm/call", json=payload, headers=headers)
        assert resp_a.status_code == 200
        payload["correlation_id"] = "llm-r2"
        resp_b = client.post("/llm/call", json=payload, headers=headers)
        assert resp_b.status_code == 200
        snap_a = client.get("/snapshot?correlation_id=llm-r1", headers=headers).json()
        snap_b = client.get("/snapshot?correlation_id=llm-r2", headers=headers).json()
        intent_a = next(e for e in snap_a["events"] if e["kind"] == "INTENT")["payload"]
        intent_b = next(e for e in snap_b["events"] if e["kind"] == "INTENT")["payload"]
        assert intent_a["intent_digest"] == intent_b["intent_digest"]
        assert intent_a["input_digest"] == intent_b["input_digest"]
        assert intent_a["input_digest"] == intent_a["intent_digest"]


def test_llm_call_rejects_disallowed_tenant_before_intent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_ALLOWED_TENANTS", "tenant-allowed")
    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    db_path = tmp_path / "trail.sqlite"
    app = create_app(db_path)
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read"}
        payload = {
            "correlation_id": "llm-tenant",
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10},
        }
        resp = client.post("/llm/call", json=payload, headers=headers)
        assert resp.status_code == 403
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        assert int(row[0]) == 0
    finally:
        conn.close()


def test_rejects_unknown_event_kind(tmp_path: Path) -> None:
    import dbl_gateway.app as gateway_app

    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app):
        with pytest.raises(HTTPException, match="unsupported event kind"):
            gateway_app._append_event(
                app,
                kind="UNKNOWN",
                correlation_id="c-1",
                payload={"boundary_version": 1, "boundary_config_hash": "unknown"},
            )


def test_get_event_by_index(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 200
        event = client.get("/event/0", headers=headers).json()
        assert event["index"] == 0
        assert event["correlation_id"] == "c-1"


def test_debug_config_requires_role(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/debug/config")
        assert resp.status_code == 403


def test_debug_config_ok(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_DEV_ROLES", "gateway.admin.read")
    monkeypatch.setenv("DBL_GATEWAY_DB", str(tmp_path / "trail.sqlite"))
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/debug/config")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["interface_version"] == INTERFACE_VERSION
        assert payload["store_backend"] == "sqlite"
        assert payload["db_path"] == "trail.sqlite"
        assert payload["db_url_set"] is False
        assert payload["auth_mode"] == "dev"
        assert payload["leader_lock_enabled"] is True
        assert payload["idempotency_enabled"] is False
        assert payload["strict_read_verify"] is False
        assert isinstance(payload["uptime_s"], int)


def test_llm_deny_response_includes_reasons(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_LLM_REQUIRED_ROLE", "gateway.llm.call")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.llm.call,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "prompt": "hello",
            "parameters": {"model": "test", "temperature": 0.2, "max_tokens": 10, "tools_enabled": True},
        }
        resp = client.post("/llm/call", json=payload, headers=headers)
        assert resp.status_code == 403
        data = resp.json()
        assert data["decision"] == "DENY"
        assert "tools_not_allowed" in data["reason_codes"]


def test_request_id_roundtrip(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/healthz", headers={"x-request-id": "req-123"})
        assert resp.headers["x-request-id"] == "req-123"


def test_request_id_generated(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.headers.get("x-request-id", "") != ""


@pytest.mark.parametrize(
    ("endpoint", "roles", "payload"),
    [
        (
            "/ingress/intent",
            "gateway.intent.write",
            {
                "boundary_version": 1,
                "boundary_config_hash": "unknown",
                "input_digest": "sha256:" + "0" * 64,
            },
        ),
        ("/governance/decision", "gateway.decision.write", {"policy_version": 1}),
        (
            "/governance/policy-update",
            "gateway.policy.update",
            {"policy_version": 1, "policy_digest": "sha256:" + "1" * 64},
        ),
        (
            "/governance/boundary-update",
            "gateway.boundary.update",
            {"boundary_version": 2, "boundary_config_hash": "unknown"},
        ),
        (
            "/execution/event",
            "gateway.execution.write",
            {"execution_digest": "sha256:" + "0" * 64},
        ),
        (
            "/proof/artifact",
            "gateway.proof.write",
            {"proof_digest": "sha256:" + "0" * 64},
        ),
    ],
)
def test_write_rejects_wrong_interface_version(
    tmp_path: Path, endpoint: str, roles: str, payload: dict[str, object]
) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": roles}
        resp = client.post(
            endpoint,
            json={
                "interface_version": 999,
                "correlation_id": "c-1",
                "payload": payload,
            },
            headers=headers,
        )
        assert resp.status_code == 400


def test_follower_mode_rejects_writes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_MODE", "follower")
    db_path = tmp_path / "trail.sqlite"
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                idx INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                digest TEXT NOT NULL,
                canon_len INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    app = create_app(db_path)
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        assert resp.status_code == 403


def test_idempotency_key_dedupes_appends(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_IDEMPOTENCY", "1")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {
            "x-dev-roles": "gateway.intent.write,gateway.snapshot.read",
            "idempotency-key": "idem-1",
        }
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        first = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        second = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["index"] == second.json()["index"]
        snap = client.get("/snapshot", headers=headers).json()
        assert snap["length"] == 1


def test_idempotency_key_conflict_is_409(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_IDEMPOTENCY", "1")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write", "idempotency-key": "idem-2"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        first = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert first.status_code == 200
        payload["input_digest"] = "sha256:" + "1" * 64
        second = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert second.status_code == 409


def test_oidc_tenant_allowlist_rejects(tmp_path: Path, monkeypatch) -> None:
    import dbl_gateway.auth as auth

    async def fake_authenticate(headers, cfg):
        return {
            "oid": "actor-1",
            "tid": "tenant-bad",
            "roles": ["gateway.snapshot.read"],
        }

    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_ISSUER", "https://example.invalid/issuer")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_AUDIENCE", "aud")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_JWKS_URL", "https://example.invalid/jwks")
    monkeypatch.setenv("DBL_GATEWAY_ALLOWED_TENANTS", "tenant-good")
    monkeypatch.setattr(auth, "_authenticate_oidc", fake_authenticate)

    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot", headers={"authorization": "Bearer token"})
        assert resp.status_code == 403


def test_oidc_role_map_allows_snapshot(tmp_path: Path, monkeypatch) -> None:
    import dbl_gateway.auth as auth

    async def fake_authenticate(headers, cfg):
        return {
            "oid": "actor-1",
            "tid": "tenant-good",
            "roles": ["external.role"],
            "scp": "scope.read",
        }

    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_ISSUER", "https://example.invalid/issuer")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_AUDIENCE", "aud")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_JWKS_URL", "https://example.invalid/jwks")
    monkeypatch.setenv("DBL_GATEWAY_ALLOWED_TENANTS", "*")
    monkeypatch.setenv("DBL_GATEWAY_ROLE_CLAIMS", "roles,scp")
    monkeypatch.setenv(
        "DBL_GATEWAY_ROLE_MAP",
        '{"scope.read":["gateway.snapshot.read"],"external.role":"gateway.intent.write"}',
    )
    monkeypatch.setattr(auth, "_authenticate_oidc", fake_authenticate)

    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot", headers={"authorization": "Bearer token"})
        assert resp.status_code == 200


def test_leader_lock_rejects_second_instance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_LEADER_LOCK", "1")
    db_path = tmp_path / "trail.sqlite"
    lock_path = db_path.parent / "trail.leader.lock"
    client = None
    try:
        app = create_app(db_path)
        client = TestClient(app)
        client.__enter__()
        with pytest.raises(RuntimeError, match="leader lock already held"):
            TestClient(create_app(db_path)).__enter__()
    finally:
        if client is not None:
            client.__exit__(None, None, None)
        if lock_path.exists():
            lock_path.unlink()


def test_append_only_changes_v_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp_a = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        assert resp_a.status_code == 200
        snap_a = client.get("/snapshot", headers=headers).json()
        resp_b = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-2", "payload": payload}, headers=headers
        )
        assert resp_b.status_code == 200
        snap_b = client.get("/snapshot", headers=headers).json()
        assert snap_a["length"] == 1
        assert snap_b["length"] == 2
        assert snap_a["v_digest"] != snap_b["v_digest"]


def test_event_digest_excludes_obs_but_v_digest_changes_on_append(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        base_payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "1" * 64,
        }
        payload_a = dict(base_payload)
        payload_a["_obs"] = {"note": "a", "meta": {"x": 1, "y": ["a", "b"]}}
        payload_b = dict(base_payload)
        payload_b["_obs"] = {"note": "b", "meta": {"x": 2, "y": ["c"]}}
        resp_a = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload_a}, headers=headers
        )
        snap_a = client.get("/snapshot", headers=headers).json()
        resp_b = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload_b}, headers=headers
        )
        snap_b = client.get("/snapshot", headers=headers).json()
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        assert resp_a.json()["digest"] == resp_b.json()["digest"]
        assert resp_a.json()["canon_len"] == resp_b.json()["canon_len"]
        assert snap_a["v_digest"] != snap_b["v_digest"]


def test_identity_validation_missing_fields(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        resp = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": {}}, headers=headers
        )
        assert resp.status_code == 400


def test_identity_validation_rejects_invalid_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "not-a-digest",
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 400


def test_boundary_config_hash_accepts_unknown(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 200


def test_boundary_config_hash_accepts_opaque(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "build-2025.12.31+abc",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 200


def test_boundary_config_hash_rejects_blank(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 400


def test_boundary_config_hash_rejects_whitespace(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "   ",
            "input_digest": "sha256:" + "0" * 64,
        }
        resp = client.post(
            "/ingress/intent",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload},
            headers=headers,
        )
        assert resp.status_code == 400


def test_execution_requires_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.execution.write"}
        resp = client.post(
            "/execution/event",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {},
            },
            headers=headers,
        )
        assert resp.status_code == 400


def test_execution_accepts_optional_decision_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.execution.write"}
        resp = client.post(
            "/execution/event",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {
                    "execution_digest": "sha256:" + "1" * 64,
                    "decision_digest": "sha256:" + "2" * 64,
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200


def test_proof_requires_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.proof.write"}
        resp = client.post(
            "/proof/artifact",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {},
            },
            headers=headers,
        )
        assert resp.status_code == 400


def test_proof_rejects_blank_kind(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.proof.write"}
        resp = client.post(
            "/proof/artifact",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {
                    "proof_digest": "sha256:" + "3" * 64,
                    "proof_kind": " ",
                },
            },
            headers=headers,
        )
        assert resp.status_code == 400


def test_proof_accepts_optional_fields(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.proof.write"}
        resp = client.post(
            "/proof/artifact",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {
                    "proof_digest": "sha256:" + "4" * 64,
                    "decision_digest": "sha256:" + "5" * 64,
                    "proof_kind": "verification",
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200


def test_identity_validation_rejects_non_int_version(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.decision.write"}
        resp = client.post(
            "/governance/decision",
            json={
                "interface_version": INTERFACE_VERSION,
                "correlation_id": "c-1",
                "payload": {"policy_version": "1"},
            },
            headers=headers,
        )
        assert resp.status_code == 400


def test_wire_contract_rejects_wrong_interface_version(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        snap = client.get("/snapshot", headers=headers).json()
        snap["interface_version"] = 999
        import pytest

        with pytest.raises(ValueError, match="unsupported interface_version"):
            validate_wire_snapshot(snap)


def test_norm_snapshot_includes_commit_kinds(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {
            "x-dev-roles": (
                "gateway.intent.write,gateway.decision.write,"
                "gateway.policy.update,gateway.boundary.update,gateway.snapshot.read"
            )
        }
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        client.post(
            "/governance/decision",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": {"policy_version": 1}},
            headers=headers,
        )
        client.post(
            "/governance/policy-update",
            json={"interface_version": INTERFACE_VERSION, 
                "correlation_id": "c-1",
                "payload": {"policy_version": 1, "policy_digest": "sha256:" + "1" * 64},
            },
            headers=headers,
        )
        client.post(
            "/governance/boundary-update",
            json={"interface_version": INTERFACE_VERSION, 
                "correlation_id": "c-1",
                "payload": {"boundary_version": 2, "boundary_config_hash": "unknown"},
            },
            headers=headers,
        )
        norm = client.get("/snapshot/norm", headers=headers).json()
        assert all(
            event["kind"]
            in {"DECISION", "POLICY_UPDATE_DECISION", "BOUNDARY_UPDATE_DECISION"}
            for event in norm["events"]
        )


def test_decision_accepts_optional_policy_digest(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.decision.write"}
        resp = client.post(
            "/governance/decision",
            json={"interface_version": INTERFACE_VERSION, 
                "correlation_id": "c-1",
                "payload": {
                    "policy_version": 1,
                    "policy_digest": "sha256:" + "2" * 64,
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200

def test_norm_snapshot_v_digest_matches_snapshot(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        headers = {"x-dev-roles": "gateway.intent.write,gateway.decision.write,gateway.snapshot.read"}
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        client.post(
            "/governance/decision",
            json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": {"policy_version": 1}},
            headers=headers,
        )
        snap = client.get("/snapshot", headers=headers).json()
        norm = client.get("/snapshot/norm", headers=headers).json()
        assert snap["v_digest"] == norm["v_digest"]


def test_oidc_config_incomplete_is_401(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot")
        assert resp.status_code == 401


def test_oidc_missing_bearer_is_401(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_ISSUER", "https://example.invalid/issuer")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_AUDIENCE", "aud")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_JWKS_URL", "https://example.invalid/jwks")
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot")
        assert resp.status_code == 401


def test_oidc_refresh_on_kid_miss(tmp_path: Path, monkeypatch) -> None:
    import dbl_gateway.auth as auth
    jose = pytest.importorskip("jose")
    from jose import jwt as jose_jwt
    from jose import jwk as jose_jwk

    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_ISSUER", "https://example.invalid/issuer")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_AUDIENCE", "aud")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_JWKS_URL", "https://example.invalid/jwks")

    calls = {"count": 0}

    async def fake_get_jwks(url: str, force: bool = False):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"keys": [{"kid": "old", "kty": "RSA"}]}
        return {"keys": [{"kid": "match", "kty": "RSA"}]}

    monkeypatch.setattr(auth, "_get_jwks", fake_get_jwks)
    monkeypatch.setattr(jose_jwt, "get_unverified_header", lambda token: {"kid": "match", "alg": "RS256"})
    monkeypatch.setattr(jose_jwk, "construct", lambda jwk_data: jwk_data)
    monkeypatch.setattr(
        jose_jwt,
        "decode",
        lambda token, key, algorithms, issuer, audience, options, leeway: {
            "oid": "actor-1",
            "tid": "tenant-ok",
            "roles": ["gateway.snapshot.read"],
        },
    )

    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot", headers={"authorization": "Bearer token"})
        assert resp.status_code == 200
    assert calls["count"] == 2


def test_oidc_rejects_future_nbf(tmp_path: Path, monkeypatch) -> None:
    import dbl_gateway.auth as auth
    jose = pytest.importorskip("jose")
    from jose import jwt as jose_jwt
    from jose import jwk as jose_jwk
    from jose.exceptions import JWTError

    monkeypatch.setenv("DBL_GATEWAY_AUTH_MODE", "oidc")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_ISSUER", "https://example.invalid/issuer")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_AUDIENCE", "aud")
    monkeypatch.setenv("DBL_GATEWAY_OIDC_JWKS_URL", "https://example.invalid/jwks")

    async def fake_get_jwks(url: str, force: bool = False):
        return {"keys": [{"kid": "match", "kty": "RSA"}]}

    monkeypatch.setattr(auth, "_get_jwks", fake_get_jwks)
    monkeypatch.setattr(jose_jwt, "get_unverified_header", lambda token: {"kid": "match", "alg": "RS256"})
    monkeypatch.setattr(jose_jwk, "construct", lambda jwk_data: jwk_data)

    seen = {"options": None, "leeway": None}

    def fake_decode(token, key, algorithms, issuer, audience, options, leeway):
        seen["options"] = dict(options)
        seen["leeway"] = leeway
        raise JWTError("nbf")

    monkeypatch.setattr(jose_jwt, "decode", fake_decode)

    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        resp = client.get("/snapshot", headers={"authorization": "Bearer token"})
        assert resp.status_code == 401

    assert seen["options"]["verify_nbf"] is True
    assert seen["options"]["verify_iat"] is True
    assert seen["leeway"] == 60


def test_role_missing_is_forbidden(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        headers = {"x-dev-roles": "gateway.snapshot.read"}
        resp = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        assert resp.status_code == 403


def test_actor_attribution_on_intent(tmp_path: Path) -> None:
    app = create_app(tmp_path / "trail.sqlite")
    with TestClient(app) as client:
        payload = {
            "boundary_version": 1,
            "boundary_config_hash": "unknown",
            "input_digest": "sha256:" + "0" * 64,
        }
        headers = {
            "x-dev-roles": "gateway.intent.write,gateway.snapshot.read",
            "x-dev-actor": "alice",
            "x-dev-tenant": "t-1",
            "x-dev-client": "c-1",
        }
        resp = client.post(
            "/ingress/intent", json={"interface_version": INTERFACE_VERSION, "correlation_id": "c-1", "payload": payload}, headers=headers
        )
        assert resp.status_code == 200
        snap = client.get("/snapshot", headers=headers).json()
        payload_out = snap["events"][0]["payload"]
        obs = payload_out.get("_obs", {})
        assert obs["actor_id"] == "alice"
        assert obs["actor_tenant_id"] == "t-1"
        assert obs["actor_client_id"] == "c-1"
        assert "actor_id" not in payload_out
