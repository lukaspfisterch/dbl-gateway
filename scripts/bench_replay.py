"""bench_replay.py — Empirical validation of A3 (Append-Only Accountability).

Generates N intents through dbl-gateway, then replays every DECISION event
and verifies that recomputed digests match the stored ones.  This is the
quantitative evidence for Claim 3 (Replay Equivalence) in the paper.

Phase 3 (policy-diff) replays the same INTENT inputs from V against a
stricter policy (v2) and counts ALLOW/DENY flips — demonstrating that
governance is deterministic but policy-exchangeable, without re-execution.

Usage:
    # Start gateway with stub provider first:
    #   STUB_MODE=scenario python -m dbl_gateway
    python scripts/bench_replay.py --turns 100
    python scripts/bench_replay.py --turns 1000 --report markdown
    python scripts/bench_replay.py --turns 100 --policy-diff
    python scripts/bench_replay.py --turns 100 --policy-diff --db data/events.db
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from pathlib import Path

import httpx
from dbl_gateway.demo_agent import DemoStep, active_provider_model, build_envelope


# ── Traffic patterns ─────────────────────────────────────────────────

def _bench_steps() -> list[DemoStep]:
    """Rotating mix of ALLOW and DENY payloads for traffic generation."""
    return [
        DemoStep(
            name="normal",
            description="Normal message (ALLOW expected).",
            expected="ALLOW->EXECUTION",
            payload={"message": "Bench turn: normal request."},
        ),
        DemoStep(
            name="with-tools",
            description="Message with declared tools and budget.",
            expected="ALLOW->EXECUTION",
            payload={
                "message": "Bench turn: tools and budget.",
                "declared_tools": ["web.search"],
                "tool_scope": "strict",
                "budget": {"max_tokens": 512, "max_duration_ms": 8000},
            },
        ),
        DemoStep(
            name="follow-up",
            description="Simple follow-up.",
            expected="ALLOW->EXECUTION",
            payload={"message": "Bench turn: follow-up."},
        ),
        DemoStep(
            name="another",
            description="Another normal turn.",
            expected="ALLOW->EXECUTION",
            payload={"message": "Bench turn: another request."},
        ),
        DemoStep(
            name="deny-shape",
            description="Non-scalar extension value — v2 policy denies this shape.",
            expected="ALLOW (v1) / DENY (v2)",
            payload={
                "message": "Bench turn: has nested extension.",
                "inputs": {
                    "principal_id": "bench-user",
                    "extensions": {"config": {"nested": True}},
                },
            },
        ),
    ]


# ── Results ──────────────────────────────────────────────────────────

@dataclass
class TurnResult:
    turn_id: str
    correlation_id: str
    decision: str  # ALLOW or DENY
    events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ReplayResult:
    turn_id: str
    decision_index: int
    match: bool
    stored_digest: str
    recomputed_digest: str
    replay_ms: float


@dataclass
class PolicyDiffEntry:
    turn_id: str
    v1_outcome: str  # ALLOW or DENY
    v2_outcome: str
    flipped: bool


@dataclass
class PolicyDiffReport:
    total: int
    allow_to_deny: int
    deny_to_allow: int
    unchanged: int
    v1_id: str
    v2_id: str


@dataclass
class BenchReport:
    turns_generated: int
    decisions_total: int
    allow_count: int
    deny_count: int
    replay_total: int
    replay_match: int
    replay_mismatch: int
    replay_error: int
    total_replay_ms: float
    policy_diff: PolicyDiffReport | None = None
    errors: list[str] = field(default_factory=list)


# ── HTTP helpers ─────────────────────────────────────────────────────

def _headers(token: str) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if token.strip():
        h["Authorization"] = f"Bearer {token.strip()}"
    return h


def _require_ok(resp: httpx.Response, ctx: str) -> None:
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:300]
        raise SystemExit(f"{ctx} failed: {exc} body={body!r}") from exc


def _preflight(client: httpx.Client, token: str) -> str:
    health = client.get("/healthz", headers=_headers(token))
    _require_ok(health, "GET /healthz")
    caps = client.get("/capabilities", headers=_headers(token))
    _require_ok(caps, "GET /capabilities")
    active = active_provider_model(caps.json())
    if active is None:
        raise SystemExit("No active provider/model. Start gateway with stub provider first.")
    return active[1]


def _wait_for_turn(
    client: httpx.Client,
    *,
    token: str,
    stream_id: str,
    correlation_id: str,
    search_offset: int = 0,
    timeout_s: float = 30.0,
    poll_s: float = 0.3,
) -> tuple[list[dict[str, Any]], int]:
    """Poll until DECISION (+ optional EXECUTION) events appear for this correlation_id.

    Returns (events, new_offset) so callers can track the high-water mark.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snap = client.get(
            "/ui/snapshot",
            params={"stream_id": stream_id, "limit": 100, "offset": search_offset},
            headers=_headers(token),
        )
        _require_ok(snap, "GET /ui/snapshot")
        snap_body = snap.json()
        total_length = snap_body.get("length", 0)
        all_events = snap_body.get("events") or []
        events = [
            e for e in all_events
            if e.get("correlation_id") == correlation_id
        ]
        has_decision = any(e.get("kind") == "DECISION" for e in events)
        if not has_decision:
            time.sleep(poll_s)
            continue
        # For DENY turns we're done at DECISION; for ALLOW, wait for EXECUTION
        decision_result = None
        for e in events:
            if e.get("kind") == "DECISION":
                p = e.get("payload") or {}
                decision_result = p.get("result") or p.get("decision")
        new_offset = max(search_offset, total_length - 1) if total_length else search_offset
        if decision_result == "DENY":
            return events, new_offset
        if any(e.get("kind") == "EXECUTION" for e in events):
            return events, new_offset
        time.sleep(poll_s)
    raise SystemExit(f"Timeout waiting for turn correlation_id={correlation_id}")


# ── Phase 1: Generate ───────────────────────────────────────────────

def generate(
    client: httpx.Client,
    *,
    token: str,
    model_id: str,
    n_turns: int,
    stream_id: str,
    lane: str,
    actor: str,
) -> list[TurnResult]:
    steps = _bench_steps()
    thread_id = f"bench-{uuid.uuid4().hex[:8]}"
    results: list[TurnResult] = []
    parent_turn_id: str | None = None
    offset = 0  # high-water mark for snapshot polling

    print(f"[generate] {n_turns} turns, thread={thread_id}")
    for i in range(1, n_turns + 1):
        step = steps[(i - 1) % len(steps)]
        turn_id = f"turn-{i}"
        envelope = build_envelope(
            step=step,
            requested_model_id=model_id,
            stream_id=stream_id,
            lane=lane,
            actor=actor,
            thread_id=thread_id,
            turn_id=turn_id,
            parent_turn_id=parent_turn_id,
        )
        resp = client.post(
            "/ingress/intent",
            headers=_headers(token),
            json=envelope,
        )
        _require_ok(resp, f"POST /ingress/intent (turn {i})")
        ack = resp.json()
        correlation_id = str(ack.get("correlation_id") or envelope["correlation_id"])

        events, offset = _wait_for_turn(
            client,
            token=token,
            stream_id=stream_id,
            correlation_id=correlation_id,
            search_offset=offset,
        )
        decision = "UNKNOWN"
        for e in events:
            if e.get("kind") == "DECISION":
                p = e.get("payload") or {}
                decision = str(p.get("result") or p.get("decision") or "UNKNOWN")

        results.append(TurnResult(
            turn_id=turn_id,
            correlation_id=correlation_id,
            decision=decision,
            events=events,
        ))
        parent_turn_id = turn_id

        if i % 50 == 0 or i == n_turns:
            print(f"  [{i}/{n_turns}] last={step.name} decision={decision}")

    return results


# ── Phase 2: Replay ─────────────────────────────────────────────────

def replay(
    client: httpx.Client,
    *,
    token: str,
    turn_results: list[TurnResult],
) -> list[ReplayResult]:
    """Replay every DECISION via /ui/replay and verify digest match."""
    # Collect (thread_id, turn_id, decision_index) from generated events
    replay_targets: list[tuple[str, str, int]] = []
    for tr in turn_results:
        for e in tr.events:
            if e.get("kind") == "DECISION":
                thread_id = e.get("thread_id", "")
                turn_id = e.get("turn_id", "")
                idx = e.get("index", -1)
                replay_targets.append((thread_id, turn_id, idx))

    print(f"[replay] {len(replay_targets)} DECISION events to verify")
    results: list[ReplayResult] = []

    for i, (thread_id, turn_id, dec_idx) in enumerate(replay_targets, 1):
        t0 = time.perf_counter()
        try:
            resp = client.get(
                "/ui/replay",
                params={"thread_id": thread_id, "turn_id": turn_id},
                headers=_headers(token),
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            _require_ok(resp, f"GET /ui/replay (turn={turn_id})")
            body = resp.json()
            results.append(ReplayResult(
                turn_id=turn_id,
                decision_index=dec_idx,
                match=body.get("match", False),
                stored_digest=body.get("stored_digest", ""),
                recomputed_digest=body.get("recomputed_digest", ""),
                replay_ms=elapsed_ms,
            ))
        except SystemExit:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            results.append(ReplayResult(
                turn_id=turn_id,
                decision_index=dec_idx,
                match=False,
                stored_digest="ERROR",
                recomputed_digest="ERROR",
                replay_ms=elapsed_ms,
            ))
        if i % 50 == 0 or i == len(replay_targets):
            print(f"  [{i}/{len(replay_targets)}] replayed")

    return results


# ── Phase 3: Policy Diff ─────────────────────────────────────────

def _make_v2_policy() -> Any:
    """Stricter policy: denies intents whose extensions contain non-scalar values.

    v1 (allow_all) allows everything.  v2 rejects governance inputs where
    extensions carry nested objects — the same shape violation that a
    production compose policy would catch.  This demonstrates that
    governance is deterministic but policy-exchangeable: same V, different
    policy → different outcomes, without re-execution.
    """
    from dataclasses import dataclass as _dc
    from dbl_policy.model import (
        DecisionOutcome as _O,
        PolicyContext as _Ctx,
        PolicyDecision as _D,
        PolicyId as _PId,
        PolicyVersion as _PVer,
    )

    @_dc(frozen=True)
    class StrictExtensionsPolicy:
        policy_id: _PId = _PId("bench.strict_extensions")
        policy_version: _PVer = _PVer("2")

        def evaluate(self, context: _Ctx) -> _D:
            inputs = dict(context.inputs) if context.inputs else {}
            # Deny if extensions contain non-scalar values
            extensions = inputs.get("extensions")
            if isinstance(extensions, dict):
                for v in extensions.values():
                    if isinstance(v, (dict, list)):
                        return _D(
                            outcome=_O.DENY,
                            reason_code="shape.non_scalar_extension",
                            policy_id=self.policy_id,
                            policy_version=self.policy_version,
                            tenant_id=context.tenant_id,
                        )
            return _D(
                outcome=_O.ALLOW,
                reason_code="ok",
                policy_id=self.policy_id,
                policy_version=self.policy_version,
                tenant_id=context.tenant_id,
            )

    return StrictExtensionsPolicy()


def policy_diff(
    *,
    db_path: Path,
    turn_results: list[TurnResult],
) -> tuple[list[PolicyDiffEntry], str, str]:
    """Replay INTENT events from V against v1 and v2 policies via direct store access."""
    from dbl_gateway.adapters.policy_adapter_dbl_policy import DblPolicyAdapter, _load_policy
    from dbl_gateway.store.sqlite import SQLiteStore

    store = SQLiteStore(db_path)
    try:
        # v1: the policy that was used during generation
        v1_policy_obj = _load_policy()
        v1 = DblPolicyAdapter(policy=v1_policy_obj)
        v1_id = getattr(v1_policy_obj, "policy_id", "v1")

        # v2: stricter policy
        v2_policy_obj = _make_v2_policy()
        v2 = DblPolicyAdapter(policy=v2_policy_obj)
        v2_id = getattr(v2_policy_obj, "policy_id", "v2")

        # Collect thread_ids from generated turns
        thread_ids: set[str] = set()
        for tr in turn_results:
            for e in tr.events:
                tid = e.get("thread_id", "")
                if tid:
                    thread_ids.add(tid)

        # Read INTENT events from store
        entries: list[PolicyDiffEntry] = []
        for thread_id in sorted(thread_ids):
            timeline = store.timeline(thread_id=thread_id, include_payload=True)
            intent_events = [e for e in timeline if e.get("kind") == "INTENT"]

            for intent_event in intent_events:
                turn_id = intent_event.get("turn_id", "")
                correlation_id = intent_event.get("correlation_id", "")
                authoritative = {
                    "stream_id": intent_event.get("stream_id"),
                    "lane": intent_event.get("lane"),
                    "actor": intent_event.get("actor"),
                    "intent_type": intent_event.get("intent_type"),
                    "correlation_id": correlation_id,
                    "payload": intent_event.get("payload"),
                }
                try:
                    r1 = v1.decide(authoritative)
                    r2 = v2.decide(authoritative)
                except Exception:
                    continue

                entries.append(PolicyDiffEntry(
                    turn_id=turn_id,
                    v1_outcome=r1.decision,
                    v2_outcome=r2.decision,
                    flipped=r1.decision != r2.decision,
                ))
    finally:
        store.close()

    return entries, str(v1_id), str(v2_id)


def build_diff_report(entries: list[PolicyDiffEntry], v1_id: str, v2_id: str) -> PolicyDiffReport:
    a2d = sum(1 for e in entries if e.v1_outcome == "ALLOW" and e.v2_outcome == "DENY")
    d2a = sum(1 for e in entries if e.v1_outcome == "DENY" and e.v2_outcome == "ALLOW")
    unchanged = sum(1 for e in entries if not e.flipped)
    return PolicyDiffReport(
        total=len(entries),
        allow_to_deny=a2d,
        deny_to_allow=d2a,
        unchanged=unchanged,
        v1_id=v1_id,
        v2_id=v2_id,
    )


# ── Report ───────────────────────────────────────────────────────────

def build_report(
    turn_results: list[TurnResult],
    replay_results: list[ReplayResult],
) -> BenchReport:
    allow = sum(1 for t in turn_results if t.decision == "ALLOW")
    deny = sum(1 for t in turn_results if t.decision == "DENY")
    match = sum(1 for r in replay_results if r.match)
    mismatch = sum(1 for r in replay_results if not r.match and r.stored_digest != "ERROR")
    error = sum(1 for r in replay_results if r.stored_digest == "ERROR")
    total_ms = sum(r.replay_ms for r in replay_results)
    errors = []
    for r in replay_results:
        if not r.match:
            errors.append(
                f"  MISMATCH {r.turn_id} idx={r.decision_index}: "
                f"stored={r.stored_digest[:24]}... recomputed={r.recomputed_digest[:24]}..."
            )
    return BenchReport(
        turns_generated=len(turn_results),
        decisions_total=len(replay_results),
        allow_count=allow,
        deny_count=deny,
        replay_total=len(replay_results),
        replay_match=match,
        replay_mismatch=mismatch,
        replay_error=error,
        total_replay_ms=total_ms,
        errors=errors,
    )


def print_report(report: BenchReport, fmt: str = "text") -> None:
    if fmt == "markdown":
        _print_markdown(report)
    elif fmt == "json":
        _print_json(report)
    else:
        _print_text(report)


def _print_text(r: BenchReport) -> None:
    print()
    print("=" * 60)
    print("A3 Empirical Validation — Replay Equivalence")
    print("=" * 60)
    print(f"  Turns generated:       {r.turns_generated}")
    print(f"  DECISION events:       {r.decisions_total}")
    print(f"  ALLOW / DENY:          {r.allow_count} / {r.deny_count}")
    print(f"  Replay digest match:   {r.replay_match}/{r.replay_total}")
    print(f"  Replay mismatch:       {r.replay_mismatch}")
    print(f"  Replay errors:         {r.replay_error}")
    avg = r.total_replay_ms / r.replay_total if r.replay_total else 0
    print(f"  Total replay time:     {r.total_replay_ms:.1f} ms")
    print(f"  Avg replay time:       {avg:.2f} ms/decision")
    print()
    if r.replay_match == r.replay_total and r.replay_total > 0:
        print(f"  PASS: All {r.replay_total} DECISION events reproduced identical")
        print("        digests under replay, confirming A3 (Append-Only Accountability).")
    else:
        print("  FAIL: Digest mismatches detected.")
        for line in r.errors:
            print(line)
    if r.policy_diff:
        d = r.policy_diff
        print()
        print("-" * 60)
        print("Policy Diff (v1 vs v2)")
        print("-" * 60)
        print(f"  v1: {d.v1_id}")
        print(f"  v2: {d.v2_id}")
        print(f"  Total decisions:       {d.total}")
        print(f"  ALLOW -> DENY:         {d.allow_to_deny}")
        print(f"  DENY -> ALLOW:         {d.deny_to_allow}")
        print(f"  Unchanged:             {d.unchanged}")
        print()
        print("  Governance is deterministic but policy-exchangeable:")
        print(f"  {d.allow_to_deny + d.deny_to_allow} decisions flipped outcome")
        print("  without requiring re-execution of any turn.")
    print()


def _print_markdown(r: BenchReport) -> None:
    avg = r.total_replay_ms / r.replay_total if r.replay_total else 0
    print()
    print("| Metric | Value |")
    print("|---|---|")
    print(f"| Events generated | {r.turns_generated * 2 + r.allow_count} |")
    print(f"| DECISION events | {r.decisions_total} |")
    print(f"| ALLOW / DENY ratio | {r.allow_count} / {r.deny_count} |")
    print(f"| Replay time (total) | {r.total_replay_ms:.1f} ms |")
    print(f"| Replay time (avg) | {avg:.2f} ms |")
    print(f"| Digest matches | {r.replay_match}/{r.replay_total} |")
    if r.policy_diff:
        d = r.policy_diff
        print(f"| Policy v1 | {d.v1_id} |")
        print(f"| Policy v2 | {d.v2_id} |")
        print(f"| v1->v2 ALLOW->DENY | {d.allow_to_deny} |")
        print(f"| v1->v2 DENY->ALLOW | {d.deny_to_allow} |")
        print(f"| v1->v2 unchanged | {d.unchanged} |")
    print()
    if r.replay_match == r.replay_total and r.replay_total > 0:
        print(f"All {r.replay_total} DECISION events reproduced identical digests")
        print("under replay, confirming Claim 3 (Replay Equivalence).")
    if r.policy_diff:
        d = r.policy_diff
        flips = d.allow_to_deny + d.deny_to_allow
        print(f"Under a modified policy ({d.v2_id}), {flips} decisions flipped")
        print("outcome without requiring re-execution.")
    print()


def _print_json(r: BenchReport) -> None:
    out: dict[str, Any] = {
        "turns_generated": r.turns_generated,
        "decisions_total": r.decisions_total,
        "allow": r.allow_count,
        "deny": r.deny_count,
        "replay_match": r.replay_match,
        "replay_mismatch": r.replay_mismatch,
        "replay_error": r.replay_error,
        "total_replay_ms": round(r.total_replay_ms, 2),
        "avg_replay_ms": round(r.total_replay_ms / r.replay_total, 2) if r.replay_total else 0,
        "pass": r.replay_match == r.replay_total and r.replay_total > 0,
    }
    if r.policy_diff:
        d = r.policy_diff
        out["policy_diff"] = {
            "v1": d.v1_id,
            "v2": d.v2_id,
            "total": d.total,
            "allow_to_deny": d.allow_to_deny,
            "deny_to_allow": d.deny_to_allow,
            "unchanged": d.unchanged,
        }
    print(json.dumps(out, indent=2))


# ── CLI ──────────────────────────────────────────────────────────────

def _find_db(explicit: str | None) -> Path:
    """Resolve the SQLite database path."""
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p
        raise SystemExit(f"Database not found: {p}")
    # Default locations used by dbl-gateway
    for candidate in [Path("data/events.db"), Path("data/dbl_gateway.db")]:
        if candidate.exists():
            return candidate
    raise SystemExit(
        "No database found. Use --db to specify the path, "
        "or run from the dbl-gateway project root."
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="A3 empirical validation: generate traffic, replay decisions, verify digests.",
    )
    p.add_argument("--base-url", default="http://127.0.0.1:8010")
    p.add_argument("--turns", type=int, default=100, help="Number of turns to generate (default: 100)")
    p.add_argument("--stream-id", default="default")
    p.add_argument("--lane", default="bench")
    p.add_argument("--actor", default="bench-agent")
    p.add_argument("--auth-token", default="")
    p.add_argument("--report", choices=["text", "markdown", "json"], default="text")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-turn timeout in seconds")
    p.add_argument("--policy-diff", action="store_true", help="Run Phase 3: policy diff (v1 vs v2)")
    p.add_argument("--db", default=None, help="Path to SQLite database (for --policy-diff)")
    return p.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    args = _parse_args()
    base_url = args.base_url.rstrip("/")

    print("dbl-gateway bench_replay — A3 empirical validation")
    print(f"gateway: {base_url}")
    print(f"turns:   {args.turns}")
    print()

    with httpx.Client(base_url=base_url, timeout=args.timeout) as client:
        model_id = _preflight(client, args.auth_token)
        print(f"model:   {model_id}")
        print()

        # Phase 1: Generate
        t_gen_start = time.perf_counter()
        turn_results = generate(
            client,
            token=args.auth_token,
            model_id=model_id,
            n_turns=args.turns,
            stream_id=args.stream_id,
            lane=args.lane,
            actor=args.actor,
        )
        t_gen = (time.perf_counter() - t_gen_start) * 1000
        print(f"[generate] done in {t_gen:.0f} ms")
        print()

        # Phase 2: Replay
        t_replay_start = time.perf_counter()
        replay_results = replay(
            client,
            token=args.auth_token,
            turn_results=turn_results,
        )
        t_replay = (time.perf_counter() - t_replay_start) * 1000
        print(f"[replay] done in {t_replay:.0f} ms")

        # Phase 3: Policy Diff (optional)
        diff_report: PolicyDiffReport | None = None
        if args.policy_diff:
            print()
            db_path = _find_db(args.db)
            print(f"[policy-diff] db={db_path}")
            diff_entries, v1_id, v2_id = policy_diff(
                db_path=db_path,
                turn_results=turn_results,
            )
            diff_report = build_diff_report(diff_entries, v1_id, v2_id)
            print(f"[policy-diff] {diff_report.allow_to_deny} ALLOW->DENY, "
                  f"{diff_report.deny_to_allow} DENY->ALLOW, "
                  f"{diff_report.unchanged} unchanged")

        # Report
        report = build_report(turn_results, replay_results)
        report.policy_diff = diff_report
        print_report(report, args.report)

    return 0 if (report.replay_match == report.replay_total and report.replay_total > 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
