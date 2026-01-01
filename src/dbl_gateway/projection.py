from __future__ import annotations

from typing import Iterable

from dbl_core import DblEvent, DblEventKind, GateDecision
from dbl_main import Phase, RunnerStatus, State, project_state


def project_runner_state(events: Iterable[dict[str, object]]) -> State:
    dbl_events: list[DblEvent] = []
    for event in events:
        kind = DblEventKind(str(event.get("kind")))
        correlation_id = str(event.get("correlation_id"))
        data = event.get("payload")
        if kind == DblEventKind.DECISION and isinstance(data, dict):
            decision = str(data.get("decision", "DENY"))
            reason_codes = data.get("reason_codes")
            if isinstance(reason_codes, list) and reason_codes:
                reason_code = str(reason_codes[0])
            else:
                reason_code = str(data.get("reason_code", "unspecified"))
            reason_message = data.get("reason_message") if isinstance(data.get("reason_message"), str) else None
            data = GateDecision(decision, reason_code, reason_message)
        dbl_events.append(DblEvent(event_kind=kind, correlation_id=correlation_id, data=data))
    return project_state(dbl_events)


def state_payload(state: State) -> dict[str, object]:
    return {
        "phase": state.phase.value,
        "runner_status": state.runner_status.value,
        "t_index": state.t_index,
        "note": state.note,
    }
