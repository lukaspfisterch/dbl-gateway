# Deterministic AI Gateway

The **Deterministic AI Gateway** is a secure execution boundary for LLM calls. It transforms AI usage into a deterministic, auditable event chain by enforcing explicit boundaries between intent, context, and decision.

It is **not** an agent framework, a RAG pipeline, or a UI product. It is a governance layer.

## Core Concepts

Every AI interaction follows a strict **Canonical Chain**:

1. **INTENT**: Explicit user/system request with identity anchors.
2. **CONTEXT**: Deterministic assembly of data (produces a `context_digest`).
3. **ADMISSION**: Boundary checks (deciding what may enter/leave).
4. **EXECUTION**: Secure call to an LLM provider.
5. **DECISION**: Normative record of the outcome + metadata (produces a `decision_digest`).

### Identity Anchors
To maintain causal ordering and enable branching, every intent must include:
- `thread_id`: Stable identifier for a dialogue or workflow.
- `turn_id`: Unique identifier for each specific call.
- `parent_turn_id`: (Optional) The turn this call branches from.

## Design Stance
- **Determinism First**: Same inputs -> same context -> same digests.
- **Auditable**: All interactions are recorded as an append-only event stream.
- **Explicit Boundaries**: No heuristics. Input/output rules are enforced by policy.
- **Replayable**: Decision artifacts can be replayed offline for audit/verification.

## Installation

Install the package in a virtual environment:

```bash
pip install -e .
```

## Running the Gateway

The gateway requires model provider credentials (e.g., OpenAI) and a policy module configuration.

### Configuration (Environment Variables)

| Variable | Description |
| :--- | :--- |
| `OPENAI_API_KEY` | Your OpenAI API key. |
| `DBL_GATEWAY_POLICY_MODULE` | The python module containig the policy (e.g., `dbl_policy.allow_all`). |
| `DBL_GATEWAY_POLICY_OBJECT` | The specific policy object within that module (usually `policy`). |
| `DBL_GATEWAY_DB` | Path to the SQLite event trail (optional, defaults to `.\data\trail.sqlite`). |

### Running the Server

#### Bash / Zsh
```bash
export OPENAI_API_KEY="sk-proj-..."
export DBL_GATEWAY_POLICY_MODULE="dbl_policy.allow_all"
export DBL_GATEWAY_POLICY_OBJECT="policy"

dbl-gateway serve --host 127.0.0.1 --port 8010
```

#### PowerShell
```powershell
$env:OPENAI_API_KEY = "sk-proj-..."
$env:DBL_GATEWAY_POLICY_MODULE = "dbl_policy.allow_all"
$env:DBL_GATEWAY_POLICY_OBJECT = "policy"

dbl-gateway serve --host 127.0.0.1 --port 8010
```

## Tail (/tail) behavior

The `/tail` endpoint is intended for **live observation**, not historical inspection.

- **Default behavior**: On connect, the gateway emits only the **last 20 events**, then continues streaming new events as they occur.
- **Parameters**:
  - `since`: Start streaming from a specific event index.
  - `backlog`: Number of recent events to emit on connect (only used if `since` is omitted). Default is 20.

### Examples

#### Bash / Zsh
```bash
# Live tail (default: last 20 events)
curl -N http://127.0.0.1:8010/tail

# Live tail with explicit backlog
curl -N "http://127.0.0.1:8010/tail?backlog=50"

# Resume from a known cursor
curl -N "http://127.0.0.1:8010/tail?since=1234"
```

#### PowerShell
```powershell
# Live tail (default: last 20 events)
curl.exe -N "http://127.0.0.1:8010/tail"

# Live tail with explicit backlog
curl.exe -N "http://127.0.0.1:8010/tail?backlog=50"

# Resume from a known cursor
curl.exe -N "http://127.0.0.1:8010/tail?since=1234"
```

## Non-Goals
- Agent orchestration or planning logic.
- Long-term memory or semantic user modeling.
- Vector database management.
- UI/UX implementation.

## Status
Early access. Focusing on core canon, invariants, and stabilization trails.

---

## License
TBD