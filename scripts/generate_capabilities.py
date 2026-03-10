#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import tomllib
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dbl_gateway.wire_contract import (  # noqa: E402
    BUDGET_FIELDS,
    BUDGET_LIMITS,
    CAPABILITIES_INTENT_TYPES,
    INTERFACE_VERSION,
    MAX_DECLARED_TOOLS,
    SUPPORTED_TOOL_SCOPE,
    TOOL_NAME_PATTERN,
)


def _gateway_version(repo_root: Path) -> str:
    pyproject = repo_root / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _build_payload(*, gateway_version: str) -> dict[str, Any]:
    interface_version = INTERFACE_VERSION
    return {
        "schema": "gateway.capabilities.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_from": {
            "wire_contract": f"v{interface_version}",
            "gateway_version": gateway_version,
            "sources": [
                "src/dbl_gateway/wire_contract.py",
                "src/dbl_gateway/contracts.py",
            ],
        },
        "interface_version": interface_version,
        "intents": {
            "supported": list(CAPABILITIES_INTENT_TYPES),
        },
        "tool_surface": {
            "declared_tools": {
                "max_items": MAX_DECLARED_TOOLS,
                "name_pattern": TOOL_NAME_PATTERN,
            },
            "tool_scope": {
                "supported": list(SUPPORTED_TOOL_SCOPE),
                "default_when_declared_tools_present": "strict",
            },
        },
        "budget": {
            "fields": {
                field: {
                    "type": "integer",
                    "min": BUDGET_LIMITS[field]["min"],
                    "max": BUDGET_LIMITS[field]["max"],
                }
                for field in BUDGET_FIELDS
            }
        },
    }


def _default_output(repo_root: Path) -> Path:
    return repo_root / "docs" / f"capabilities.gateway.v{INTERFACE_VERSION}.json"


def generate(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _build_payload(gateway_version=_gateway_version(REPO_ROOT))
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate versioned gateway capabilities JSON from source-of-truth contract modules.")
    parser.add_argument("--output", type=Path, default=None, help="Optional output file path")
    args = parser.parse_args()

    out = args.output if args.output else _default_output(REPO_ROOT)
    written = generate(out)
    print(f"Wrote {written}")


if __name__ == "__main__":
    main()
