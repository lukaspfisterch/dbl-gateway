#!/usr/bin/env python3
"""Generate capabilities snapshot from the runtime contract.

This script has zero own logic. It calls get_capabilities(),
strips runtime-dynamic fields (providers), and writes JSON.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dbl_gateway.capabilities import get_capabilities  # noqa: E402
from dbl_gateway.wire_contract import INTERFACE_VERSION  # noqa: E402


def _default_output() -> Path:
    return REPO_ROOT / "docs" / f"capabilities.gateway.v{INTERFACE_VERSION}.json"


def generate(output_path: Path) -> Path:
    caps = get_capabilities()
    # Strip runtime-dynamic fields
    caps.pop("providers", None)
    # Add generation metadata
    caps["generated_at"] = datetime.now(timezone.utc).isoformat()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(caps, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate capabilities snapshot from runtime contract.",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    out = args.output if args.output else _default_output()
    written = generate(out)
    print(f"Wrote {written}")


if __name__ == "__main__":
    main()
