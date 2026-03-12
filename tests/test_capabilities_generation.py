from __future__ import annotations

import json
from pathlib import Path
import sys

from dbl_gateway.capabilities import CAPABILITIES_SCHEMA_VERSION
from dbl_gateway.wire_contract import INTERFACE_VERSION


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _import_generator_module():
    repo_root = _repo_root()
    scripts_dir = repo_root / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import generate_capabilities

    return generate_capabilities


def test_generator_writes_versioned_file(tmp_path: Path) -> None:
    generator = _import_generator_module()
    out = tmp_path / f"capabilities.gateway.v{INTERFACE_VERSION}.json"
    written = generator.generate(out)
    assert written == out
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["interface_version"] == INTERFACE_VERSION
    assert data["schema_version"] == CAPABILITIES_SCHEMA_VERSION
    assert "gateway_version" in data
    assert "generated_at" in data


def test_repo_capabilities_file_matches_wire_contract() -> None:
    docs_path = _repo_root() / "docs" / f"capabilities.gateway.v{INTERFACE_VERSION}.json"
    assert docs_path.exists()

    data = json.loads(docs_path.read_text(encoding="utf-8"))
    assert data["interface_version"] == INTERFACE_VERSION
    assert data["schema_version"] == CAPABILITIES_SCHEMA_VERSION


def test_generated_snapshot_has_contract_fields(tmp_path: Path) -> None:
    generator = _import_generator_module()
    out = tmp_path / "caps.json"
    generator.generate(out)

    data = json.loads(out.read_text(encoding="utf-8"))
    # Contract fields present
    assert "intents" in data
    assert "tool_surface" in data
    assert "budget" in data
    assert "surfaces" in data
    # Runtime-dynamic fields stripped
    assert "providers" not in data
    # Contract structure
    assert isinstance(data["intents"]["supported"], list)
    assert isinstance(data["tool_surface"]["declared_tools"]["max_items"], int)
    assert isinstance(data["budget"]["fields"]["max_tokens"]["min"], int)
