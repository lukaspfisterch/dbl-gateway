from __future__ import annotations

import json
from pathlib import Path

from dbl_gateway.app import create_app


def test_openapi_snapshot_matches_fixture() -> None:
    app = create_app()
    openapi = app.openapi()
    rendered = json.dumps(openapi, sort_keys=True, indent=2)
    fixture_path = Path("tests/fixtures/openapi_snapshot.json")
    expected = fixture_path.read_text(encoding="utf-8").rstrip()
    assert rendered == expected
