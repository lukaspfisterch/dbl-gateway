# Contributing

This repository is a **reference-grade implementation**.
Changes must preserve determinism, ordering, and wire compatibility.

## Scope
- Keep changes minimal and focused.
- Do not introduce new behavior without an explicit contract.
- Avoid semantic drift from the DBL papers and documented invariants.

## Style
- Match existing structure, naming, and error handling.
- Prefer explicit validation over implicit assumptions.
- All user-facing changes must be reflected in `CHANGELOG.md`.

## Development
- Python 3.11
- Install (editable):
  ```bash
  python -m pip install -e ".[dev]"
  ```

## Tests
Run the full test suite before submitting changes:
```bash
pytest
```
New behavior requires invariant-level tests, not only unit tests.

## Versioning
Version is defined in `pyproject.toml` and `README.md`.
These files must be updated together.

Patch releases (`x.y.z`) are for:
- Bug fixes
- Clarifications
- Non-breaking contract tightening

Minor releases (`x.y.0`) are for:
- New wire-compatible surfaces
- New invariants or enforced guarantees

Breaking changes require a major version bump.

This document defines contribution constraints, not contribution encouragement.
