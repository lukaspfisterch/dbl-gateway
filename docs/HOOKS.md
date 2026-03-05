# Pre-Commit Hooks

The pre-commit hook enforces DBL component ownership boundaries at commit time.
Violations block the commit. The hook scans only staged `.py` files.

## Validation Rules

| ID | Severity | What it catches | Fix |
|----|----------|-----------------|-----|
| BOUNDARY-001 | ERROR | `from dbl_core.canonical import canonicalize` in gateway | Use `digest_bytes`, not `canonicalize` |
| BOUNDARY-002 | ERROR | `def evaluate_policy` in gateway | Policy evaluation belongs to dbl-policy |
| BOUNDARY-003 | ERROR | `def digest_bytes` in gateway | Use `dbl_core.canonical.digest_bytes`; never reimplement |
| EVENT-001 | ERROR | Event kind not in {INTENT, DECISION, EXECUTION, PROOF} | Use `DblEventKind` enum |
| POLICY-001 | ERROR | Observational keys (`trace`, `execution`, `timing`, `errors`) passed to `PolicyContext()` | Remove observational kwargs; governance sees only authoritative inputs |
| INVARIANT-001 | WARNING | EXECUTION emitted without prior ALLOW decision | Ensure DECISION precedes EXECUTION in event sequence |

## Usage

Normal commit (hook runs automatically):

```
git commit -m "feat: add endpoint"
```

Explain mode (detailed violation output):

```powershell
$env:DBL_HOOK_EXPLAIN = "1"
git commit -m "feat: add endpoint"
```

```bash
DBL_HOOK_EXPLAIN=1 git commit -m "feat: add endpoint"
```

List all rules:

```powershell
$env:DBL_HOOK_LIST_RULES = "1"
python .git/hooks/pre-commit
```

Bypass (emergency only):

```
git commit --no-verify -m "hotfix: unblock deploy"
```

## Installation

The hook lives at `.git/hooks/pre-commit`. If missing:

```powershell
.\Install-DBLHook.ps1
```

Or copy manually:

```
cp .git-hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Test the hook without committing:

```
python .git/hooks/pre-commit
```

## Troubleshooting

**Hook not running.**
Check that the file exists and is executable:

```
ls -la .git/hooks/pre-commit
```

On Windows, set executable via Git:

```
git update-index --chmod=+x .git/hooks/pre-commit
```

**Python not found.**
The hook requires Python 3. If using the Windows `py` launcher, ensure the
hook shebang is `#!/usr/bin/env python`.

**False positive on POLICY-001.**
The matcher flags only `PolicyContext(` constructor calls with observational
keyword arguments. Imports, type hints, and string literals are excluded.
If a legitimate use is flagged, check for an observational key name appearing
as a keyword argument.

## Design

- Fail-open: if the hook itself errors, the commit proceeds.
- No external dependencies. Python stdlib only.
- Typical runtime: < 0.5s.
- Scans staged files only (`git show :path`).
- UTF-8 with `errors="ignore"` for encoding safety.
