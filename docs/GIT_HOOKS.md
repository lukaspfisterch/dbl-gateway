# DBL Gateway Git Hooks (Windows 11 / PowerShell)

## Pre-Commit Boundary Validation

Enhanced pre-commit hook for Windows 11 with PowerShell 5/7 that enforces DBL boundaries and invariants.

### Quick Start (PowerShell)

#### Normal Commit
```powershell
git commit -m "your message"
```

#### Explain Mode (Detailed Violations)
```powershell
$env:DBL_HOOK_EXPLAIN = "1"
git commit -m "your message"
```

#### List All Rules
```powershell
$env:DBL_HOOK_LIST_RULES = "1"
git commit -m "test"
```

#### Bypass Hook (Emergency Only)
```powershell
git commit --no-verify -m "your message"
```

### Features

✅ **Boundary Enforcement** - Blocks canonicalization/policy/digest logic in gateway
✅ **Event Kind Validation** - Only INTENT, DECISION, EXECUTION, PROOF allowed  
✅ **PolicyContext Guard** - Prevents observational data in governance
✅ **Invariant Checking** - Validates I-DECISION-1, I-POLICY-CTX-1/2, etc.
✅ **Windows Native** - Optimized for Win11, PS5/7, Git for Windows
✅ **Explain Mode** - Detailed fix hints via environment variable

### Validation Rules

| ID | Severity | Description |
|----|----------|-------------|
| BOUNDARY-001 | ERROR | No canonicalization logic in gateway |
| BOUNDARY-002 | ERROR | No policy evaluation in gateway |
| BOUNDARY-003 | ERROR | No digest computation in gateway |
| EVENT-001 | ERROR | Only 4 event kinds valid |
| POLICY-001 | ERROR | No observational keys in PolicyContext |
| INVARIANT-001 | WARNING | EXECUTION after ALLOW decision |

### Example Violations (PowerShell)

#### BOUNDARY-001: Canonicalization
```powershell
# ❌ Blocked by hook:
# from dbl_core.canonical import canonicalize

# ✅ Correct:
from dbl_core.canonical import digest_bytes
```

#### EVENT-001: Invalid Event Kind
```powershell
# ❌ Blocked:
# event = DblEvent(kind="OBSERVATION", ...)

# ✅ Correct:
event = DblEvent(kind=DblEventKind.INTENT, ...)
```

#### POLICY-001: Observational Data
```powershell
# ❌ Blocked:
# ctx = PolicyContext(intent=..., trace=execution_trace)

# ✅ Correct:
ctx = PolicyContext(intent=intent_payload, boundary_version="0.3.0")
```

### Windows-Specific Usage

#### PowerShell 5 (Default on Windows 11)
```powershell
# One-time explain mode
$env:DBL_HOOK_EXPLAIN = "1"; git commit -m "msg"

# Persistent for session
$env:DBL_HOOK_EXPLAIN = "1"
git commit -m "msg"
git commit -m "another"
Remove-Item Env:\DBL_HOOK_EXPLAIN
```

#### PowerShell 7
```powershell
# Same as PS5, but with cleaner output
pwsh -Command '$env:DBL_HOOK_EXPLAIN="1"; git commit -m "msg"'
```

#### Git Bash (on Windows)
```bash
DBL_HOOK_EXPLAIN=1 git commit -m "msg"
```

### Hook Location (Windows Paths)

```
D:\DEV\projects\dbl-gateway\.git\hooks\pre-commit
```

**References:**
- `D:\DEV\projects\ensdg\docs\BOUNDARY_MAP.md`
- `D:\DEV\projects\ensdg\docs\INVARIANTS.md`
- `D:\DEV\projects\ensdg-corpus\AI_ASSISTANT_CONSTRAINTS.md`

### Troubleshooting (Windows)

**Hook not running?**
```powershell
# Check if hook exists
Test-Path .git\hooks\pre-commit

# Make executable (Git Bash)
git update-index --chmod=+x .git/hooks/pre-commit

# Or via Python
python -c "import os; os.chmod('.git/hooks/pre-commit', 0o755)"
```

**Python not found?**
```powershell
# Check Python 3
python --version
py -3 --version

# If using py launcher, edit hook shebang to:
# #!/usr/bin/env python
```

**Path issues on Windows?**
The hook automatically converts Windows paths. If you see errors about paths, check:
```powershell
git config core.autocrlf  # Should be 'true' or 'input'
```

**Test hook manually:**
```powershell
python .git\hooks\pre-commit
```

### PowerShell Helper Functions

Add to your `$PROFILE`:

```powershell
# Quick explain mode commit
function gitce {
    param([string]$Message)
    $env:DBL_HOOK_EXPLAIN = "1"
    git commit -m $Message
    Remove-Item Env:\DBL_HOOK_EXPLAIN
}

# List DBL validation rules
function dbl-rules {
    $env:DBL_HOOK_LIST_RULES = "1"
    python .git\hooks\pre-commit
    Remove-Item Env:\DBL_HOOK_LIST_RULES
}

# Usage:
# gitce "fix: update admission logic"
# dbl-rules
```

### Installation (Windows)

If hook is missing or needs reinstallation:

```powershell
# From D:\DEV\projects directory
cd D:\DEV\projects
.\install-dbl-hooks.ps1  # If available

# Or manually copy from template
Copy-Item D:\DEV\projects\.git-hooks\pre-commit `
          D:\DEV\projects\dbl-gateway\.git\hooks\pre-commit
```

### Extending the Hook

To add custom rules for dbl-gateway:

```python
# Edit .git\hooks\pre-commit

# 1. Define matcher
def my_matcher(content: str, file_path: str):
    violations = []
    # ... your logic ...
    return [(line_no, snippet, context), ...]

# 2. Add to RULES list
RULES.append(
    Rule(
        id="GATEWAY-CUSTOM-001",
        description="Your rule description",
        severity="ERROR",
        file_pattern=r".*\.py$",
        matcher=my_matcher,
        fix_hint="How to fix this",
        references=["D:\DEV\projects\ensdg\docs\BOUNDARY_MAP.md"]
    )
)
```

### Performance

- **Typical commit**: < 0.5s on Windows 11
- **Large commit** (20+ files): < 2s
- **Scans**: Only staged `.py`, `.ts`, `.tsx` files
- **Fail-safe**: Hook errors allow commit (fail-open)

### Windows-Specific Notes

✅ Works with **Git for Windows** (Git Bash, Git CMD, PowerShell)
✅ Compatible with **VS Code** integrated terminal
✅ Works in **Windows Terminal** (PowerShell 7)
✅ Supports **PyCharm**, **Cursor**, **VS Code** Git integration
✅ CRLF line endings handled automatically

❌ Does not require WSL
❌ Does not require admin privileges
❌ No external dependencies (Python stdlib only)

### CI/CD Integration (Windows)

For GitHub Actions on Windows runners:

```yaml
- name: Run DBL boundary check
  shell: pwsh
  run: |
    $env:DBL_HOOK_EXPLAIN = "1"
    python .git\hooks\pre-commit
```

### References

- **Source of Truth**: `D:\DEV\projects\ensdg-corpus\AI_ASSISTANT_CONSTRAINTS.md`
- **Boundary Map**: `D:\DEV\projects\ensdg\docs\BOUNDARY_MAP.md`
- **Invariants**: `D:\DEV\projects\ensdg\docs\INVARIANTS.md`
- **Hook Implementation**: `.git\hooks\pre-commit` (Python 3)

---

**Note**: This hook enforces normative boundaries from the DBL kernel specification. Violations indicate architectural drift and must be resolved before commit.
