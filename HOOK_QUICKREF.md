# DBL Git Hook Quick Reference (Windows)

## Usage (PowerShell)

```powershell
# Normal commit - hook validates automatically
git commit -m "feat: add endpoint"

# Bypass hook (emergency only)
git commit --no-verify -m "hotfix"

# Check hook status
.\Install-DBLHook.ps1

# Test hook
.\Install-DBLHook.ps1 -Test
```

## What Gets Blocked

❌ `from dbl_core.canonical import canonicalize`  
❌ `def evaluate_policy` in gateway  
❌ `def digest_bytes` in gateway  
❌ Observational keys in PolicyContext  
❌ Invalid event kinds (only INTENT, DECISION, EXECUTION, PROOF)

## Common Fixes

**Violation:** `from dbl_core.canonical import canonicalize`  
**Fix:** Use `from dbl_core.canonical import digest_bytes` instead

**Violation:** `ctx = PolicyContext(trace=...)`  
**Fix:** Remove observational keys (trace, execution, timing, errors)

**Violation:** `kind = "OBSERVATION"`  
**Fix:** Use only INTENT, DECISION, EXECUTION, or PROOF

## Full Documentation

- Complete guide: `docs\GIT_HOOKS.md`
- Implementation notes: `docs\HOOK_SUMMARY.md`
- Constraints: `D:\DEV\projects\ensdg-corpus\AI_ASSISTANT_CONSTRAINTS.md`
