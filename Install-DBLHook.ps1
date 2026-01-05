# Install-DBLHook.ps1 - DBL Pre-Commit Hook Installer for Windows
[CmdletBinding()]
param(
    [switch]$Test,
    [switch]$ListRules
)

$ErrorActionPreference = "Stop"

Write-Host "DBL Pre-Commit Hook Installer (Windows)" -ForegroundColor Cyan
Write-Host ("=" * 60)

if (-not (Test-Path ".git")) {
    Write-Error "Not a git repository. Run from dbl-gateway root."
    exit 1
}

$hookPath = ".git\hooks\pre-commit"

if (Test-Path $hookPath) {
    Write-Host "Hook exists: $hookPath" -ForegroundColor Green
    
    if ($Test) {
        Write-Host "Testing hook..." -ForegroundColor Yellow
        python $hookPath
        exit $LASTEXITCODE
    }
    
    if ($ListRules) {
        Write-Host "Listing validation rules..." -ForegroundColor Yellow
        $env:DBL_HOOK_LIST_RULES = "1"
        python $hookPath
        Remove-Item Env:\DBL_HOOK_LIST_RULES
        exit 0
    }
    
    Write-Host "Hook is installed and ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  Normal:        git commit -m 'message'"
    Write-Host "  Explain mode:  `$env:DBL_HOOK_EXPLAIN='1'; git commit -m 'msg'"
    Write-Host "  List rules:    `$env:DBL_HOOK_LIST_RULES='1'; git commit -m 'msg'"
    Write-Host "  Bypass:        git commit --no-verify -m 'msg'"
    
} else {
    Write-Warning "Hook not found at $hookPath"
    Write-Host "Expected: D:\DEV\projects\dbl-gateway\.git\hooks\pre-commit"
    exit 1
}
