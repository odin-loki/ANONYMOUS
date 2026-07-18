# Windows wrapper: run full dudect lab attempt under WSL and capture evidence.
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [int]$DudectMeasurements = 5000
)

$normalized = $RepoRoot.TrimEnd('\', '/')
if ($normalized -notmatch '^([A-Za-z]):(.*)$') {
    Write-Error "Expected a Windows drive path, got: $RepoRoot"
    exit 1
}
$drive = $Matches[1].ToLowerInvariant()
$rest = ($Matches[2] -replace '\\', '/').TrimStart('/')
$RepoRootWsl = "/mnt/$drive/$rest"
$ScriptWsl = "$RepoRootWsl/scripts/run_dudect_lab_wsl.sh"

Write-Host "Running WSL dudect lab via: wsl -e bash -lc 'DUDECT_MEASUREMENTS=$DudectMeasurements $ScriptWsl'"
wsl -e bash -lc "chmod +x '$ScriptWsl' && DUDECT_MEASUREMENTS=$DudectMeasurements '$ScriptWsl'"
exit $LASTEXITCODE
