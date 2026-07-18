# Windows wrapper: run full dudect lab attempt under WSL and capture evidence.
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('short', 'deepen', 'custom')]
    [string]$LabMode = 'short',
    [int]$DudectMeasurements = -1,
    [int]$DudectMaxChunks = -1,
    [int]$TimeoutReplaySec = -1,
    [int]$TimeoutMacSec = -1,
    [int]$TimeoutSec = -1,
    [switch]$SkipSmoke
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

$envParts = @("DUDECT_LAB_MODE=$LabMode")
if ($DudectMeasurements -ge 0) { $envParts += "DUDECT_MEASUREMENTS=$DudectMeasurements" }
if ($DudectMaxChunks -ge 0) { $envParts += "DUDECT_MAX_CHUNKS=$DudectMaxChunks" }
if ($TimeoutReplaySec -ge 0) { $envParts += "DUDECT_TIMEOUT_REPLAY=$TimeoutReplaySec" }
if ($TimeoutMacSec -ge 0) { $envParts += "DUDECT_TIMEOUT_MAC=$TimeoutMacSec" }
if ($TimeoutSec -ge 0) { $envParts += "DUDECT_TIMEOUT_SEC=$TimeoutSec" }
if ($SkipSmoke) { $envParts += "DUDECT_SKIP_SMOKE=1" }
$envPrefix = ($envParts -join ' ')

Write-Host "Running WSL dudect lab via: wsl -e bash -lc '$envPrefix $ScriptWsl'"
wsl -e bash -lc "chmod +x '$ScriptWsl' && $envPrefix '$ScriptWsl'"
exit $LASTEXITCODE
