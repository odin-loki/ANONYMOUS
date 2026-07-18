# Windows wrapper: run Sphinx fuzz evidence pack under WSL.
# Wave A6 / S1. Not a formal proof. No Docker.
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('short', 'overnight', 'custom')]
    [string]$Mode = 'short',
    [int]$Seconds = -1,
    [string]$Target = 'fuzz_sphinx_process',
    [switch]$SkipSeed,
    [switch]$NoSmokeFallback
)

$normalized = $RepoRoot.TrimEnd('\', '/')
if ($normalized -notmatch '^([A-Za-z]):(.*)$') {
    Write-Error "Expected a Windows drive path, got: $RepoRoot"
    exit 1
}
$drive = $Matches[1].ToLowerInvariant()
$rest = ($Matches[2] -replace '\\', '/').TrimStart('/')
$RepoRootWsl = "/mnt/$drive/$rest"
$ScriptWsl = "$RepoRootWsl/scripts/run_sphinx_fuzz_evidence.sh"

$envParts = @("SPHINX_FUZZ_MODE=$Mode", "SPHINX_FUZZ_TARGET=$Target")
if ($Seconds -ge 0) { $envParts += "SPHINX_FUZZ_SECONDS=$Seconds" }
if ($SkipSeed) { $envParts += "SPHINX_FUZZ_SKIP_SEED=1" }
if ($NoSmokeFallback) { $envParts += "SPHINX_FUZZ_ALLOW_SMOKE=0" }
$envPrefix = ($envParts -join ' ')

Write-Host "Running WSL Sphinx fuzz evidence via: wsl -e bash -lc '$envPrefix $ScriptWsl'"
wsl -e bash -lc "chmod +x '$ScriptWsl' && $envPrefix '$ScriptWsl'"
exit $LASTEXITCODE
