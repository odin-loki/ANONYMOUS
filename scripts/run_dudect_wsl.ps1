# Windows wrapper: run in-tree CT smokes under WSL and capture evidence.
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$normalized = $RepoRoot.TrimEnd('\', '/')
if ($normalized -notmatch '^([A-Za-z]):(.*)$') {
    Write-Error "Expected a Windows drive path, got: $RepoRoot"
    exit 1
}
$drive = $Matches[1].ToLowerInvariant()
$rest = ($Matches[2] -replace '\\', '/').TrimStart('/')
$RepoRootWsl = "/mnt/$drive/$rest"
$ScriptWsl = "$RepoRootWsl/scripts/run_dudect_wsl.sh"

Write-Host "Running WSL dudect smoke via: wsl -e bash -lc '$ScriptWsl'"
wsl -e bash -lc "chmod +x '$ScriptWsl' && '$ScriptWsl'"
exit $LASTEXITCODE
