# Generate bridge-network pilot configs for deploy/compose/docker-compose.yml
param(
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

$ErrorActionPreference = "Stop"
$Out = Join-Path $PSScriptRoot "pilot_configs"
$Gen = Join-Path $RepoRoot "sim\scripts\generate_pilot_configs.py"

& python $Gen --out $Out --network bridge
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Docker pilot configs -> $Out"
Write-Host "Next: offline lint (no daemon)  python deploy/scripts/validate_compose_offline.py"
Write-Host "  or with Docker:             docker compose -f deploy/compose/docker-compose.yml up --build"
