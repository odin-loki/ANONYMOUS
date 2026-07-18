# Probe host prerequisites for the AEGIS Docker / loopback pilot.
# Never starts containers. Never runs hanging installs.
param(
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$EvidenceDir = ""
)

$ErrorActionPreference = "Continue"
$Root = (Resolve-Path $RepoRoot).Path
if (-not $EvidenceDir) {
    $EvidenceDir = Join-Path $Root "deploy\evidence"
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$EvidenceFile = Join-Path $EvidenceDir "host_probe.txt"

function Test-Cmd([string]$Name) {
    $c = Get-Command $Name -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

$lines = New-Object System.Collections.Generic.List[string]
function Log([string]$Msg) {
    # Strip NULs / non-text so evidence stays plain UTF-8 for editors/tools.
    $clean = ($Msg -replace "`0", "") -replace "[\x00-\x08\x0B\x0C\x0E-\x1F]", ""
    Write-Host $clean
    $lines.Add($clean) | Out-Null
}

Log "== AEGIS pilot prerequisite probe =="
Log ("timestamp_utc: " + [DateTime]::UtcNow.ToString("o"))
Log ("repo: $Root")
Log ("host: Windows")
Log ""

$docker = Test-Cmd "docker"
$podman = Test-Cmd "podman"
$python = Test-Cmd "python"
if (-not $python) { $python = Test-Cmd "py" }
$cargo = Test-Cmd "cargo"
if (-not $cargo) {
    $homeCargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $homeCargo) { $cargo = $homeCargo }
}

Log "--- Windows PATH ---"
Log ("docker:  " + $(if ($docker) { $docker } else { "MISSING" }))
Log ("podman:  " + $(if ($podman) { $podman } else { "MISSING" }))
Log ("python:  " + $(if ($python) { $python } else { "MISSING" }))
Log ("cargo:   " + $(if ($cargo) { $cargo } else { "MISSING" }))

$dockerOk = $false
$composeOk = $false
if ($docker) {
    try {
        $ver = & docker version --format "{{.Server.Version}}" 2>&1
        if ($LASTEXITCODE -eq 0 -and $ver) {
            Log ("docker engine: $ver")
            $dockerOk = $true
        } else {
            Log ("docker CLI present but engine unreachable: $ver")
        }
    } catch {
        Log ("docker probe error: $_")
    }
    try {
        $cv = & docker compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Log ("docker compose: $cv")
            $composeOk = $true
        } else {
            Log ("docker compose: FAILED ($cv)")
        }
    } catch {
        Log ("docker compose probe error: $_")
    }
}

Log ""
Log "--- WSL (non-interactive) ---"
$wsl = Test-Cmd "wsl"
if ($wsl) {
    try {
        $status = & wsl --status 2>&1 | Out-String
        Log ($status.Trim())
    } catch {
        Log "wsl --status failed"
    }
    $wslProbe = & wsl -e sh -c "command -v docker; docker --version 2>/dev/null; command -v podman; command -v cargo; cargo --version 2>/dev/null; command -v python3; python3 --version 2>/dev/null" 2>&1
    Log ("wsl tools:`n$wslProbe")
} else {
    Log "wsl: MISSING"
}

Log ""
Log "--- Binary / offline tools ---"
$aegisCandidates = @(
    (Join-Path $Root "crates\target\debug\aegis-node.exe"),
    (Join-Path $Root "crates\target\release\aegis-node.exe"),
    (Join-Path $Root "crates\target\debug\aegis-node"),
    (Join-Path $Root "crates\target\release\aegis-node")
)
$aegis = $aegisCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
Log ("aegis-node: " + $(if ($aegis) { $aegis } else { "MISSING (optional for offline TOML/YAML lint)" }))

$pyyaml = $false
if ($python) {
    & $python -c "import yaml" 2>$null
    if ($LASTEXITCODE -eq 0) { $pyyaml = $true }
}
Log ("PyYAML:    " + $(if ($pyyaml) { "OK" } else { "MISSING (pip install pyyaml)" }))

Log ""
Log "--- Verdict ---"
if ($dockerOk -and $composeOk) {
    Log "Docker: PRESENT - you may run compose (see docs/ops/PILOT.md)."
    Log "  .\deploy\compose\generate_configs.ps1"
    Log "  docker compose -f deploy/compose/docker-compose.yml up --build"
} else {
    Log "Docker: ABSENT or engine not running - do NOT claim containers ran."
    Log "Offline path still available:"
    Log "  python deploy/scripts/validate_compose_offline.py"
    Log "  .\scripts\run_pilot.ps1   # loopback (needs cargo + python)"
}

Log ""
Log "--- Unblock steps (Windows Docker Desktop + WSL2) ---"
Log "1. Enable Virtualization in BIOS/UEFI if disabled."
Log "2. Admin PowerShell (no hanging auto-install from this script):"
Log "     dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart"
Log "     dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart"
Log "3. Reboot, then: wsl --install -d Ubuntu   (or wsl --update && wsl --set-default-version 2)"
Log "4. Download Docker Desktop for Windows from https://docs.docker.com/desktop/setup/install/windows-install/"
Log "5. Installer UI (interactive - operator must complete): enable WSL2 backend, finish wizard, Start Docker Desktop."
Log "6. Verify in a NEW terminal:"
Log "     docker version"
Log "     docker compose version"
Log "7. From repo root:"
Log "     .\deploy\compose\generate_configs.ps1"
Log "     docker compose -f deploy/compose/docker-compose.yml up --build"
Log "8. Optional client send:"
Log "     docker compose -f deploy/compose/docker-compose.yml --profile client run --rm client"
Log ""
Log "If Docker Desktop cannot be installed, use loopback pilot + offline validate."
Log "Evidence: this probe never starts containers."

# .NET WriteAllLines => UTF-8 without BOM (readable on all hosts)
[System.IO.File]::WriteAllLines($EvidenceFile, $lines.ToArray())
Write-Host ""
Write-Host "Wrote $EvidenceFile"

# Exit 0 always for probe (informational). Use validate script for pack gate.
exit 0
