# Operator pilot: 4-node loopback mix path with production-checklist defaults.
# Docker bridge variant: deploy/compose/ (probe first: deploy/scripts/check_pilot_prereqs.ps1).
# Offline compose lint (no daemon): python deploy/scripts/validate_compose_offline.py
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$EphemeralPorts,
    [int]$Sends = 3,
    [double]$CoverSecs = 2.0,
    [double]$TauSecs = 0.35,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path $RepoRoot).Path
$Crates = Join-Path $Root "crates"
$ConfigDir = Join-Path $Root "sim\data\pilot_configs"
$GenScript = Join-Path $Root "sim\scripts\generate_pilot_configs.py"
$NodeProcs = @()

function Find-Cargo {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) { return $cargo.Source }
    $homeCargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $homeCargo) { return $homeCargo }
    throw "cargo not found"
}

function Stop-PilotNodes {
    foreach ($proc in $NodeProcs) {
        if ($null -eq $proc -or $proc.HasExited) { continue }
        try {
            & taskkill /PID $proc.Id /T /F 2>$null | Out-Null
        } catch {}
    }
}

function Wait-Listen([string]$HostName, [int]$Port, [double]$TimeoutSec = 45) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($HostName, $Port)
            $client.Close()
            return
        } catch {
            Start-Sleep -Milliseconds 80
        }
    }
    throw "timed out waiting for ${HostName}:${Port}"
}

function Get-ListenPorts {
    $ports = @()
    for ($i = 0; $i -lt 4; $i++) {
        $cfg = Join-Path $ConfigDir "node$i.toml"
        $line = Select-String -Path $cfg -Pattern '^listen\s*=' | Select-Object -First 1
        if (-not $line) { throw "no listen= in $cfg" }
        if ($line.Line -match '127\.0\.0\.1:(\d+)') {
            $ports += [int]$Matches[1]
        } else {
            throw "could not parse listen from $($line.Line)"
        }
    }
    return ,$ports
}

try {
    Write-Host "== AEGIS operator pilot (loopback) =="

    $genArgs = @("--out", $ConfigDir)
    if ($EphemeralPorts) { $genArgs += "--ephemeral-ports" }
    if (-not $SkipBuild) {
        # generate_pilot_configs builds aegis-pilot-gen; full node/client build below.
    } else {
        $genArgs += "--skip-build"
    }
    & python $GenScript @genArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $cargo = Find-Cargo
    if (-not $SkipBuild) {
        Write-Host "Building aegis-node and aegis-client..."
        Push-Location $Crates
        try {
            & $cargo build --quiet -p aegis-node -p aegis-client
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } finally {
            Pop-Location
        }
    }

    $nodeBin = Join-Path $Crates "target\debug\aegis-node.exe"
    $clientBin = Join-Path $Crates "target\debug\aegis-client.exe"
    if (-not (Test-Path $nodeBin)) { throw "missing $nodeBin" }
    if (-not (Test-Path $clientBin)) { throw "missing $clientBin" }

    $ports = Get-ListenPorts
    Write-Host "Starting 4 nodes (ports=$($ports -join ','))..."

    for ($i = 0; $i -lt 4; $i++) {
        $cfg = Join-Path $ConfigDir "node$i.toml"
        $proc = Start-Process -FilePath $nodeBin `
            -ArgumentList @("--config", $cfg) `
            -WorkingDirectory $ConfigDir `
            -PassThru `
            -WindowStyle Hidden `
            -RedirectStandardError "NUL"
        $NodeProcs += $proc
    }

    foreach ($p in $ports) {
        Wait-Listen "127.0.0.1" $p
    }

    foreach ($proc in $NodeProcs) {
        if ($proc.HasExited) {
            throw "node exited before ready (code $($proc.ExitCode))"
        }
    }

    Write-Host "Nodes listening. Running $Sends paced client send(s)..."
    $clientCfg = Join-Path $ConfigDir "client.toml"
    $ok = 0
    for ($i = 0; $i -lt $Sends; $i++) {
        $payload = "pilot-$i"
        Push-Location $ConfigDir
        try {
            & $clientBin --config "client.toml" --payload $payload --cover-secs $CoverSecs --tau-secs $TauSecs
            if ($LASTEXITCODE -ne 0) {
                Write-Host "client send $i failed (exit $LASTEXITCODE)" -ForegroundColor Red
            } else {
                $ok++
            }
        } finally {
            Pop-Location
        }
        Start-Sleep -Milliseconds 500
    }

    Start-Sleep -Seconds 2

    Write-Host "`n== coarse health =="
    $alive = 0
    for ($i = 0; $i -lt 4; $i++) {
        $proc = $NodeProcs[$i]
        if ($proc.HasExited) {
            Write-Host "  node$i : EXITED (code $($proc.ExitCode))" -ForegroundColor Red
        } else {
            $alive++
            Write-Host "  node$i : running (pid $($proc.Id), port $($ports[$i]))"
        }
    }

    $exitLog = Join-Path $ConfigDir "data\exit_deliveries.log"
    if (Test-Path $exitLog) {
        $lines = (Get-Content $exitLog | Measure-Object -Line).Lines
        Write-Host "  exit deliveries log: $lines line(s) at $exitLog"
    } else {
        Write-Host "  exit deliveries log: (not yet created)"
    }

    $quorumLog = Join-Path $ConfigDir "data\health_quorum.log"
    if (Test-Path $quorumLog) {
        $bytes = (Get-Item $quorumLog).Length
        Write-Host "  health quorum log: $bytes byte(s)"
    } else {
        Write-Host "  health quorum log: (none yet - gossip quorum may need longer interval)"
    }

    Write-Host "`nClient sends OK: $ok / $Sends"
    if ($alive -lt 4 -or $ok -lt $Sends) {
        exit 1
    }
    Write-Host "Pilot smoke passed."
    exit 0
}
finally {
    Stop-PilotNodes
}
