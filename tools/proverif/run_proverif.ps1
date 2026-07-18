# Probe ProVerif via WSL (preferred) or native PATH; run Sphinx models (Wave S3).
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if ($wsl) {
    Write-Host "=== AEGIS Sphinx ProVerif probe (Windows → WSL) ==="
    $unix = (wsl -e wslpath -a "$Root" 2>$null | Select-Object -Last 1).Trim()
    if (-not $unix) {
        Write-Host "STATUS: MISSING (wslpath failed)"
        Write-Host "Expected lemmas: L1 secrecy, L2 integrity, L3 replay — see README.md"
        exit 2
    }
    wsl -e bash -lc "chmod +x '$unix/run_proverif.sh'; '$unix/run_proverif.sh'"
    exit $LASTEXITCODE
}

$pv = $null
if ($env:PROVERIF -and (Test-Path $env:PROVERIF)) { $pv = $env:PROVERIF }
elseif (Get-Command proverif -ErrorAction SilentlyContinue) {
    $pv = (Get-Command proverif).Source
}

if (-not $pv) {
    Write-Host "STATUS: MISSING"
    Write-Host "Neither WSL nor native proverif found."
    Write-Host "Install: opam install proverif  OR  https://bblanche.gitlabpages.inria.fr/proverif/"
    Write-Host "Expected lemmas: L1 secrecy, L2 integrity (sphinx_hop.pv),"
    Write-Host "                 L3 injective replay (sphinx_replay.pv)"
    exit 2
}

Write-Host "STATUS: FOUND (native) $pv"
& $pv (Join-Path $Root "sphinx_hop.pv")
& $pv (Join-Path $Root "sphinx_replay.pv")
exit 0
