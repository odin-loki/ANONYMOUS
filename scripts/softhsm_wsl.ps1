# SoftHSM operator helper: run probe / user-build / init inside WSL from Windows.
# Avoids interactive sudo hangs by never passing `sudo` without `-n` checks.
#
# Examples:
#   powershell -File scripts/softhsm_wsl.ps1 -Action probe
#   powershell -File scripts/softhsm_wsl.ps1 -Action user-build
#   powershell -File scripts/softhsm_wsl.ps1 -Action init
#   powershell -File scripts/softhsm_wsl.ps1 -Action init -Evidence
#   powershell -File scripts/softhsm_wsl.ps1 -Action dry-run
#
# Repo root is inferred from this script's location.

[CmdletBinding()]
param(
    [ValidateSet("probe", "user-build", "init", "dry-run", "fix-pkcs11")]
    [string]$Action = "probe",
    [string]$WslUser = "odin",
    [switch]$Evidence
)

$ErrorActionPreference = "Stop"
$RepoWin = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
# WSL path for the Windows drive mount
$RepoWsl = "/mnt/" + $RepoWin.Substring(0, 1).ToLower() + ($RepoWin.Substring(2) -replace "\\", "/")

Write-Host "RepoWin=$RepoWin"
Write-Host "RepoWsl=$RepoWsl"
Write-Host "Action=$Action WslUser=$WslUser"

function Invoke-WslBashScript {
    param([string]$ScriptRel, [string]$ExtraArgs = "")
    $cmd = "cd '$RepoWsl' && bash '$ScriptRel' $ExtraArgs"
    Write-Host ">> wsl -u $WslUser bash -lc <$ScriptRel $ExtraArgs>"
    & wsl -u $WslUser bash -lc $cmd
    return $LASTEXITCODE
}

switch ($Action) {
    "probe" {
        exit (Invoke-WslBashScript "scripts/softhsm_probe.sh")
    }
    "user-build" {
        exit (Invoke-WslBashScript "scripts/softhsm_user_build.sh")
    }
    "dry-run" {
        exit (Invoke-WslBashScript "scripts/softhsm_init.sh" "--dry-run")
    }
    "fix-pkcs11" {
        exit (Invoke-WslBashScript "scripts/softhsm_fix_pkcs11_tool.sh")
    }
    "init" {
        $args = ""
        if ($Evidence) {
            $args = "--evidence sim/softhsm_init_evidence.txt"
        }
        exit (Invoke-WslBashScript "scripts/softhsm_init.sh" $args)
    }
}
