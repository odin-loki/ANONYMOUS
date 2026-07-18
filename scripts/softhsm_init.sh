#!/usr/bin/env bash
# SoftHSM2 token init helper for AEGIS consortium ceremony pilot (WSL/Linux).
#
# Safe when softhsm2-util is missing: prints install hint and exits 0 (CI/agents).
# Does NOT run in default CI. See docs/ops/softhsm_ceremony.md.
#
# Flags / env:
#   --dry-run              Probe + print actions; do not init token
#   --evidence FILE        Append a structured evidence block to FILE
#   AEGIS_SOFTHSM_DRY_RUN=1
#   AEGIS_SOFTHSM_SLOT / AEGIS_SOFTHSM_TOKEN_LABEL / AEGIS_SOFTHSM_*_PIN
#   SOFTHSM2_CONF / AEGIS_PKCS11_MODULE
#
# Evidence RESULT codes (written when --evidence is set):
#   SUCCEEDED              token present + show-slots OK
#   ALREADY_INITIALIZED    label already present; show-slots OK
#   MISSING_SOFTHSM        softhsm2-util absent (graceful exit 0)
#   SHOW_SLOTS_FAIL        util present but module/conf broken
#   INIT_FAIL              softhsm2-util --init-token failed
#   DRY_RUN                dry-run only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLOT="${AEGIS_SOFTHSM_SLOT:-0}"
LABEL="${AEGIS_SOFTHSM_TOKEN_LABEL:-aegis-ceremony}"
SO_PIN="${AEGIS_SOFTHSM_SO_PIN:-1234}"
USER_PIN="${AEGIS_SOFTHSM_USER_PIN:-1234}"
DRY_RUN="${AEGIS_SOFTHSM_DRY_RUN:-0}"
EVIDENCE_FILE=""
RESULT_CODE=""
RESULT_DETAIL=""

usage() {
  cat <<EOF
Usage: bash scripts/softhsm_init.sh [--dry-run] [--evidence FILE]

Init (or re-check) SoftHSM token label '$LABEL' for the AEGIS ceremony pilot.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --evidence) EVIDENCE_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

# Resolve relative evidence paths against repo root (not caller cwd).
if [[ -n "$EVIDENCE_FILE" && "$EVIDENCE_FILE" != /* ]]; then
  EVIDENCE_FILE="$ROOT/$EVIDENCE_FILE"
fi

write_evidence() {
  [[ -n "$EVIDENCE_FILE" ]] || return 0
  mkdir -p "$(dirname "$EVIDENCE_FILE")"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u)"
  {
    echo ""
    echo "---"
    echo "# SoftHSM init evidence block"
    echo "# Captured: $ts"
    echo "# Host: $(uname -srm 2>/dev/null || uname -a)"
    echo "# User: $(whoami)"
    echo "# Repo: $ROOT"
    echo "RESULT_CODE=$RESULT_CODE"
    echo "RESULT_DETAIL=$RESULT_DETAIL"
    echo "SOFTHSM2_UTIL=$(command -v softhsm2-util 2>/dev/null || echo missing)"
    echo "AEGIS_PKCS11_MODULE=${AEGIS_PKCS11_MODULE:-}"
    echo "SOFTHSM2_CONF=${SOFTHSM2_CONF:-}"
    echo "LABEL=$LABEL SLOT=$SLOT DRY_RUN=$DRY_RUN"
    if command -v softhsm2-util >/dev/null 2>&1; then
      echo "SOFTHSM2_VERSION=$(softhsm2-util --version 2>/dev/null | head -1 || true)"
      echo "--- show-slots ---"
      softhsm2-util --show-slots 2>&1 || echo "(show-slots failed)"
    fi
    if command -v pkcs11-tool >/dev/null 2>&1; then
      local mod="${AEGIS_PKCS11_MODULE:-}"
      if [[ -z "$mod" && -f "${HOME}/.local/lib/softhsm/libsofthsm2.so" ]]; then
        mod="${HOME}/.local/lib/softhsm/libsofthsm2.so"
      fi
      if [[ -n "$mod" && -f "$mod" ]]; then
        echo "--- pkcs11-tool --list-slots ---"
        export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
        pkcs11-tool --module "$mod" --list-slots 2>&1 || echo "(pkcs11-tool failed)"
      fi
    fi
  } >>"$EVIDENCE_FILE"
  echo "Appended evidence to $EVIDENCE_FILE (RESULT_CODE=$RESULT_CODE)"
}

# Prefer user-local SoftHSM2 build (--prefix=$HOME/.local) over system packages.
if [[ -x "${HOME}/.local/bin/softhsm2-util" ]]; then
  export PATH="${HOME}/.local/bin:${PATH}"
  export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
  export AEGIS_PKCS11_MODULE="${AEGIS_PKCS11_MODULE:-${HOME}/.local/lib/softhsm/libsofthsm2.so}"
fi

if ! command -v softhsm2-util >/dev/null 2>&1; then
  cat <<EOF
SoftHSM2 not found (softhsm2-util missing).

Unblock checklist (WSL/Ubuntu, non-interactive agents: avoid hanging sudo):

1) Probe first:
     bash scripts/softhsm_probe.sh

2) Preferred no-sudo path (downloads uuid-dev/libtool debs if needed):
     bash scripts/softhsm_user_build.sh
     bash scripts/softhsm_init.sh

3) System packages (needs interactive sudo password once):
     sudo apt-get update && sudo apt-get install -y softhsm2 opensc

4) From Windows PowerShell:
     powershell -File scripts/softhsm_wsl.ps1 -Action probe
     powershell -File scripts/softhsm_wsl.ps1 -Action user-build
     powershell -File scripts/softhsm_wsl.ps1 -Action init

See docs/ops/softhsm_ceremony.md
EOF
  RESULT_CODE=MISSING_SOFTHSM
  RESULT_DETAIL="softhsm2-util absent"
  write_evidence
  exit 0
fi

if ! command -v pkcs11-tool >/dev/null 2>&1; then
  echo "WARN: pkcs11-tool not found (optional). Install opensc, or:"
  echo "  bash scripts/softhsm_fix_pkcs11_tool.sh"
fi

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.config/softhsm2/softhsm2.conf}"
mkdir -p "$(dirname "$SOFTHSM2_CONF")"
if [[ ! -f "$SOFTHSM2_CONF" ]]; then
  TOKDIR="${SOFTHSM2_TOKDIR:-$HOME/softhsm2/tokens}"
  mkdir -p "$TOKDIR"
  cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKDIR
objectstore.backend = file
log.level = INFO
EOF
  echo "Wrote default SoftHSM config: $SOFTHSM2_CONF"
fi

echo "=== AEGIS SoftHSM init (slot=$SLOT label=$LABEL dry_run=$DRY_RUN) ==="
echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "softhsm2-util=$(command -v softhsm2-util)"
echo "AEGIS_PKCS11_MODULE=${AEGIS_PKCS11_MODULE:-}"

if ! softhsm2-util --show-slots >/tmp/aegis-softhsm-slots.txt 2>&1; then
  echo "ERROR: softhsm2-util --show-slots failed:"
  cat /tmp/aegis-softhsm-slots.txt || true
  echo "Hint: deb-extracted util may hardcode /usr/lib/.../libsofthsm2.so;"
  echo "      use bash scripts/softhsm_user_build.sh instead."
  RESULT_CODE=SHOW_SLOTS_FAIL
  RESULT_DETAIL="show-slots failed"
  write_evidence
  exit 1
fi

if grep -q "Label: *$LABEL" /tmp/aegis-softhsm-slots.txt; then
  echo "Token '$LABEL' already present — skipping init."
  RESULT_CODE=ALREADY_INITIALIZED
  RESULT_DETAIL="label=$LABEL"
  if [[ "$DRY_RUN" == "1" ]]; then
    RESULT_CODE=DRY_RUN
    RESULT_DETAIL="would skip init; token already present"
  fi
else
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "DRY_RUN: would run softhsm2-util --init-token --slot $SLOT --label $LABEL"
    RESULT_CODE=DRY_RUN
    RESULT_DETAIL="would init token"
    cat /tmp/aegis-softhsm-slots.txt || true
    write_evidence
    exit 0
  fi
  if ! softhsm2-util --init-token --slot "$SLOT" --label "$LABEL" \
      --so-pin "$SO_PIN" --pin "$USER_PIN"; then
    RESULT_CODE=INIT_FAIL
    RESULT_DETAIL="init-token failed"
    write_evidence
    exit 1
  fi
  echo "Initialized token label='$LABEL' on slot $SLOT"
  RESULT_CODE=SUCCEEDED
  RESULT_DETAIL="initialized label=$LABEL"
fi

softhsm2-util --show-slots || true

if command -v pkcs11-tool >/dev/null 2>&1; then
  MODULE="${AEGIS_PKCS11_MODULE:-}"
  if [[ -z "$MODULE" ]]; then
    if [[ -f "${HOME}/.local/lib/softhsm/libsofthsm2.so" ]]; then
      MODULE="${HOME}/.local/lib/softhsm/libsofthsm2.so"
    else
      MODULE="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    fi
  fi
  if [[ -f "$MODULE" ]]; then
    echo "--- pkcs11-tool slot smoke ---"
    export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
    if ! pkcs11-tool --module "$MODULE" --list-slots; then
      echo "WARN: pkcs11-tool failed (optional). Try: bash scripts/softhsm_fix_pkcs11_tool.sh"
    fi
  else
    echo "pkcs11 module not at $MODULE — set AEGIS_PKCS11_MODULE if different."
  fi
fi

# ALREADY_INITIALIZED / SUCCEEDED / DRY_RUN already set above; normalize empty.
if [[ -z "$RESULT_CODE" ]]; then
  RESULT_CODE=SUCCEEDED
  RESULT_DETAIL="token ready label=$LABEL"
fi

echo "Done. SoftHSM is a software token — not hardware custody."
echo "Lab smoke (no SoftHSM): cargo test -p aegis-topology custody::tests::simulated_hsm_lab_only_roundtrip"
echo "Contract: Pkcs11CustodyOps / HsmCustodyProvider still fail-closed until PKCS#11 wired."
write_evidence
exit 0
