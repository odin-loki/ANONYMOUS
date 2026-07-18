#!/usr/bin/env bash
# SoftHSM ceremony regression harness (WSL/Linux, no Docker, no sudo hang).
#
# Re-runs the operator path after a prior successful user-build + token init:
#   probe → dry-run → init (expect ALREADY_INITIALIZED) → optional pkcs11 → custody tests
#
# SoftHSM remains a software token — never claim hardware custody.
#
# Usage:
#   bash scripts/softhsm_ceremony_regress.sh
#   bash scripts/softhsm_ceremony_regress.sh --evidence sim/softhsm_ceremony_regress.txt
#   powershell -File scripts/softhsm_wsl.ps1 -Action regress -Evidence
#
# Exit:
#   0  all steps ok (SoftHSM usable + custody tests green)
#   1  SoftHSM missing / not usable (recover via softhsm_user_build.sh)
#   2  unexpected failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVIDENCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence)
      EVIDENCE="${2:-}"
      shift 2
      ;;
    --evidence=*)
      EVIDENCE="${1#--evidence=}"
      shift
      ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

export PATH="${HOME}/.local/bin:${PATH}"
export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
export AEGIS_PKCS11_MODULE="${AEGIS_PKCS11_MODULE:-${HOME}/.local/lib/softhsm/libsofthsm2.so}"
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.config/softhsm2/softhsm2.conf}"

EVIDENCE_FILE="${EVIDENCE:-$ROOT/sim/softhsm_ceremony_regress.txt}"
mkdir -p "$(dirname "$EVIDENCE_FILE")"

{
  echo "# AEGIS SoftHSM ceremony regression"
  echo "# Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Host: $(uname -srm 2>/dev/null || uname -a)"
  echo "# User: $(whoami)"
  echo "# Repo: $ROOT"
  echo "# Tip: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
  echo "SoftHSM is a software token only. Do NOT claim hardware custody."
  echo "sudo: never used without -n (probe only)."
  echo
} >"$EVIDENCE_FILE"

log() { echo "$@" | tee -a "$EVIDENCE_FILE"; }
fail() {
  log "RESULT_CODE=FAIL detail=$*"
  exit 2
}

log "===== 1/5 probe (no sudo hang) ====="
if ! bash scripts/softhsm_probe.sh 2>&1 | tee -a "$EVIDENCE_FILE"; then
  log "RESULT_CODE=MISSING_SOFTHSM"
  log "Unblock: bash scripts/softhsm_user_build.sh && bash scripts/softhsm_init.sh"
  exit 1
fi

log ""
log "===== 2/5 dry-run ====="
bash scripts/softhsm_init.sh --dry-run 2>&1 | tee -a "$EVIDENCE_FILE" || fail "dry-run"

log ""
log "===== 3/5 init (expect ALREADY_INITIALIZED) ====="
# Append RESULT_CODE block into the shared init evidence + this regress log.
bash scripts/softhsm_init.sh --evidence sim/softhsm_init_evidence.txt 2>&1 | tee -a "$EVIDENCE_FILE" || fail "init"

if ! grep -q 'aegis-ceremony' <<<"$(softhsm2-util --show-slots 2>/dev/null || true)"; then
  fail "token label aegis-ceremony not visible in show-slots"
fi
log "TOKEN_LABEL_CHECK=ok (aegis-ceremony)"

log ""
log "===== 4/5 optional pkcs11-tool ====="
if bash scripts/softhsm_fix_pkcs11_tool.sh 2>&1 | tee -a "$EVIDENCE_FILE"; then
  if command -v pkcs11-tool >/dev/null 2>&1; then
    pkcs11-tool --module "$AEGIS_PKCS11_MODULE" --list-slots 2>&1 | tee -a "$EVIDENCE_FILE" || true
  fi
  log "PKCS11_TOOL_STEP=ok"
else
  log "PKCS11_TOOL_STEP=skipped_or_optional_fail (ok for ceremony token path)"
fi

log ""
log "===== 5/5 cargo custody tests (SimulatedHsm / fail-closed Hardware) ====="
if ! command -v cargo >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo missing in WSL"
fi
(
  cd "$ROOT/crates"
  cargo test -p aegis-topology custody::tests -- --nocapture
) 2>&1 | tee -a "$EVIDENCE_FILE" || fail "custody tests"

log ""
log "RESULT_CODE=SUCCEEDED"
log "HARDWARE_CUSTODY_CLAIM=no"
log "evidence_file=$EVIDENCE_FILE"
log "===== CEREMONY REGRESS DONE ====="
exit 0
