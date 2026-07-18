#!/usr/bin/env bash
# SoftHSM2 token init helper for AEGIS consortium ceremony pilot (WSL/Linux).
# Safe when softhsm2-util is missing: prints install hint and exits 0.
# Does NOT run in default CI. See docs/ops/softhsm_ceremony.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLOT="${AEGIS_SOFTHSM_SLOT:-0}"
LABEL="${AEGIS_SOFTHSM_TOKEN_LABEL:-aegis-ceremony}"
SO_PIN="${AEGIS_SOFTHSM_SO_PIN:-1234}"
USER_PIN="${AEGIS_SOFTHSM_USER_PIN:-1234}"

if ! command -v softhsm2-util >/dev/null 2>&1; then
  cat <<EOF
SoftHSM2 not found (softhsm2-util missing).

Install on Debian/Ubuntu WSL:
  sudo apt-get update && sudo apt-get install -y softhsm2 opensc

Then re-run:
  bash scripts/softhsm_init.sh

See docs/ops/softhsm_ceremony.md for PKCS#11 module path and AEGIS wiring.
EOF
  exit 0
fi

if ! command -v pkcs11-tool >/dev/null 2>&1; then
  echo "WARN: pkcs11-tool not found (optional). Install opensc for slot smoke checks."
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

echo "=== AEGIS SoftHSM init (slot=$SLOT label=$LABEL) ==="
echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"

if softhsm2-util --show-slots 2>/dev/null | grep -q "Label: *$LABEL"; then
  echo "Token '$LABEL' already present — skipping init."
else
  softhsm2-util --init-token --slot "$SLOT" --label "$LABEL" \
    --so-pin "$SO_PIN" --pin "$USER_PIN"
  echo "Initialized token label='$LABEL' on slot $SLOT"
fi

softhsm2-util --show-slots || true

if command -v pkcs11-tool >/dev/null 2>&1; then
  MODULE="${AEGIS_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}"
  if [[ -f "$MODULE" ]]; then
    echo "--- pkcs11-tool slot smoke ---"
    pkcs11-tool --module "$MODULE" --list-slots || true
  else
    echo "pkcs11 module not at $MODULE — set AEGIS_PKCS11_MODULE if different."
  fi
fi

echo "Done. Next: wire HsmCustodyProvider + Pkcs11CustodyOps (still fail-closed in-tree)."
echo "Lab path unchanged: SimulatedHsmProvider / SoftwareCustodyProvider."
