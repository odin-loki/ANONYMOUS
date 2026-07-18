#!/usr/bin/env bash
# Post-success verification: probe, dry-run, init (already-initialized), custody tests.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/bin:${PATH}"
export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
export AEGIS_PKCS11_MODULE="${AEGIS_PKCS11_MODULE:-${HOME}/.local/lib/softhsm/libsofthsm2.so}"
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.config/softhsm2/softhsm2.conf}"

echo "===== probe ====="
bash scripts/softhsm_probe.sh || true

echo "===== dry-run ====="
bash scripts/softhsm_init.sh --dry-run

echo "===== init (expect already initialized) ====="
bash scripts/softhsm_init.sh --evidence sim/softhsm_init_evidence.txt

echo "===== optional pkcs11-tool ====="
bash scripts/softhsm_fix_pkcs11_tool.sh || echo "pkcs11 optional failed (ok)"

echo "===== cargo custody tests ====="
cd "$ROOT/crates"
# Single filter substring matches all custody unit tests in aegis-topology.
cargo test -p aegis-topology custody::tests -- --nocapture

echo "===== ALL VERIFY DONE ====="
