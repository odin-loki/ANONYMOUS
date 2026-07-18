#!/usr/bin/env bash
# Pull opensc + runtime deps into ~/.local so pkcs11-tool can load (no sudo).
# Optional: SoftHSM token smoke works with softhsm2-util alone.
#
# Exit codes:
#   0  pkcs11-tool --list-slots succeeded (or tool installed + module listed)
#   1  could not make pkcs11-tool usable
set -euo pipefail

PREFIX="${HOME}/.local"
DEBDIR="${AEGIS_SOFTHSM_DEBDIR:-/tmp/aegis-softhsm-probe}"
STAGE=/tmp/aegis-softhsm-opensc-stage

mkdir -p "$DEBDIR" "$PREFIX/lib" "$PREFIX/bin"
cd "$DEBDIR"

download_pkg() {
  local pkg="$1"
  if ls "${pkg}"_*.deb >/dev/null 2>&1; then
    return 0
  fi
  if apt-get download "$pkg"; then
    return 0
  fi
  echo "WARN: could not download $pkg"
  return 1
}

# opensc transitive deps (Ubuntu noble); ignore missing names
for pkg in libeac3 opensc opensc-pkcs11 libpcsclite1 zlib1g libssl3; do
  download_pkg "$pkg" || true
done
# libopensc may be embedded in opensc-pkcs11 package on some releases
download_pkg libopensc8 || download_pkg libopensc6 || true

rm -rf "$STAGE"
mkdir -p "$STAGE"
shopt -s nullglob
for deb in "$DEBDIR"/*.deb; do
  dpkg-deb -x "$deb" "$STAGE" || true
done
shopt -u nullglob

if [[ -f "$STAGE/usr/bin/pkcs11-tool" ]]; then
  install -m 755 "$STAGE/usr/bin/pkcs11-tool" "$PREFIX/bin/pkcs11-tool"
fi

# Copy shared libs into ~/.local/lib (skip SoftHSM module tree).
# Also flatten libs that live under multiarch dirs (libeac.so.3, libopensc, …).
while IFS= read -r -d '' so; do
  case "$so" in
    */softhsm/*) continue ;;
  esac
  cp -a "$so" "$PREFIX/lib/" 2>/dev/null || true
done < <(find "$STAGE" \( -type f -o -type l \) -name '*.so*' -print0 2>/dev/null || true)

# Explicit copy for known opensc deps (symlinks matter for SONAME resolution)
for pattern in 'libeac.so*' 'libopensc.so*' 'libpcsclite.so*'; do
  # shellcheck disable=SC2086
  find "$STAGE" \( -type f -o -type l \) -name "$pattern" -exec cp -a {} "$PREFIX/lib/" \; 2>/dev/null || true
done

export PATH="$PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
MODULE="${AEGIS_PKCS11_MODULE:-$PREFIX/lib/softhsm/libsofthsm2.so}"

if ! command -v pkcs11-tool >/dev/null 2>&1; then
  echo "ERROR: pkcs11-tool still missing after deb extract"
  exit 1
fi

echo "pkcs11-tool=$(command -v pkcs11-tool)"
ldd "$(command -v pkcs11-tool)" || true

if [[ ! -f "$MODULE" ]]; then
  echo "WARN: module missing at $MODULE — install SoftHSM first (softhsm_user_build.sh)"
  exit 1
fi

echo "--- pkcs11-tool --list-slots ---"
if pkcs11-tool --module "$MODULE" --list-slots; then
  echo "OK: pkcs11-tool smoke succeeded"
  exit 0
fi
echo "ERROR: pkcs11-tool --list-slots failed (check missing .so via ldd above)"
exit 1
