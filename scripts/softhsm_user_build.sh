#!/usr/bin/env bash
# SoftHSM2 user-local build (no sudo install of softhsm2).
#
# Strategy:
#   1. Prefer system uuid-dev + libtool if present.
#   2. Else download those debs with `apt-get download` and extract headers/tools
#      into ~/.local/aegis-build-deps (no sudo, non-interactive).
#   3. Build SoftHSMv2 into --prefix=$HOME/.local.
#
# Never prompts for a sudo password. If sudo is needed for something else, exit
# with a clear code instead of hanging.
#
# Exit codes:
#   0  success (softhsm2-util installed under ~/.local)
#   2  missing downloadable build deps / network failure
#   3  configure/build/install failure
#
# See docs/ops/softhsm_ceremony.md
set -euo pipefail

PREFIX="${AEGIS_SOFTHSM_PREFIX:-$HOME/.local}"
DEPS="${AEGIS_SOFTHSM_DEPS:-$HOME/.local/aegis-build-deps}"
SRC="${AEGIS_SOFTHSM_SRC:-$HOME/src}"
DEBDIR="${AEGIS_SOFTHSM_DEBDIR:-/tmp/aegis-softhsm-build-debs}"
VERSION="${AEGIS_SOFTHSM_VERSION:-2.6.1}"
DRY_RUN="${AEGIS_SOFTHSM_DRY_RUN:-0}"

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit "${2:-3}"; }

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

log "=== SoftHSM2 user-local build ==="
log "PREFIX=$PREFIX VERSION=$VERSION DRY_RUN=$DRY_RUN"

if [[ -x "${PREFIX}/bin/softhsm2-util" && -z "${AEGIS_SOFTHSM_FORCE_REBUILD:-}" ]]; then
  log "Already installed: ${PREFIX}/bin/softhsm2-util"
  "${PREFIX}/bin/softhsm2-util" --version || true
  log "Skipping rebuild (set AEGIS_SOFTHSM_FORCE_REBUILD=1 to rebuild)."
  exit 0
fi

need_uuid=0
need_libtool=0
[[ -f /usr/include/uuid/uuid.h ]] || need_uuid=1
command -v libtool >/dev/null 2>&1 || need_libtool=1

log "System uuid.h: $([[ $need_uuid -eq 0 ]] && echo OK || echo MISSING)"
log "System libtool: $([[ $need_libtool -eq 0 ]] && echo OK || echo MISSING)"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN: would download uuid-dev/libtool debs if missing, then:"
  log "  curl SoftHSMv2-${VERSION}, autogen, configure --prefix=$PREFIX --disable-gost, make install"
  exit 0
fi

mkdir -p "$DEBDIR" "$DEPS" "$SRC" "$PREFIX"

if [[ $need_uuid -eq 1 || $need_libtool -eq 1 ]]; then
  log "Fetching build-dep debs via apt-get download (no sudo) ..."
  cd "$DEBDIR"
  for pkg in uuid-dev libuuid1 libtool libtool-bin; do
    if ! ls ${pkg}_*.deb >/dev/null 2>&1; then
      apt-get download "$pkg" || die "apt-get download $pkg failed (network/apt cache?)" 2
    fi
  done
  for deb in "$DEBDIR"/*.deb; do
    [[ -f "$deb" ]] || continue
    dpkg-deb -x "$deb" "$DEPS"
  done
fi

export PATH="$DEPS/usr/bin:$PREFIX/bin:$PATH"
export CPATH="$DEPS/usr/include:${CPATH:-}"
export C_INCLUDE_PATH="$DEPS/usr/include:${C_INCLUDE_PATH:-}"
export LIBRARY_PATH="$DEPS/usr/lib/x86_64-linux-gnu:$DEPS/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$DEPS/usr/lib/x86_64-linux-gnu:$DEPS/lib/x86_64-linux-gnu:$PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$DEPS/usr/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}"

if [[ ! -f /usr/include/uuid/uuid.h && ! -f "$DEPS/usr/include/uuid/uuid.h" ]]; then
  die "uuid headers unavailable after deb extract" 2
fi
if ! command -v libtool >/dev/null 2>&1 && [[ ! -x "$DEPS/usr/bin/libtool" ]]; then
  # SoftHSM ships its own libtool after autogen; libtoolize is enough for many hosts.
  if ! command -v libtoolize >/dev/null 2>&1; then
    die "libtool/libtoolize unavailable after deb extract" 2
  fi
  log "WARN: libtool binary missing; continuing with libtoolize (autogen may vendor libtool)"
fi

TARBALL="$SRC/${VERSION}.tar.gz"
SRCDIR="$SRC/SoftHSMv2-${VERSION}"
if [[ ! -d "$SRCDIR" ]]; then
  log "Fetching SoftHSM2 ${VERSION} source ..."
  curl -fsSL -o "$TARBALL" \
    "https://github.com/opendnssec/SoftHSMv2/archive/refs/tags/${VERSION}.tar.gz" \
    || die "curl SoftHSM source failed" 2
  tar xzf "$TARBALL" -C "$SRC"
fi

cd "$SRCDIR"
if [[ ! -f configure ]]; then
  ./autogen.sh || die "autogen.sh failed" 3
fi

./configure --prefix="$PREFIX" --disable-gost \
  CPPFLAGS="-I$DEPS/usr/include" \
  LDFLAGS="-L$DEPS/usr/lib/x86_64-linux-gnu -L$DEPS/lib/x86_64-linux-gnu" \
  || die "configure failed" 3

make -j"$(nproc)" || die "make failed" 3
make install || die "make install failed" 3

export PATH="$PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
softhsm2-util --version
test -f "$PREFIX/lib/softhsm/libsofthsm2.so" || die "module missing after install" 3

log "=== SoftHSM2 installed to $PREFIX ==="
log "Next: bash scripts/softhsm_init.sh"
log "Module: $PREFIX/lib/softhsm/libsofthsm2.so"
