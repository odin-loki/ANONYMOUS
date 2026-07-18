#!/usr/bin/env bash
# Non-interactive SoftHSM / OpenSC / build-dep probe for WSL/Linux.
# Never prompts for sudo. Prints machine-readable STATUS lines.
#
# Exit codes:
#   0  SoftHSM usable (softhsm2-util + module load path OK)
#   1  SoftHSM missing but recoverable via documented unblock
#   2  Unexpected probe failure
#
# Usage:
#   bash scripts/softhsm_probe.sh
#   bash scripts/softhsm_probe.sh --json   # compact key=value summary still on stdout
set -euo pipefail

JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

status_line() { printf 'STATUS %s=%s\n' "$1" "$2"; }
info() { printf 'INFO %s\n' "$*"; }

# Prefer user-local SoftHSM
if [[ -x "${HOME}/.local/bin/softhsm2-util" ]]; then
  export PATH="${HOME}/.local/bin:${PATH}"
  export LD_LIBRARY_PATH="${HOME}/.local/lib:${LD_LIBRARY_PATH:-}"
fi

info "host=$(uname -srm 2>/dev/null || uname -a)"
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  info "os=${PRETTY_NAME:-unknown}"
fi
info "user=$(whoami) groups=$(groups | tr ' ' ',')"

# sudo non-interactive probe (never hang)
if sudo -n true 2>/dev/null; then
  status_line SUDO_NOPASSWD yes
else
  status_line SUDO_NOPASSWD no
  status_line SUDO_BLOCKER password_required_or_denied
fi

UTIL="$(command -v softhsm2-util 2>/dev/null || true)"
if [[ -n "$UTIL" ]]; then
  status_line SOFTHSM2_UTIL "$UTIL"
  status_line SOFTHSM2_VERSION "$(softhsm2-util --version 2>/dev/null | head -1 || echo unknown)"
else
  status_line SOFTHSM2_UTIL missing
fi

PKCS11_TOOL="$(command -v pkcs11-tool 2>/dev/null || true)"
if [[ -n "$PKCS11_TOOL" ]]; then
  status_line PKCS11_TOOL "$PKCS11_TOOL"
else
  status_line PKCS11_TOOL missing
fi

MODULE=""
for cand in \
  "${AEGIS_PKCS11_MODULE:-}" \
  "${HOME}/.local/lib/softhsm/libsofthsm2.so" \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  /usr/lib/softhsm/libsofthsm2.so
do
  [[ -n "$cand" && -f "$cand" ]] || continue
  MODULE="$cand"
  break
done
if [[ -n "$MODULE" ]]; then
  status_line PKCS11_MODULE "$MODULE"
else
  status_line PKCS11_MODULE missing
fi

# apt cache (no install)
if command -v apt-cache >/dev/null 2>&1; then
  status_line APT_SOFTHSM2_CANDIDATE "$(apt-cache policy softhsm2 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  status_line APT_OPENSC_CANDIDATE "$(apt-cache policy opensc 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
else
  status_line APT_SOFTHSM2_CANDIDATE n/a
fi

# build deps
[[ -f /usr/include/uuid/uuid.h ]] && status_line UUID_DEV present || status_line UUID_DEV missing
command -v libtool >/dev/null 2>&1 && status_line LIBTOOL present || status_line LIBTOOL missing
command -v libtoolize >/dev/null 2>&1 && status_line LIBTOOLIZE present || status_line LIBTOOLIZE missing
command -v gcc >/dev/null 2>&1 && status_line GCC present || status_line GCC missing
command -v make >/dev/null 2>&1 && status_line MAKE present || status_line MAKE missing
[[ -f /usr/include/openssl/ssl.h ]] && status_line LIBSSL_DEV present || status_line LIBSSL_DEV missing
command -v autoconf >/dev/null 2>&1 && status_line AUTOCONF present || status_line AUTOCONF missing
command -v automake >/dev/null 2>&1 && status_line AUTOMAKE present || status_line AUTOMAKE missing
command -v curl >/dev/null 2>&1 && status_line CURL present || status_line CURL missing

# usability: can show-slots with a throwaway conf if util exists
USABLE=0
if [[ -n "$UTIL" ]]; then
  CONF="${SOFTHSM2_CONF:-}"
  if [[ -z "$CONF" ]]; then
    CONF=$(mktemp /tmp/softhsm-probe-XXXX.conf)
    TOK=$(mktemp -d /tmp/softhsm-probe-tok-XXXX)
    cat >"$CONF" <<EOF
directories.tokendir = $TOK
objectstore.backend = file
log.level = ERROR
EOF
    export SOFTHSM2_CONF="$CONF"
  fi
  if softhsm2-util --show-slots >/dev/null 2>&1; then
    USABLE=1
    status_line SHOW_SLOTS ok
  else
    status_line SHOW_SLOTS fail
    # Common failure: Debian util hardcodes /usr/lib/.../libsofthsm2.so
    status_line SHOW_SLOTS_HINT "deb-extracted util needs system module path; use scripts/softhsm_user_build.sh"
  fi
fi
status_line SOFTHSM_USABLE "$USABLE"

if [[ "$USABLE" -eq 1 ]]; then
  info "SoftHSM usable. Run: bash scripts/softhsm_init.sh"
  exit 0
fi

info "SoftHSM not usable. Unblock options (pick one):"
info "A) sudo apt-get update && sudo apt-get install -y softhsm2 opensc"
info "B) bash scripts/softhsm_user_build.sh   # no sudo; apt-get download uuid-dev/libtool if needed"
info "C) From Windows: powershell -File scripts/softhsm_wsl.ps1 -Action probe"
exit 1
