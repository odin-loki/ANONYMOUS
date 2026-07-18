#!/usr/bin/env bash
# Probe host prerequisites for the AEGIS Docker / loopback pilot.
# Never starts containers. Never runs hanging installs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE_DIR="${1:-$ROOT/deploy/evidence}"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_FILE="$EVIDENCE_DIR/host_probe.txt"

log() { printf '%s\n' "$*" | tee -a "$EVIDENCE_FILE"; }

: >"$EVIDENCE_FILE"
log "== AEGIS pilot prerequisite probe =="
log "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "repo: $ROOT"
log "host: $(uname -s 2>/dev/null || echo unknown)"
log ""

have() { command -v "$1" >/dev/null 2>&1; }

log "--- PATH tools ---"
if have docker; then
  log "docker: $(command -v docker)"
  docker version 2>&1 | tee -a "$EVIDENCE_FILE" || log "docker engine: unreachable"
  docker compose version 2>&1 | tee -a "$EVIDENCE_FILE" || log "docker compose: FAILED"
else
  log "docker: MISSING"
fi

if have podman; then
  log "podman: $(command -v podman)"
  podman version 2>&1 | head -5 | tee -a "$EVIDENCE_FILE" || true
else
  log "podman: MISSING"
fi

if have python3; then
  log "python3: $(command -v python3) ($(python3 --version 2>&1))"
elif have python; then
  log "python: $(command -v python) ($(python --version 2>&1))"
else
  log "python: MISSING"
fi

if have cargo; then
  log "cargo: $(command -v cargo) ($(cargo --version 2>&1))"
elif [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  log "cargo: $HOME/.cargo/bin/cargo ($("$HOME/.cargo/bin/cargo" --version 2>&1))"
else
  log "cargo: MISSING"
fi

AEGIS=""
for c in \
  "$ROOT/crates/target/debug/aegis-node" \
  "$ROOT/crates/target/release/aegis-node" \
  "$(command -v aegis-node 2>/dev/null || true)"; do
  if [[ -n "$c" && -x "$c" ]]; then AEGIS="$c"; break; fi
done
log "aegis-node: ${AEGIS:-MISSING (optional for offline TOML/YAML lint)}"

PYYAML=no
if have python3 && python3 -c "import yaml" 2>/dev/null; then PYYAML=yes
elif have python && python -c "import yaml" 2>/dev/null; then PYYAML=yes
fi
log "PyYAML: $PYYAML"

log ""
log "--- Verdict ---"
if have docker && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  log "Docker: PRESENT — you may run compose (see docs/ops/PILOT.md)."
  log "  ./deploy/compose/generate_configs.sh"
  log "  docker compose -f deploy/compose/docker-compose.yml up --build"
else
  log "Docker: ABSENT or engine not running — do NOT claim containers ran."
  log "Offline path still available:"
  log "  python3 deploy/scripts/validate_compose_offline.py"
  log "  ./scripts/run_pilot.sh   # loopback (needs cargo + python)"
fi

log ""
log "--- Unblock steps ---"
log "Linux: install Docker Engine + Compose v2 from your distro docs, then:"
log "  sudo systemctl enable --now docker"
log "  docker version && docker compose version"
log "Windows host: see docs/ops/PILOT.md § Windows Docker Desktop + WSL2"
log "  (interactive Docker Desktop installer UI — not automated here)"
log "Evidence: this probe never starts containers."
log "Wrote $EVIDENCE_FILE"
