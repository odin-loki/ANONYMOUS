#!/usr/bin/env bash
# Operator pilot: 4-node loopback mix path with production-checklist defaults.
# Docker bridge variant: deploy/compose/ (probe: deploy/scripts/check_pilot_prereqs.sh).
# Offline compose lint (no daemon): python3 deploy/scripts/validate_compose_offline.py
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATES="$REPO_ROOT/crates"
CONFIG_DIR="$REPO_ROOT/sim/data/pilot_configs"
GEN_SCRIPT="$REPO_ROOT/sim/scripts/generate_pilot_configs.py"
SENDS=3
COVER_SECS=2.0
TAU_SECS=0.35
EPHEMERAL=0
SKIP_BUILD=0

usage() {
  echo "Usage: $0 [--ephemeral-ports] [--sends N] [--cover-secs F] [--tau-secs F] [--skip-build]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ephemeral-ports) EPHEMERAL=1; shift ;;
    --sends) SENDS="$2"; shift 2 ;;
    --cover-secs) COVER_SECS="$2"; shift 2 ;;
    --tau-secs) TAU_SECS="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1"; usage; exit 1 ;;
  esac
done

find_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
    return
  fi
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    echo "$HOME/.cargo/bin/cargo"
    return
  fi
  echo "cargo not found" >&2
  exit 1
}

terminate_nodes() {
  if [[ ${#NODE_PIDS[@]:-0} -gt 0 ]]; then
    for pid in "${NODE_PIDS[@]}"; do
      kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
  fi
}
trap terminate_nodes EXIT

NODE_PIDS=()

echo "== AEGIS operator pilot (loopback) =="
GEN_ARGS=(--out "$CONFIG_DIR")
[[ "$EPHEMERAL" -eq 1 ]] && GEN_ARGS+=(--ephemeral-ports)
[[ "$SKIP_BUILD" -eq 1 ]] && GEN_ARGS+=(--skip-build)
python3 "$GEN_SCRIPT" "${GEN_ARGS[@]}"

CARGO="$(find_cargo)"
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building aegis-node and aegis-client..."
  (cd "$CRATES" && "$CARGO" build --quiet -p aegis-node -p aegis-client)
fi

NODE_BIN="$CRATES/target/debug/aegis-node"
CLIENT_BIN="$CRATES/target/debug/aegis-client"
[[ -x "$NODE_BIN" ]] || { echo "missing $NODE_BIN" >&2; exit 1; }
[[ -x "$CLIENT_BIN" ]] || { echo "missing $CLIENT_BIN" >&2; exit 1; }

PORTS=()
for i in 0 1 2 3; do
  line="$(grep -E '^listen\s*=' "$CONFIG_DIR/node$i.toml" | head -1)"
  port="$(echo "$line" | sed -n 's/.*127\.0\.0\.1:\([0-9]*\).*/\1/p')"
  PORTS+=("$port")
done

echo "Starting 4 nodes (ports=${PORTS[*]})..."
for i in 0 1 2 3; do
  (cd "$CONFIG_DIR" && "$NODE_BIN" --config "node$i.toml") >/dev/null 2>&1 &
  NODE_PIDS+=("$!")
done

wait_listen() {
  local port="$1"
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    if (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.08
  done
  echo "timed out waiting for 127.0.0.1:$port" >&2
  return 1
}

for p in "${PORTS[@]}"; do
  wait_listen "$p"
done

echo "Nodes listening. Running $SENDS paced client send(s)..."
OK=0
for ((i=0; i<SENDS; i++)); do
  if (cd "$CONFIG_DIR" && "$CLIENT_BIN" --config client.toml \
      --payload "pilot-$i" --cover-secs "$COVER_SECS" --tau-secs "$TAU_SECS"); then
    OK=$((OK + 1))
  fi
  sleep 0.5
done

sleep 2

echo
echo "== coarse health =="
ALIVE=0
for i in 0 1 2 3; do
  pid="${NODE_PIDS[$i]}"
  if kill -0 "$pid" 2>/dev/null; then
    ALIVE=$((ALIVE + 1))
    echo "  node$i : running (pid $pid, port ${PORTS[$i]})"
  else
    echo "  node$i : EXITED"
  fi
done

EXIT_LOG="$CONFIG_DIR/data/exit_deliveries.log"
if [[ -f "$EXIT_LOG" ]]; then
  lines="$(wc -l < "$EXIT_LOG" | tr -d ' ')"
  echo "  exit deliveries log: ${lines} line(s)"
else
  echo "  exit deliveries log: (not yet created)"
fi

QUORUM_LOG="$CONFIG_DIR/data/health_quorum.log"
if [[ -f "$QUORUM_LOG" ]]; then
  bytes="$(wc -c < "$QUORUM_LOG" | tr -d ' ')"
  echo "  health quorum log: ${bytes} byte(s)"
else
  echo "  health quorum log: (none yet — gossip quorum may need longer interval)"
fi

echo
echo "Client sends OK: $OK / $SENDS"
if [[ "$ALIVE" -lt 4 || "$OK" -lt "$SENDS" ]]; then
  exit 1
fi
echo "Pilot smoke passed."
