#!/usr/bin/env bash
# Generate bridge-network pilot configs for deploy/compose/docker-compose.yml
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(cd "$(dirname "$0")" && pwd)/pilot_configs"
python3 "$ROOT/sim/scripts/generate_pilot_configs.py" --out "$OUT" --network bridge
echo "Docker pilot configs -> $OUT"
echo "Next: offline lint (no daemon)  python3 deploy/scripts/validate_compose_offline.py"
echo "  or with Docker:             docker compose -f deploy/compose/docker-compose.yml up --build"
