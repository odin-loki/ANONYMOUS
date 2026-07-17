"""
Load relay post-forward trace CSV (Phase 8 post-shaping vantage).

Format: timestamp,cell_count,event_type  (unix_secs_f64, u32, forward|cover|exit)

Run:  cd sim && PYTHONPATH=. python scripts/load_relay_forward_trace.py [path]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "sim" / "data" / "relay_forward_trace_sample.csv"

sys.path.insert(0, str(ROOT / "sim"))
from aegis_sim import traffic  # noqa: E402


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    if not path.exists():
        print(f"missing trace: {path}", file=sys.stderr)
        return 1
    rows = traffic.load_relay_forward_trace(path)
    print(f"loaded {len(rows)} events from {path}")
    for ts, cells, kind in rows[:5]:
        print(f"  {ts:.6}  cells={cells}  {kind}")
    if len(rows) > 5:
        print(f"  … ({len(rows) - 5} more)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
