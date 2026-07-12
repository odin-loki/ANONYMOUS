#!/usr/bin/env python3
"""Analyze the real testnet trace through Phase 8 shapeability tooling."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TRACE = ROOT / "sim" / "data" / "real_testnet_trace.csv"
SLOT_SECONDS = 1.0
SYNTH_SLOTS = 40000
SYNTH_SEED = 103


def load_trace_events(path: Path) -> tuple[list[float], list[int], list[int], dict]:
    timestamps: list[float] = []
    payload_bytes: list[int] = []
    cell_counts: list[int] = []
    meta: dict = {"path": str(path)}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if line.startswith("# capture="):
                    meta["capture"] = line.split("=", 1)[1]
                if line.startswith("# vantage="):
                    meta["vantage"] = line.split("=", 1)[1]
                continue
            if line.startswith("timestamp,"):
                continue
            parts = line.split(",")
            if len(parts) != 3:
                continue
            timestamps.append(float(parts[0]))
            payload_bytes.append(int(parts[1]))
            cell_counts.append(int(parts[2]))
    return timestamps, payload_bytes, cell_counts, meta


def main() -> int:
    trace_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TRACE
    if not trace_path.exists():
        print(f"trace not found: {trace_path}", file=sys.stderr)
        return 1

    timestamps, payload_bytes, cell_counts, meta = load_trace_events(trace_path)
    if not timestamps:
        print("empty trace", file=sys.stderr)
        return 1

    t0, t1 = timestamps[0], timestamps[-1]
    duration = t1 - t0
    counts = traffic.load_trace_counts(timestamps, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    real_report = metrics.shapeability_report(counts)

    synth = traffic.synthetic_c2_like_counts(SYNTH_SLOTS, rng=np.random.default_rng(SYNTH_SEED))
    synth_report = metrics.shapeability_report(synth)

    result = {
        "trace_file": str(trace_path),
        "meta": meta,
        "n_events": len(timestamps),
        "duration_seconds": duration,
        "slot_seconds": SLOT_SECONDS,
        "n_slots": int(len(counts)),
        "events_per_slot_mean": float(counts.mean()),
        "events_per_slot_max": float(counts.max()),
        "total_cells_on_wire": int(sum(cell_counts)),
        "payload_bytes_mean": float(np.mean(payload_bytes)),
        "real_shapeability": {
            k: (None if isinstance(v, float) and np.isnan(v) else v)
            for k, v in real_report.items()
        },
        "synthetic_c2_like_shapeability": synth_report,
        "cv_ratio_real_over_synthetic": float(real_report["cv"] / synth_report["cv"]),
    }

    out_json = trace_path.with_suffix(".analysis.json")
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("=== Real testnet trace shapeability ===")
    print(f"file: {trace_path}")
    print(f"vantage: {meta.get('vantage', 'unknown')}")
    print(f"capture: {meta.get('capture', 'unknown')}")
    print(f"events={len(timestamps)}  duration={duration:.2f}s  slots={len(counts)}")
    print(f"per-slot mean={counts.mean():.3f}  max={counts.max():.0f}")
    print()
    print("real trace shapeability_report:")
    for k, v in real_report.items():
        print(f"  {k}: {v}")
    print()
    print("synthetic_c2_like stand-in (seed=103, n=40000):")
    for k, v in synth_report.items():
        print(f"  {k}: {v}")
    print()
    print(f"CV ratio (real / synthetic): {result['cv_ratio_real_over_synthetic']:.4f}")
    print(f"saved: {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
