#!/usr/bin/env python3
"""Compare multi-process vs in-process real testnet traces via shapeability_report."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
IN_PROCESS = ROOT / "sim" / "data" / "real_testnet_trace.csv"
MULTIPROCESS = ROOT / "sim" / "data" / "real_multiprocess_trace.csv"
SLOT_SECONDS = 1.0


def load_trace_events(path: Path) -> tuple[list[float], dict]:
    timestamps: list[float] = []
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
            timestamps.append(float(line.split(",")[0]))
    return timestamps, meta


def analyze(path: Path) -> dict:
    timestamps, meta = load_trace_events(path)
    t0, t1 = timestamps[0], timestamps[-1]
    counts = traffic.load_trace_counts(timestamps, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)
    return {
        "trace_file": str(path),
        "meta": meta,
        "n_events": len(timestamps),
        "duration_seconds": t1 - t0,
        "n_slots": int(len(counts)),
        "events_per_slot_mean": float(counts.mean()),
        "events_per_slot_max": float(counts.max()),
        "shapeability": {
            k: (None if isinstance(v, float) and np.isnan(v) else v)
            for k, v in report.items()
        },
    }


def main() -> int:
    mp_path = Path(sys.argv[1]) if len(sys.argv) > 1 else MULTIPROCESS
    ip_path = Path(sys.argv[2]) if len(sys.argv) > 2 else IN_PROCESS

    if not mp_path.exists():
        print(f"multiprocess trace not found: {mp_path}", file=sys.stderr)
        return 1
    if not ip_path.exists():
        print(f"in-process trace not found: {ip_path}", file=sys.stderr)
        return 1

    mp = analyze(mp_path)
    ip = analyze(ip_path)

    mp_cv = mp["shapeability"]["cv"]
    ip_cv = ip["shapeability"]["cv"]
    mp_mm = mp["shapeability"].get("min_multiple")
    ip_mm = ip["shapeability"].get("min_multiple")

    result = {
        "multiprocess": mp,
        "in_process": ip,
        "comparison": {
            "cv_ratio_multiprocess_over_in_process": float(mp_cv / ip_cv),
            "min_multiple_delta": (None if mp_mm is None or ip_mm is None else float(mp_mm - ip_mm)),
            "same_tier": mp["shapeability"]["tier"] == ip["shapeability"]["tier"],
        },
    }

    out_json = mp_path.with_name("real_multiprocess_trace.analysis.json")
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("=== Multi-process vs in-process shapeability ===")
    print(f"multiprocess: {mp_path.name}  events={mp['n_events']}  duration={mp['duration_seconds']:.2f}s")
    for k, v in mp["shapeability"].items():
        print(f"  mp {k}: {v}")
    print()
    print(f"in-process:   {ip_path.name}  events={ip['n_events']}  duration={ip['duration_seconds']:.2f}s")
    for k, v in ip["shapeability"].items():
        print(f"  ip {k}: {v}")
    print()
    print(f"CV ratio (mp/ip): {result['comparison']['cv_ratio_multiprocess_over_in_process']:.4f}")
    print(f"same tier: {result['comparison']['same_tier']}")
    print(f"saved: {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
