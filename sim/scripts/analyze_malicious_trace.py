#!/usr/bin/env python3
"""Analyze malicious flood trace vs benign real trace and synthetic stand-in."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MALICIOUS = ROOT / "sim" / "data" / "real_testnet_malicious_trace.csv"
DEFAULT_BENIGN = ROOT / "sim" / "data" / "real_testnet_trace.csv"
SLOT_SECONDS = 1.0
SYNTH_SLOTS = 40000
SYNTH_SEED = 103


def load_trace_events(path: Path) -> tuple[list[float], list[int], list[int], list[bool], dict]:
    timestamps: list[float] = []
    payload_bytes: list[int] = []
    cell_counts: list[int] = []
    send_ok: list[bool] = []
    meta: dict = {"path": str(path)}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if line.startswith("# capture="):
                    meta["capture"] = line.split("=", 1)[1]
                if line.startswith("# vantage="):
                    meta["vantage"] = line.split("=", 1)[1]
                if line.startswith("# relay_stats"):
                    meta["relay_stats"] = line.split("=", 1)[1]
                continue
            if line.startswith("timestamp,"):
                continue
            parts = line.split(",")
            if len(parts) == 3:
                timestamps.append(float(parts[0]))
                payload_bytes.append(int(parts[1]))
                cell_counts.append(int(parts[2]))
                send_ok.append(True)
            elif len(parts) == 4:
                timestamps.append(float(parts[0]))
                payload_bytes.append(int(parts[1]))
                cell_counts.append(int(parts[2]))
                send_ok.append(parts[3] == "1")
    return timestamps, payload_bytes, cell_counts, send_ok, meta


def analyze(path: Path) -> dict:
    timestamps, payload_bytes, cell_counts, send_ok, meta = load_trace_events(path)
    if not timestamps:
        raise ValueError(f"empty trace: {path}")
    t0, t1 = timestamps[0], timestamps[-1]
    duration = t1 - t0
    counts = traffic.load_trace_counts(timestamps, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)
    inter_gaps = np.diff(timestamps) if len(timestamps) > 1 else np.array([])
    return {
        "trace_file": str(path),
        "meta": meta,
        "n_events": len(timestamps),
        "duration_seconds": duration,
        "slot_seconds": SLOT_SECONDS,
        "n_slots": int(len(counts)),
        "events_per_slot_mean": float(counts.mean()),
        "events_per_slot_max": float(counts.max()),
        "send_ok_rate": float(sum(send_ok) / len(send_ok)),
        "inter_send_gap_ms_median": float(np.median(inter_gaps) * 1000) if len(inter_gaps) else None,
        "inter_send_gap_ms_min": float(np.min(inter_gaps) * 1000) if len(inter_gaps) else None,
        "total_cells_on_wire": int(sum(cell_counts)),
        "payload_bytes_mean": float(np.mean(payload_bytes)),
        "shapeability": {
            k: (None if isinstance(v, float) and np.isnan(v) else v)
            for k, v in report.items()
        },
    }


def main() -> int:
    malicious_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_MALICIOUS
    benign_path = DEFAULT_BENIGN

    if not malicious_path.exists():
        print(f"malicious trace not found: {malicious_path}", file=sys.stderr)
        return 1

    malicious = analyze(malicious_path)
    benign = analyze(benign_path) if benign_path.exists() else None
    synth = traffic.synthetic_c2_like_counts(SYNTH_SLOTS, rng=np.random.default_rng(SYNTH_SEED))
    synth_report = metrics.shapeability_report(synth)

    result = {
        "malicious": malicious,
        "benign": benign,
        "synthetic_c2_like_shapeability": synth_report,
    }
    if benign:
        result["cv_ratio_malicious_over_benign"] = (
            malicious["shapeability"]["cv"] / benign["shapeability"]["cv"]
        )
        result["min_multiple_ratio_malicious_over_benign"] = (
            (malicious["shapeability"]["min_multiple"] or 99)
            / (benign["shapeability"]["min_multiple"] or 1)
        )

    out_json = malicious_path.with_suffix(".analysis.json")
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("=== Malicious flood trace shapeability ===")
    print(f"file: {malicious_path}")
    print(f"events={malicious['n_events']}  duration={malicious['duration_seconds']:.3f}s")
    print(f"send_ok_rate={malicious['send_ok_rate']:.3f}")
    print(f"per-slot mean={malicious['events_per_slot_mean']:.1f}  max={malicious['events_per_slot_max']:.0f}")
    if malicious.get("inter_send_gap_ms_median") is not None:
        print(
            f"inter-send gap ms: median={malicious['inter_send_gap_ms_median']:.1f} "
            f"min={malicious['inter_send_gap_ms_min']:.1f}"
        )
    if malicious["meta"].get("relay_stats"):
        print(f"relay_stats: {malicious['meta']['relay_stats']}")
    print("shapeability_report:")
    for k, v in malicious["shapeability"].items():
        print(f"  {k}: {v}")

    if benign:
        print("\n=== Comparison to benign real trace ===")
        print(f"benign CV={benign['shapeability']['cv']:.3f}  malicious CV={malicious['shapeability']['cv']:.3f}")
        print(
            f"benign min_multiple={benign['shapeability']['min_multiple']}  "
            f"malicious min_multiple={malicious['shapeability']['min_multiple']}"
        )
        print(
            f"benign max/slot={benign['events_per_slot_max']:.0f}  "
            f"malicious max/slot={malicious['events_per_slot_max']:.0f}"
        )

    print("\n=== Synthetic stand-in (seed=103) ===")
    for k, v in synth_report.items():
        print(f"  {k}: {v}")

    print(f"\nsaved: {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
