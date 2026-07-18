#!/usr/bin/env python3
"""Shapeability analysis for paced multi-process relay post-forward trace."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
RELAY_FORWARD = ROOT / "sim" / "data" / "real_multiprocess_relay_forward_trace.csv"
IN_PROCESS = ROOT / "sim" / "data" / "real_testnet_trace.csv"
MULTIPROCESS = ROOT / "sim" / "data" / "real_multiprocess_trace.csv"
SLOT_SECONDS = 1.0


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_meta(path: Path) -> dict:
    meta: dict = {"path": _rel(path)}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("#"):
                continue
            if line.startswith("# capture="):
                meta["capture"] = line.split("=", 1)[1]
            if line.startswith("# vantage="):
                meta["vantage"] = line.split("=", 1)[1]
    return meta


def analyze_relay_forward(path: Path) -> dict:
    rows = traffic.load_relay_forward_trace(path)
    if not rows:
        raise ValueError(f"empty relay forward trace: {path}")

    timestamps = [ts for ts, _, _ in rows]
    event_types: dict[str, int] = {}
    cell_total = 0
    for _, cell_count, event_type in rows:
        event_types[event_type] = event_types.get(event_type, 0) + 1
        cell_total += cell_count

    t0, t1 = timestamps[0], timestamps[-1]
    counts = traffic.load_trace_counts(timestamps, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)

    return {
        "trace_file": _rel(path),
        "meta": _parse_meta(path),
        "n_events": len(timestamps),
        "duration_seconds": t1 - t0,
        "slot_seconds": SLOT_SECONDS,
        "n_slots": int(len(counts)),
        "events_per_slot_mean": float(counts.mean()),
        "events_per_slot_max": float(counts.max()),
        "event_type_counts": event_types,
        "total_cells_on_wire": cell_total,
        "shapeability": {
            k: (None if isinstance(v, float) and np.isnan(v) else v)
            for k, v in report.items()
        },
    }


def analyze_client_send(path: Path) -> dict | None:
    if not path.is_file():
        return None
    events: list[float] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("timestamp,"):
                continue
            events.append(float(line.split(",")[0]))
    if not events:
        return None
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)
    return {
        "trace_file": _rel(path),
        "meta": _parse_meta(path),
        "n_events": len(events),
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
    relay_path = Path(sys.argv[1]) if len(sys.argv) > 1 else RELAY_FORWARD
    if not relay_path.is_file():
        print(f"relay forward trace not found: {relay_path}", file=sys.stderr)
        return 1

    relay = analyze_relay_forward(relay_path)
    ip = analyze_client_send(IN_PROCESS)
    mp = analyze_client_send(MULTIPROCESS)

    comparison: dict = {}
    if ip is not None:
        comparison["vs_in_process_client_send"] = {
            "cv_ratio_relay_over_client": float(relay["shapeability"]["cv"] / ip["shapeability"]["cv"]),
            "same_tier": relay["shapeability"]["tier"] == ip["shapeability"]["tier"],
            "min_multiple_delta": (
                None
                if relay["shapeability"].get("min_multiple") is None
                or ip["shapeability"].get("min_multiple") is None
                else float(relay["shapeability"]["min_multiple"] - ip["shapeability"]["min_multiple"])
            ),
        }
    if mp is not None:
        comparison["vs_multiprocess_client_send"] = {
            "cv_ratio_relay_over_client": float(relay["shapeability"]["cv"] / mp["shapeability"]["cv"]),
            "same_tier": relay["shapeability"]["tier"] == mp["shapeability"]["tier"],
            "min_multiple_delta": (
                None
                if relay["shapeability"].get("min_multiple") is None
                or mp["shapeability"].get("min_multiple") is None
                else float(relay["shapeability"]["min_multiple"] - mp["shapeability"]["min_multiple"])
            ),
        }

    result = {
        "relay_forward": relay,
        "client_send_baselines": {
            "in_process": ip,
            "multiprocess": mp,
        },
        "comparison": comparison,
        "loopback_limits": {
            "note": (
                "127.0.0.1 loopback testnet; paced CLI (tau/cover) not raw send; "
                "trace on ingress+exit only (not every hop); short horizon (~12 sends)."
            ),
            "hurst_unreliable_below_128_slots": relay["n_slots"] < 128,
        },
    }

    out_json = relay_path.with_name("real_multiprocess_relay_forward_trace.analysis.json")
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("=== Paced multi-process relay forward shapeability ===")
    print(
        f"relay: events={relay['n_events']} duration={relay['duration_seconds']:.2f}s "
        f"types={relay['event_type_counts']}"
    )
    for k, v in relay["shapeability"].items():
        print(f"  relay {k}: {v}")
    if ip:
        print(f"in-process client-send CV={ip['shapeability']['cv']:.3f} tier={ip['shapeability']['tier']}")
    if mp:
        print(f"multiprocess client-send CV={mp['shapeability']['cv']:.3f} tier={mp['shapeability']['tier']}")
    print(f"saved: {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
