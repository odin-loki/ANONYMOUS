"""
Phase 8 real-trace gate: load captured testnet send events and run shapeability_report.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_real_trace.py
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "sim" / "data" / "real_testnet_trace.csv"
SLOT_SECONDS = 1.0


def _load_events(path: Path) -> list[float]:
    events: list[float] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("timestamp,"):
                continue
            events.append(float(line.split(",")[0]))
    return events


def test_real_trace_file_exists_and_has_events():
    assert TRACE.exists(), f"missing captured trace at {TRACE}"
    events = _load_events(TRACE)
    assert len(events) >= 20, "trace should contain a bursty multi-send capture"


def test_real_trace_shapeability_produces_numeric_report():
    events = _load_events(TRACE)
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)

    assert report["cv"] > 0
    assert report["tier"] in ("cheap", "feasible", "unshapeable")
    assert report["min_multiple"] is None or report["min_multiple"] >= 1.1

    synth = traffic.synthetic_c2_like_counts(40000, rng=np.random.default_rng(103))
    synth_report = metrics.shapeability_report(synth)

    # Real benign burst traffic is cheaper to hard-cap than the synthetic stand-in
    # (lower min_multiple), even when per-slot CV is in the same ballpark.
    assert (report["min_multiple"] or 99) < (synth_report["min_multiple"] or 99)
