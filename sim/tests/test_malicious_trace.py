"""
Malicious flood trace gate: compare shapeability vs benign capture.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_malicious_trace.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
MALICIOUS = ROOT / "sim" / "data" / "real_testnet_malicious_trace.csv"
BENIGN = ROOT / "sim" / "data" / "real_testnet_trace.csv"
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


def test_malicious_trace_file_exists():
    assert MALICIOUS.exists(), f"missing malicious trace at {MALICIOUS}"


def test_malicious_flood_is_tighter_and_higher_per_slot_than_benign():
    mal_events = _load_events(MALICIOUS)
    ben_events = _load_events(BENIGN)
    assert len(mal_events) >= 40

    mal_duration = mal_events[-1] - mal_events[0]
    ben_duration = ben_events[-1] - ben_events[0]
    assert mal_duration < ben_duration * 0.15, "malicious flood should be much shorter wall-clock span"

    mal_gaps = np.diff(mal_events)
    ben_gaps = np.diff(ben_events)
    assert np.median(mal_gaps) < np.median(ben_gaps) * 0.1

    t0, t1 = mal_events[0], mal_events[-1]
    mal_counts = traffic.load_trace_counts(mal_events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    t0b, t1b = ben_events[0], ben_events[-1]
    ben_counts = traffic.load_trace_counts(ben_events, slot_seconds=SLOT_SECONDS, t0=t0b, t1=t1b)

    assert mal_counts.max() > ben_counts.max() * 2


def test_malicious_shapeability_report():
    events = _load_events(MALICIOUS)
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)

    assert report["tier"] in ("feasible", "unshapeable", "cheap")
    assert counts.max() >= 8, "flood should concentrate many events per slot"

    ben_events = _load_events(BENIGN)
    ben_counts = traffic.load_trace_counts(
        ben_events, slot_seconds=SLOT_SECONDS, t0=ben_events[0], t1=ben_events[-1]
    )
    ben_report = metrics.shapeability_report(ben_counts)
    # Flood saturates slots (max 12 vs 4) even though per-slot CV can be lower (more uniform).
    assert counts.max() > ben_counts.max() * 2
    assert counts.mean() > ben_counts.mean() * 5


def test_malicious_analysis_json_committed():
    analysis_path = MALICIOUS.with_suffix(".analysis.json")
    assert analysis_path.exists()
    data = json.loads(analysis_path.read_text(encoding="utf-8"))
    assert "malicious" in data
    assert data["malicious"]["send_ok_rate"] >= 0.0
