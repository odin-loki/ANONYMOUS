"""
Gate for relay post-forward trace CSV (post-shaping vantage).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_relay_forward_trace.py
"""
from __future__ import annotations

from pathlib import Path

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sim" / "data" / "relay_forward_trace_sample.csv"
SLOT_SECONDS = 1.0


def test_relay_forward_sample_exists():
    assert SAMPLE.exists(), f"missing sample trace at {SAMPLE}"


def test_relay_forward_sample_shapeability():
    events = traffic.load_relay_forward_timestamps(SAMPLE)
    assert len(events) >= 1
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    report = metrics.shapeability_report(counts)
    assert report["cv"] >= 0
    assert report["tier"] in ("cheap", "feasible", "unshapeable")
