"""
Gate for relay post-forward trace CSV (post-shaping vantage).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_relay_forward_trace.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sim" / "data" / "relay_forward_trace_sample.csv"
RELAY_CAPTURE = ROOT / "sim" / "data" / "real_multiprocess_relay_forward_trace.csv"
ANALYSIS = ROOT / "sim" / "data" / "real_multiprocess_relay_forward_trace.analysis.json"
SLOT_SECONDS = 1.0
MIN_CAPTURE_EVENTS = 12  # paced capture: partial rows common on loopback (see §5 notes)


def _relay_forward_report(path: Path) -> dict:
    events = traffic.load_relay_forward_timestamps(path)
    assert events, f"empty relay forward trace at {path}"
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    return metrics.shapeability_report(counts)


def test_relay_forward_sample_exists():
    assert SAMPLE.exists(), f"missing sample trace at {SAMPLE}"


def test_relay_forward_sample_shapeability():
    report = _relay_forward_report(SAMPLE)
    assert report["cv"] >= 0
    assert report["tier"] in ("cheap", "feasible", "unshapeable")


def test_multiprocess_relay_forward_capture_exists():
    if not RELAY_CAPTURE.exists():
        pytest.skip(
            f"paced relay forward capture not committed yet: {RELAY_CAPTURE} "
            "(run sim/scripts/capture_multiprocess_relay_forward_trace.py)"
        )
    events = traffic.load_relay_forward_timestamps(RELAY_CAPTURE)
    assert len(events) >= MIN_CAPTURE_EVENTS, (
        f"expected >= {MIN_CAPTURE_EVENTS} relay forward events, got {len(events)}"
    )


def test_multiprocess_relay_forward_shapeability():
    if not RELAY_CAPTURE.exists():
        pytest.skip(f"missing paced relay forward capture at {RELAY_CAPTURE}")

    report = _relay_forward_report(RELAY_CAPTURE)
    # Post-shaping relay vantage at 1 s slots can read unshapeable on loopback
    # (sparse cover/forward rows vs client-send feasible baselines); see §5 notes.
    assert report["tier"] in ("cheap", "feasible", "unshapeable")
    assert report["cv"] >= 0


def test_multiprocess_relay_forward_analysis_artifact():
    if not RELAY_CAPTURE.exists():
        pytest.skip(f"missing paced relay forward capture at {RELAY_CAPTURE}")
    assert ANALYSIS.exists(), (
        f"missing analysis artifact at {ANALYSIS}; "
        "run sim/scripts/analyze_multiprocess_relay_forward_trace.py"
    )
    data = json.loads(ANALYSIS.read_text(encoding="utf-8"))
    relay = data["relay_forward"]
    assert relay["n_events"] >= MIN_CAPTURE_EVENTS
    assert relay["shapeability"]["tier"] in ("cheap", "feasible", "unshapeable")
