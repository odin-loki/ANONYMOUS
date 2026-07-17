"""
Phase 8 multi-process trace gate: compare against in-process benign capture.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_multiprocess_trace.py
"""
from __future__ import annotations

from pathlib import Path

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
MULTIPROCESS = ROOT / "sim" / "data" / "real_multiprocess_trace.csv"
IN_PROCESS = ROOT / "sim" / "data" / "real_testnet_trace.csv"
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


def _report(path: Path) -> dict:
    events = _load_events(path)
    t0, t1 = events[0], events[-1]
    counts = traffic.load_trace_counts(events, slot_seconds=SLOT_SECONDS, t0=t0, t1=t1)
    return metrics.shapeability_report(counts)


def test_multiprocess_trace_file_exists_and_has_events():
    assert MULTIPROCESS.exists(), f"missing captured trace at {MULTIPROCESS}"
    events = _load_events(MULTIPROCESS)
    assert len(events) >= 40, "multiprocess trace should contain full bursty capture"


def test_multiprocess_shapeability_matches_in_process_vantage():
    mp = _report(MULTIPROCESS)
    ip = _report(IN_PROCESS)

    assert mp["tier"] in ("cheap", "feasible", "unshapeable")
    assert mp["tier"] == ip["tier"], "multi-process and in-process should share tier label"

    # Same bursty schedule => CV and min_multiple should be in the same ballpark.
    assert abs(mp["cv"] - ip["cv"]) / ip["cv"] < 0.25
    mp_mm = mp["min_multiple"] or 99.0
    ip_mm = ip["min_multiple"] or 99.0
    assert abs(mp_mm - ip_mm) < 0.5
