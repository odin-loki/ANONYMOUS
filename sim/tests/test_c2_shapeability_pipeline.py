"""
C2 shapeability ingest pipeline gates (synthetic stress clearly non-operational).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_c2_shapeability_pipeline.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from aegis_sim import metrics, traffic

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "sim" / "data"


def test_load_timestamp_csv_roundtrip(tmp_path: Path):
    p = tmp_path / "events.csv"
    p.write_text("timestamp\n1.0\n1.5\n2.0\n# comment\n3.25\n", encoding="utf-8")
    events = traffic.load_timestamp_csv(p)
    assert events == pytest.approx([1.0, 1.5, 2.0, 3.25])
    counts = traffic.load_trace_counts(events, slot_seconds=1.0, t0=1.0, t1=4.0)
    assert counts.sum() == 4


def test_load_slot_count_csv(tmp_path: Path):
    p = tmp_path / "slots.csv"
    p.write_text("slot,count\n0,3\n1,5\n2,1\n", encoding="utf-8")
    counts = traffic.load_slot_count_csv(p)
    assert list(counts) == [3.0, 5.0, 1.0]


def test_synthetic_stress_suite_is_labeled_not_operational():
    suite = traffic.synthetic_c2_stress_suite(n_slots=5000, rng=np.random.default_rng(7))
    assert suite["label"] == "NOT_OPERATIONAL_C2"
    assert "NOT" in suite["disclaimer"] or "not" in suite["disclaimer"].lower()
    report = metrics.characterize_synthetic_stress_suite(
        n_slots=5000, rng=np.random.default_rng(7)
    )
    assert report["is_operational"] is False
    assert report["label"] == "NOT_OPERATIONAL_C2"
    assert "gaussian_cheap" in report["reports"]
    assert report["reports"]["gaussian_cheap"]["tier"] in ("cheap", "feasible", "unshapeable")
    # Stress series should be messier than gaussian on CV.
    assert report["reports"]["pareto_stress"]["cv"] > report["reports"]["gaussian_cheap"]["cv"]


def test_characterize_trace_file_timestamp_ingest(tmp_path: Path):
    p = tmp_path / "wan_like.csv"
    # Synthetic timestamps only — not operational.
    ts = np.cumsum(np.random.default_rng(1).exponential(0.2, 200))
    p.write_text("\n".join(f"{t:.6f}" for t in ts) + "\n", encoding="utf-8")
    report = metrics.characterize_trace_file(
        p, slot_seconds=1.0, source_label="unit_test", is_operational=False
    )
    assert report["ingest"] == "timestamp_csv"
    assert report["is_operational"] is False
    assert report["tier"] in ("cheap", "feasible", "unshapeable")
    assert report["n_slots"] >= 1


def test_characterize_trace_file_slot_count_ingest(tmp_path: Path):
    p = tmp_path / "binned.csv"
    p.write_text("\n".join(str(x) for x in [2, 4, 4, 8, 1, 0, 3] * 40) + "\n", encoding="utf-8")
    report = metrics.characterize_trace_file(p, is_operational=False)
    assert report["ingest"] == "slot_count_csv"
    assert report["is_operational"] is False


def test_drop_in_docs_path_exists_for_operators():
    """Pipeline script must exist so operators can drop WAN traces without new code."""
    script = ROOT / "sim" / "scripts" / "run_c2_shapeability_pipeline.py"
    assert script.exists()
    text = script.read_text(encoding="utf-8")
    assert "NOT_OPERATIONAL" in text or "synthetic-stress" in text
    assert "--operational" in text
