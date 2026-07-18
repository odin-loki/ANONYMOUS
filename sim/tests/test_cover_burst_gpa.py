"""
Partial cover-burst / GPA timing characterization (not indistinguishability proof).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_cover_burst_gpa.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import cover_timing

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "sim" / "data" / "cover_burst_gpa_characterization.json"
TAU = 0.35
N_SENDS = 4
COVER_SECS = 2.0


def test_simulate_modes_non_empty_and_bounded():
    bulk = cover_timing.simulate_cell_timestamps("paced_bulk_only", tau_secs=TAU, n_sends=N_SENDS)
    cover = cover_timing.simulate_cell_timestamps(
        "paced_plus_tau_cover",
        tau_secs=TAU,
        n_sends=N_SENDS,
        cover_secs=COVER_SECS,
        relay_cover_bursts_per_send=1,
    )
    assert len(bulk) == N_SENDS * cover_timing.SPHINX_FRAGMENT_COUNT
    assert len(cover) > len(bulk)
    for stamps in (bulk, cover):
        gaps = cover_timing._inter_cell_gaps(stamps)
        assert gaps.size >= 1
        assert float(gaps.min()) >= 0.0
        assert float(gaps.max()) < 10.0


def test_paced_plus_tau_cover_increases_observable_cells():
    bulk = cover_timing.characterize_gpa_timing("paced_bulk_only", tau_secs=TAU, n_sends=N_SENDS)
    cover = cover_timing.characterize_gpa_timing(
        "paced_plus_tau_cover",
        tau_secs=TAU,
        n_sends=N_SENDS,
        cover_secs=COVER_SECS,
        relay_cover_bursts_per_send=1,
    )
    assert cover.n_cells > bulk.n_cells
    assert cover.disclaimer.startswith("Partial characterization")


def test_inter_cell_gaps_stay_near_tau_during_active_emission():
    report = cover_timing.characterize_gpa_timing(
        "paced_plus_tau_cover",
        tau_secs=TAU,
        n_sends=2,
        cover_secs=COVER_SECS,
        relay_cover_bursts_per_send=0,
        inter_send_idle_secs=0.0,
    )
    assert report.fraction_near_tau >= 0.85
    assert abs(report.gap_mean_secs - TAU) <= TAU * 0.15


def test_compare_cover_modes_structure():
    data = cover_timing.compare_cover_modes(
        tau_secs=TAU,
        n_sends=N_SENDS,
        cover_secs=COVER_SECS,
        relay_cover_bursts_per_send=1,
    )
    assert "disclaimer" in data
    assert data["paced_bulk_only"]["mode"] == "paced_bulk_only"
    assert data["paced_plus_tau_cover"]["mode"] == "paced_plus_tau_cover"
    assert data["delta"]["extra_cells"] > 0


def test_characterization_artifact_optional():
    """Artifact is optional; when present it must match the in-memory comparison."""
    data = cover_timing.compare_cover_modes(
        tau_secs=TAU,
        n_sends=N_SENDS,
        cover_secs=COVER_SECS,
    )
    if not ARTIFACT.exists():
        pytest.skip(f"optional artifact not committed: {ARTIFACT}")
    on_disk = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert on_disk["paced_bulk_only"]["n_cells"] == data["paced_bulk_only"]["n_cells"]
    assert on_disk["paced_plus_tau_cover"]["n_cells"] == data["paced_plus_tau_cover"]["n_cells"]
