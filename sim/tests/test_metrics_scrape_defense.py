"""
Metrics scrape defense ranking gates (wave A4/A5 / C5 extension).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_metrics_scrape_defense.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import metrics_scrape_defense as msd
from aegis_sim import metrics_sidechannel

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "sim" / "data" / "metrics_scrape_defense.analysis.json"


def test_baseline_matches_c5_public_api():
    base = msd.characterize_defense("baseline_c5_1s", seed=11)
    c5 = metrics_sidechannel.simulate_scrape_series(
        "flood_attack",
        duration_secs=30.0,
        scrape_interval_secs=1.0,
        attack_cells_per_sec=40.0,
        seed=11,
    )
    c5_r = metrics_sidechannel.leakage_metrics(c5)["pearson_dropped_vs_attack"]
    assert base["leakage"]["pearson_dropped_vs_attack"] == pytest.approx(c5_r, abs=1e-12)
    assert c5_r > 0.9


def test_quantize_lowers_pearson_vs_baseline():
    base = msd.characterize_defense("baseline_c5_1s", seed=11)
    quant = msd.characterize_defense("quantize", quantize_bucket=16, seed=11)
    assert abs(quant["leakage"]["pearson_dropped_vs_attack"]) < abs(
        base["leakage"]["pearson_dropped_vs_attack"]
    )


def test_suppress_drops_kills_volume_channel():
    base = msd.characterize_defense("baseline_c5_1s", seed=11)
    sup = msd.characterize_defense("suppress_drops", seed=11)
    assert base["leakage"]["attack_volume_recoverable_via_drops"] > 0.5
    assert sup["leakage"]["attack_volume_recoverable_via_drops"] == pytest.approx(
        0.0, abs=1e-12
    )
    assert sup["leakage"]["drops_detail_exported"] is False


def test_stacked_recommended_and_beats_baseline_volume():
    report = msd.metrics_scrape_defense_report(seed=11)
    assert report["claims_info_theoretic_leakage_bound"] is False
    assert report["characterizes_not_closes"] is True
    assert report["status"] == "[O] QUANTIFIED"
    assert report["c5_cross_check"]["match"] is True
    assert report["recommended"]["scheme"] == "stacked"
    by = {r["scheme"]: r for r in report["defense_ranking"]}
    assert (
        by["stacked"]["attack_volume_recoverable_via_drops"]
        < by["baseline_c5_1s"]["attack_volume_recoverable_via_drops"]
    )
    # Stacked / suppress remove drop channel; fine-held |r| ≤ baseline.
    stacked_fine = by["stacked"]["fine_held_pearson_load_vs_attack"]
    base_fine = by["baseline_c5_1s"]["fine_held_pearson_load_vs_attack"]
    assert base_fine is not None and abs(base_fine) > 0.9
    assert stacked_fine is None or abs(stacked_fine) < abs(base_fine)


def test_min_cadence_honest_window_pearson_residual():
    """Long cadence can keep high window Pearson; fine-held is the blur score."""
    report = msd.metrics_scrape_defense_report(seed=11)
    by = {r["scheme"]: r for r in report["defense_ranking"]}
    assert by["min_cadence"]["scrape_interval_secs"] == pytest.approx(30.0)
    # Document residual: volume still recoverable when drops are exported.
    assert by["min_cadence"]["attack_volume_recoverable_via_drops"] > 0.5


def test_artifact_committed_fields():
    if not ARTIFACT.exists():
        pytest.skip(f"optional artifact not committed: {ARTIFACT}")
    on_disk = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert on_disk["tag"] == "wave_A5_metrics_scrape_defense"
    assert on_disk["claims_info_theoretic_leakage_bound"] is False
    assert "defense_ranking" in on_disk
    assert on_disk["recommended"]["scheme"] == "stacked"
    live = msd.metrics_scrape_defense_report(seed=11)
    assert (
        on_disk["by_scheme"]["baseline_c5_1s"]["leakage"]["pearson_dropped_vs_attack"]
        == live["by_scheme"]["baseline_c5_1s"]["leakage"]["pearson_dropped_vs_attack"]
    )
