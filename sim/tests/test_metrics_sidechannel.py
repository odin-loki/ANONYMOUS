"""
Coarse RelayCoarseStats / IngressRateLimitStats scrape side-channel (partial).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_metrics_sidechannel.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import metrics_sidechannel

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "sim" / "data" / "metrics_sidechannel_characterization.json"


def test_flood_increases_ingress_drops_vs_baseline():
    base = metrics_sidechannel.simulate_scrape_series("baseline_paced", seed=11)
    flood = metrics_sidechannel.simulate_scrape_series(
        "flood_attack", attack_cells_per_sec=40.0, seed=11
    )
    assert flood["final_ingress"]["dropped_frames"] > base["final_ingress"]["dropped_frames"]
    assert flood["totals"]["offered_attack_cells"] > 0.0
    assert base["totals"]["offered_attack_cells"] == pytest.approx(0.0, abs=1e-9)


def test_flood_leakage_pearson_and_recoverable_volume():
    flood = metrics_sidechannel.simulate_scrape_series(
        "flood_attack",
        duration_secs=30.0,
        scrape_interval_secs=1.0,
        attack_cells_per_sec=40.0,
        seed=11,
    )
    leak = metrics_sidechannel.leakage_metrics(flood)
    assert leak["attack_volume_recoverable_via_drops"] > 0.5
    # Coarse timing: scrape deltas should correlate with attack windows.
    r = leak["pearson_dropped_vs_attack"]
    assert r == r  # not NaN
    assert r > 0.3


def test_cover_round_leaks_cover_emitted_counter():
    base = metrics_sidechannel.simulate_scrape_series("baseline_paced", seed=3)
    cover = metrics_sidechannel.simulate_scrape_series(
        "cover_bulk_round", cover_flows_per_sec=2.0, seed=3
    )
    assert (
        cover["final_coarse"]["cover_emitted"] > base["final_coarse"]["cover_emitted"]
    )
    leak = metrics_sidechannel.leakage_metrics(cover)
    r = leak["pearson_cover_vs_cover_gt"]
    assert r == r
    assert r > 0.9


def test_compare_scrape_scenarios_structure():
    data = metrics_sidechannel.compare_scrape_scenarios(
        duration_secs=30.0,
        scrape_interval_secs=1.0,
        attack_cells_per_sec=40.0,
        seed=11,
    )
    assert data["claims_info_theoretic_leakage_bound"] is False
    assert data["debug_stats_exported"] is False
    assert data["delta"]["flood_drop_total_minus_baseline"] > 0
    assert data["delta"]["ks_dropped_flood_vs_baseline"] > 0.0
    assert data["delta"]["flood_attack_volume_recoverable_via_drops"] > 0.5
    assert data["delta"]["cover_round_cover_emitted_minus_baseline"] > 0


def test_scrape_interval_sweep_volume_persists():
    sweep = metrics_sidechannel.scrape_interval_sweep(
        intervals=(0.5, 1.0, 2.0, 5.0),
        duration_secs=30.0,
        attack_cells_per_sec=40.0,
        seed=11,
    )
    assert len(sweep["rows"]) == 4
    for row in sweep["rows"]:
        # Volume leakage via cumulative drops remains usable even at coarser scrapes.
        assert row["attack_volume_recoverable_via_drops"] > 0.5


def test_characterization_artifact_matches_bundle():
    data = metrics_sidechannel.full_sidechannel_characterization_bundle(
        duration_secs=30.0,
        scrape_interval_secs=1.0,
        attack_cells_per_sec=40.0,
        seed=11,
    )
    if not ARTIFACT.exists():
        pytest.skip(f"optional artifact not committed: {ARTIFACT}")
    on_disk = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert on_disk["claims_info_theoretic_leakage_bound"] is False
    assert on_disk["debug_stats_exported"] is False
    assert (
        on_disk["delta"]["flood_drop_total_minus_baseline"]
        == data["delta"]["flood_drop_total_minus_baseline"]
    )
    assert on_disk["delta"]["flood_attack_volume_recoverable_via_drops"] > 0.5
    assert "scrape_interval_sweep" in on_disk
    assert len(on_disk["scrape_interval_sweep"]["rows"]) >= 2
