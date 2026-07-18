"""
CI-safe gates for exit-tier anonymity-set / intersection (coverage C2).

Characterizes ([O] QUANTIFIED); not WAN closed.
Run:  cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_intersection.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import exit_tier_intersection as eti

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


def test_simulate_window_has_target_in_some_sets():
    sim = eti.simulate_exit_window_epochs(
        n_clients=20, E=80, p_active=0.3, window=1, rng=RNG(1),
    )
    assert sim["target"] < 20
    assert any(sim["target"] in s for s in sim["anonymity_sets"])
    assert sim["volume"].shape == (80, 20)


def test_intersection_shrinks_or_stable_with_horizon():
    sim = eti.simulate_exit_window_epochs(
        n_clients=30, E=400, p_active=0.35, signal_rate=8.0, rng=RNG(2),
    )
    # High tip_rate so tips accumulate; ∩ is monotone non-increasing.
    curve = eti.intersection_candidate_curve(
        sim, epoch_grid=(50, 200, 400), tip_rate=0.5, rng=RNG(22),
    )
    sizes = []
    for e in (50, 200, 400):
        row = curve[e]
        sizes.append(
            row["intersection_size"] if row["tips_used"] > 0 else 30
        )
    assert sizes[0] >= sizes[1] >= sizes[2]
    assert curve["_naive_full_intersection_size"] <= sizes[0]


def test_volume_rank_beats_uniform_without_hardcap():
    """Unshaped clearnet residual: volume ranking >> 1/N at moderate E."""
    m = eti.exit_tier_intersection(
        n_clients=40, E=400, p_active=0.25, trials=120, rng=RNG(3),
    )
    assert m["p_volume_rank_top"] > m["baseline_uniform"] + 0.15
    assert m["mean_anonymity_set"] > 1.0


def test_higher_coactivity_enlarges_mean_anonymity_set():
    lo = eti.exit_tier_intersection(
        n_clients=40, E=200, p_active=0.1, trials=80, rng=RNG(4),
    )
    hi = eti.exit_tier_intersection(
        n_clients=40, E=200, p_active=0.6, trials=80, rng=RNG(5),
    )
    assert hi["mean_anonymity_set"] > lo["mean_anonymity_set"] + 2.0


def test_ci_report_skips_heavy_sections():
    report = eti.exit_tier_report(
        n_clients=20, epoch_grid=(50, 100), trials=40, rng=RNG(6),
        include_sensitivity=False, include_offline=False,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["wan_closed"] is False
    assert "sensitivity" not in report
    assert "offline_long_horizon" not in report
    assert "50" in report["curves"] and "100" in report["curves"]


def test_curve_keys_and_bounds():
    curve = eti.exit_tier_intersection_curve(
        n_clients=25, epoch_grid=(50, 100), trials=50, rng=RNG(7),
    )
    for E, row in curve.items():
        assert 0.0 <= row["p_intersection_singleton"] <= 1.0
        assert 0.0 <= row["p_volume_rank_top"] <= 1.0
        assert row["mean_anonymity_set"] >= 0.0


def test_artifact_committed_fields():
    path = DATA / "exit_tier_intersection.analysis.json"
    assert path.is_file(), "run scripts/run_exit_tier_intersection.py --offline"
    art = json.loads(path.read_text(encoding="utf-8"))
    assert art["tag"] == "coverage_C2_exit_tier_intersection"
    assert art["wan_closed"] is False
    assert art["characterizes_not_closes"] is True
    assert "curves" in art
    assert art["summary_at_long_horizon"]["p_volume_rank_top"] > art["baseline_uniform"]
