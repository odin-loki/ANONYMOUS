"""
CI-safe gates for exit-tier defenses (wave S4 / C2 extension).

Characterizes ([O] QUANTIFIED); not WAN closed.
Run:  cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_defense.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from aegis_sim import exit_tier_defense as etd
from aegis_sim import exit_tier_intersection as eti

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


def test_apply_defense_preserves_target_and_rebuilds_sets():
    raw = eti.simulate_exit_window_epochs(
        n_clients=20, E=60, p_active=0.3, rng=RNG(1),
    )
    sim = etd.apply_exit_defense(raw, "presence_pad", rng=RNG(2))
    assert sim["target"] == raw["target"]
    assert len(sim["anonymity_sets"]) == len(raw["anonymity_sets"])
    # Presence pad should enlarge mean anonymity set.
    assert eti.anonymity_set_sizes(sim).mean() >= eti.anonymity_set_sizes(raw).mean()


def test_pool_hard_cap_kills_volume_ranking_and_singleton():
    """Always-on flat Q → anonymity set = N; volume rank ~ uniform."""
    m = etd.evaluate_exit_defense(
        "pool_hard_cap", n_clients=30, E=200, trials=60, rng=RNG(3),
    )
    assert m["p_intersection_singleton"] == 0.0
    assert m["mean_anonymity_set"] == pytest.approx(30.0, abs=1e-9)
    assert m["p_volume_rank_top"] < 0.15


def test_presence_pad_beats_baseline_composite():
    base = etd.evaluate_exit_defense(
        "baseline", n_clients=40, E=100, trials=100, rng=RNG(4),
    )
    pad = etd.evaluate_exit_defense(
        "presence_pad", n_clients=40, E=100, trials=100, rng=RNG(5),
        presence_rate=0.7,
    )
    assert pad["mean_anonymity_set"] > base["mean_anonymity_set"]
    assert pad["p_intersection_singleton"] < base["p_intersection_singleton"] - 0.3
    assert pad["composite_risk"] < base["composite_risk"] - 0.1


def test_exit_window_hard_cap_cuts_active_volume_asymmetry():
    """Flat Q among actives removes signal burst; presence freq can still leak."""
    base = etd.evaluate_exit_defense(
        "baseline", n_clients=40, E=50, trials=80, rng=RNG(6),
    )
    hc = etd.evaluate_exit_defense(
        "exit_window_hard_cap", n_clients=40, E=50, trials=80, rng=RNG(7),
        pad_q=10.0,
    )
    # Mid-horizon: hard-cap among actives should not worsen composite vs baseline.
    assert hc["composite_risk"] <= base["composite_risk"] + 0.05


def test_report_ranking_and_honest_flags():
    report = etd.exit_tier_defense_report(
        n_clients=25, epoch_grid=(50, 100), decision_horizon=100,
        trials=40, rng=RNG(8),
        include_curves=True, include_offline=False,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["wan_closed"] is False
    assert report["characterizes_not_closes"] is True
    assert report["decision_horizon"] == 100
    assert "defense_ranking" in report
    assert "metrics_at_decision_horizon" in report
    assert report["recommended"]["scheme"] not in ("", "baseline")
    schemes = {r["scheme"] for r in report["defense_ranking"]}
    assert "baseline" in schemes and "pool_hard_cap" in schemes
    assert report["defense_ranking"][0]["composite_risk"] <= report[
        "defense_ranking"
    ][-1]["composite_risk"]

def test_uses_public_intersection_api():
    """Defended sim remains consumable by C2 public curve API."""
    raw = eti.simulate_exit_window_epochs(
        n_clients=20, E=80, rng=RNG(9),
    )
    sim = etd.apply_exit_defense(raw, "matched_decoy", matched_decoys=3, rng=RNG(10))
    curve = eti.intersection_candidate_curve(
        sim, epoch_grid=(40, 80), tip_rate=0.2, rng=RNG(11),
    )
    assert 40 in curve and 80 in curve


def test_artifact_committed_fields():
    path = DATA / "exit_tier_defense.analysis.json"
    assert path.is_file(), "run scripts/run_exit_tier_defense.py"
    art = json.loads(path.read_text(encoding="utf-8"))
    assert art["tag"] == "wave_S4_exit_tier_defense"
    assert art["wan_closed"] is False
    assert "defense_ranking" in art
    assert "recommended" in art
    assert "metrics_at_decision_horizon" in art
    assert art["recommended"]["scheme"] != "baseline"
    assert art["metrics_at_decision_horizon"]["baseline"]["p_volume_rank_top"] > art[
        "baseline_uniform"
    ]
