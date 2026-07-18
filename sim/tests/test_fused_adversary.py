"""
CI-safe gates for fused adaptive∩active/intersection adversary (coverage C2).

Characterizes ([O] QUANTIFIED); does not close §13; not WAN closed.
Run:  cd sim && PYTHONPATH=. pytest -q tests/test_fused_adversary.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import fused_adversary as fa
from aegis_sim.adversaries import adaptive_guard_exposure
from aegis_sim.combined_active_intersection import combined_active_intersection

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


def test_fused_trial_exposes_or_stays_clean():
    trial = fa.fused_trial_scores(
        E=100, c=0.05, g=3, M=20, epoch_grid=(50, 100), rng=RNG(11),
    )
    assert set(trial["confirms"]) == {50, 100}
    assert isinstance(trial["ever_exposed"], bool)


def test_clean_epochs_hard_cap_blocks_mode1_confirm_short_horizon():
    """With c=0, no dirty epochs → Mode-1 confirm ~ random baseline."""
    curves = fa.fused_long_horizon(
        c=0.0, g=3, M=30, epoch_grid=(200,), trials=80,
        leaky_scheme="constant_only", rng=RNG(12),
    )
    assert curves[200]["p_adaptive_exposed"] == 0.0
    assert curves[200]["p_mode1_confirm"] < 0.15


def test_high_compromise_unlocks_mode1_leak():
    """High c: adaptive exposure ~1 and Mode-1 confirm rises well above baseline."""
    curves = fa.fused_long_horizon(
        c=0.4, g=3, M=30, epoch_grid=(200,), trials=100,
        leaky_scheme="constant_only", rng=RNG(13),
    )
    assert curves[200]["p_adaptive_exposed"] > 0.95
    assert curves[200]["p_mode1_confirm"] > 0.5
    assert curves[200]["p_union_success"] >= curves[200]["p_mode1_confirm"]


def test_union_dominates_components():
    curves = fa.fused_long_horizon(
        c=0.02, g=3, M=30, epoch_grid=(100, 400), trials=120,
        leaky_scheme="constant_only", rng=RNG(14),
    )
    for E in (100, 400):
        row = curves[E]
        assert row["p_union_success"] + 1e-9 >= max(
            row["p_adaptive_exposed"], row["p_mode1_confirm"]
        )
        assert row["p_joint_success"] <= min(
            row["p_adaptive_exposed"], row["p_mode1_confirm"]
        ) + 1e-9


def test_baselines_call_public_apis():
    """Live baselines must match public adaptive / combined entry points."""
    adapt = fa.baseline_adaptive_only(
        c=0.015, g=3, epoch_grid=(50,), trials=300, rng=RNG(15),
    )
    direct = adaptive_guard_exposure(
        0.015, 3, epochs=50, mode="adaptive", trials=300, rng=RNG(15),
    )
    assert abs(adapt[50] - direct) < 1e-12

    comb = fa.baseline_combined_only(
        scheme="hard_cap", epoch_grid=(200,), trials=40, rng=RNG(16),
    )
    direct_c = combined_active_intersection(
        "hard_cap", E=200, trials=40, rng=RNG(16),
    )
    # Curve and single-horizon share RNG stream differently; only bound-check.
    assert comb[200] < 0.15
    assert direct_c < 0.15


def test_committed_baselines_load():
    loaded = fa.load_committed_baselines(data_dir=DATA)
    assert loaded["adaptive_artifact"] is not None
    assert loaded["combined_artifact"] is not None
    assert "200" in loaded["adaptive_artifact"]["adaptive_by_epochs"]
    assert "hard_cap" in loaded["combined_artifact"]["curves"]


def test_ci_report_flags():
    report = fa.fused_adversary_report(
        epoch_grid=(100, 200), trials=60, rng=RNG(17),
        include_live_baselines=False,
        include_committed_baselines=True,
        include_offline=False,
        data_dir=DATA,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["wan_closed"] is False
    assert "baselines_live" not in report
    assert "offline_long_horizon" not in report
    assert "baselines_committed" in report
    assert report["comparison_at_long_horizon"]["E"] == 200


def test_artifact_committed_fields():
    path = DATA / "fused_adversary.analysis.json"
    assert path.is_file(), "run scripts/run_fused_adversary.py --offline"
    art = json.loads(path.read_text(encoding="utf-8"))
    assert art["tag"] == "coverage_C2_fused_adaptive_active_intersection"
    assert art["wan_closed"] is False
    assert art["characterizes_not_closes"] is True
    assert "fused_curves" in art
    cmp_ = art["comparison_at_long_horizon"]
    assert cmp_["fused_p_union_success"] >= cmp_["fused_p_adaptive_exposed"] - 1e-9
