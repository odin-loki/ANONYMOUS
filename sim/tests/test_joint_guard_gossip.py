"""
CI-safe gates for joint adaptive-guard × gossip-eclipse adversary (B3).

Characterizes ([O] QUANTIFIED); does not close §13; field rates unmeasured.
Run:  cd sim && PYTHONPATH=. pytest -q tests/test_joint_guard_gossip.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import joint_guard_gossip as jgg
from aegis_sim.adversaries import adaptive_guard_exposure
from aegis_sim import gossip_eclipse as ge

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


def test_joint_trial_checkpoints():
    trial = jgg.joint_trial(
        E=40, c=0.05, g=3, n_neighbors=8, f=0.125, majority_k=2,
        epoch_grid=(20, 40), rng=RNG(11),
    )
    assert set(trial["exposed_at"]) == {20, 40}
    assert set(trial["gossip_fp_at"]) == {20, 40}
    assert isinstance(trial["ever_exposed"], bool)


def test_zero_compromise_no_boost_blocks_solo_eclipse():
    """c=0, f=0.125, K=2: cannot form pure-adv quorum; eclipse stays near 0."""
    curves = jgg.joint_long_horizon(
        c=0.0, g=3, f=0.125, majority_k=2, n_neighbors=8,
        coupling="boosted", epoch_grid=(40,), trials=60, rng=RNG(12),
    )
    assert curves[40]["p_adaptive_exposed"] == 0.0
    assert curves[40]["p_eclipse_any"] < 0.1
    assert curves[40]["p_gossip_success"] < 0.1


def test_boosted_unlocks_eclipse_vs_independent():
    """High c + f=0.125: boosted eclipse >> independent (boost seats +guards)."""
    boosted = jgg.joint_long_horizon(
        c=0.4, g=3, f=0.125, majority_k=2, n_neighbors=8,
        coupling="boosted", epoch_grid=(40,), trials=80, rng=RNG(13),
    )
    indep = jgg.joint_long_horizon(
        c=0.4, g=3, f=0.125, majority_k=2, n_neighbors=8,
        coupling="independent", epoch_grid=(40,), trials=80, rng=RNG(13),
    )
    assert boosted[40]["p_adaptive_exposed"] > 0.95
    assert boosted[40]["p_eclipse_any"] > 0.7
    assert boosted[40]["p_eclipse_any"] > indep[40]["p_eclipse_any"] + 0.3
    assert boosted[40]["p_union_success"] + 1e-9 >= max(
        boosted[40]["p_adaptive_exposed"], boosted[40]["p_gossip_success"]
    )


def test_union_dominates_components():
    curves = jgg.joint_long_horizon(
        c=0.02, g=3, f=0.125, majority_k=2, n_neighbors=8,
        coupling="boosted", epoch_grid=(50, 100), trials=80, rng=RNG(14),
    )
    for E in (50, 100):
        row = curves[E]
        assert row["p_union_success"] + 1e-9 >= max(
            row["p_adaptive_exposed"], row["p_gossip_success"]
        )
        assert row["p_joint_success"] <= min(
            row["p_adaptive_exposed"], row["p_gossip_success"]
        ) + 1e-9


def test_full_eclipse_fp_saturates():
    """f=1: gossip FP and eclipse saturate; joint with adaptive exposure."""
    curves = jgg.joint_long_horizon(
        c=0.4, g=3, f=1.0, majority_k=2, n_neighbors=8,
        coupling="boosted", epoch_grid=(40,), trials=60, rng=RNG(19),
    )
    row = curves[40]
    assert row["p_gossip_fp"] > 0.9
    assert row["p_eclipse_any"] > 0.9
    assert row["p_gossip_success"] > 0.9


def test_baselines_call_public_apis():
    adapt = jgg.baseline_adaptive_only(
        c=0.015, g=3, epoch_grid=(50,), trials=300, rng=RNG(15),
    )
    direct = adaptive_guard_exposure(
        0.015, 3, epochs=50, mode="adaptive", trials=300, rng=RNG(15),
    )
    assert abs(adapt[50] - direct) < 1e-12

    goss = jgg.baseline_gossip_only(
        n_neighbors=8, f=0.5, majority_k=2, epoch_grid=(6,), trials=40, rng=RNG(16),
    )
    cell = ge.profile_cell(8, 0.5, 2, trials=40, epochs=6, rng=RNG(16))
    assert 0.0 <= goss[6]["false_probation_rate"] <= 1.0
    assert 0.0 <= cell["false_probation_rate"] <= 1.0


def test_committed_baselines_load():
    loaded = jgg.load_committed_baselines(data_dir=DATA)
    assert loaded["adaptive_artifact"] is not None
    assert loaded["gossip_artifact"] is not None
    assert loaded["gossip_artifact"]["claim_closed"] is False


def test_joint_defense_reduces_or_matches_union():
    """stacked + adaptive_v4 should not clearly worsen union (MC noise band)."""
    d = jgg.joint_defense_curve(
        epoch_grid=(40,), trials=50, c=0.015, f=0.125, majority_k=2, rng=RNG(17),
    )
    u = d["undefended_boosted"]["40"]["p_union_success"]
    v = d["joint_v4_stacked"]["40"]["p_union_success"]
    assert v <= u + 0.15


def test_ci_report_flags():
    report = jgg.joint_guard_gossip_report(
        epoch_grid=(40, 80), trials=40, rng=RNG(18),
        include_live_baselines=False,
        include_committed_baselines=True,
        include_joint_defense=False,
        include_offline=False,
        data_dir=DATA,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["section_13_closed"] is False
    assert report["claim_closed"] is False
    assert report["wan_closed"] is False
    assert "field_residual" in report
    assert "baselines_live" not in report
    assert "joint_defense" not in report
    assert "baselines_committed" in report
    assert report["comparison_at_long_horizon"]["E"] == 80
    assert report["f"] == 0.125


def test_artifact_committed_fields():
    path = DATA / "joint_guard_gossip.analysis.json"
    assert path.is_file(), "run scripts/run_joint_guard_gossip.py"
    art = json.loads(path.read_text(encoding="utf-8"))
    assert art["tag"] == "leftovers_B3_joint_guard_gossip"
    assert art["section_13_closed"] is False
    assert art["characterizes_not_closes"] is True
    assert "joint_curves" in art
    assert "field_residual" in art
    assert abs(float(art["f"]) - 0.125) < 1e-9
    cmp_ = art["comparison_at_long_horizon"]
    assert cmp_["joint_p_union_success"] >= cmp_["joint_p_adaptive_exposed"] - 1e-9
    # Boosted should beat independent gossip unlock at long E.
    assert cmp_["joint_p_gossip_success"] >= cmp_.get(
        "independent_p_gossip_success", 0.0
    ) - 1e-9
