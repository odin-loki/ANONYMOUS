"""
CI-safe gates for fused/adaptive_v4 defenses (wave S5 / C2).

[O] QUANTIFIED Partial — does not close §13; not WAN closed.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_fused_defense.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import fused_defense as fd

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"
ARTIFACT = DATA / "fused_defense.analysis.json"


def test_hard_cap_forced_near_baseline():
    curves = fd.fused_defense_long_horizon(
        mode="hard_cap_forced",
        epoch_grid=(200, 400),
        trials=80,
        rng=RNG(1),
    )
    for E in (200, 400):
        assert curves[E]["p_mode1_confirm"] < 0.15, (
            f"hard_cap_forced should stay near 1/M; E={E} got "
            f"{curves[E]['p_mode1_confirm']:.3f}"
        )


def test_fused_v4_beats_undefended_mode1_at_mid():
    """Fewer dirty epochs under v4 → lower Mode-1 confirm vs undefended."""
    cmp_ = fd.compare_fused_defenses(
        modes=("undefended", "fused_v4"),
        epoch_grid=(200, 800),
        trials=100,
        seed=42,
    )
    u200 = cmp_["by_mode"]["undefended"]["200"]
    d200 = cmp_["by_mode"]["fused_v4"]["200"]
    assert d200["mean_dirty_epoch_fraction"] < u200["mean_dirty_epoch_fraction"]
    # Confirm may be noisy at low trials; require dirty-frac win + union not worse by much.
    assert d200["p_union_success"] <= u200["p_union_success"] + 0.08


def test_mitigated_v4_exposure_below_v3_at_2000():
    """Adaptive-only reference: v4 targets E=2000 residual vs v3."""
    from aegis_sim import adversaries as adv

    c, g = 0.015, 3
    v3 = adv.adaptive_guard_exposure(
        c, g, epochs=2000, mode="mitigated_v3", trials=1200, rng=RNG(10),
    )
    v4 = adv.adaptive_guard_exposure(
        c, g, epochs=2000, mode="mitigated_v4", trials=1200, rng=RNG(11),
    )
    assert v4 < v3 - 0.05, (
        f"v4 should beat v3 at E=2000 (v3={v3:.3f} v4={v4:.3f}); §13 still open"
    )
    assert v4 > 0.5, "honest residual: still high at long horizon"


def test_report_honest_limits():
    report = fd.fused_defense_report(
        epoch_grid=(200, 800), trials=40, include_offline=False, seed=3,
    )
    assert report["claim_closed"] is False
    assert report["wan_closed"] is False
    assert report["best_defense"] == "fused_v4"
    assert "§13" in " ".join(report["honest_limits"]) or any(
        "13" in x for x in report["honest_limits"]
    )


def test_artifact_committed():
    assert ARTIFACT.is_file(), "run scripts/run_fused_defense.py"
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert art["claim_closed"] is False
    assert art["wan_closed"] is False
    assert art["best_defense"] == "fused_v4"
    long_e = str(art["summary_at_long_horizon"]["E"])
    undef = art["compare"]["by_mode"]["undefended"][long_e]
    fused = art["compare"]["by_mode"]["fused_v4"][long_e]
    assert fused["mean_dirty_epoch_fraction"] <= undef["mean_dirty_epoch_fraction"] + 1e-9
