"""
CI-safe gates for combined active(n-1)+intersection Mode-1 defense ranking.

Characterizes ([O] QUANTIFIED); does not claim the open item closed.
Keep trials/epoch grids small so pytest never hangs.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_combined_active_intersection.py
"""
import json
from pathlib import Path

import numpy as np

from aegis_sim import combined_active_intersection as cai
from aegis_sim import adversaries as adv

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


def test_deferred_hard_cap_ties_ideal_hard_cap():
    """Product-faithful FIFO model matches ideal hard_cap under the fused attack."""
    grid = (200, 800)
    ideal = cai.combined_active_intersection_curve(
        "hard_cap", epoch_grid=grid, trials=100, rng=RNG(401),
    )
    deferred = cai.combined_active_intersection_curve(
        "deferred_hard_cap", epoch_grid=grid, trials=100, rng=RNG(401),
    )
    for e in grid:
        assert abs(ideal[e] - deferred[e]) < 0.08, f"E={e}: {ideal[e]} vs {deferred[e]}"
        assert ideal[e] < 0.12 and deferred[e] < 0.12


def test_deferred_fifo_observable_always_q():
    """FIFO deferral column model keeps external obs at exactly Q (HardCapPadder twin)."""
    rng = RNG(410)
    real = rng.poisson(12.0, size=(40, 8)).astype(float)
    real[5:10] += 30  # burst
    obs, drop, released, backlog = cai._deferred_hard_cap_columns(real, Q=10)
    assert np.all(obs == 10.0)
    assert np.all(drop == 0.0)
    assert np.all(released <= 10.0 + 1e-9)
    assert float(backlog.sum()) >= 0.0


def test_extended_ranking_recommends_hard_cap():
    """Extended scheme set recommends hard_cap; weak schemes at the bottom."""
    report = cai.combined_attack_defense_report(
        M=30, Q=25, epoch_grid=(400, 800), trials=80, rng=RNG(402),
        schemes=cai.CI_SCHEMES,
        include_sensitivity=False, include_offline=False,
    )
    by = {r["scheme"]: r for r in report["defense_ranking"]}
    assert by["hard_cap"]["holds_at_baseline"]
    assert by["deferred_hard_cap"]["holds_at_baseline"]
    assert report["recommended_mode1"]["scheme"] == "hard_cap"
    assert report["recommended_mode1"]["beats_hard_cap_in_sim"] is False
    assert report["defense_ranking"][-1]["scheme"] in ("constant_only", "truncate_only")
    assert by["constant_only"]["p_confirm_at_long_horizon"] > 0.75


def test_truncate_and_noisy_worse_than_hard_cap():
    """Non-hard-cap heuristics leak vs hard_cap at moderate horizon."""
    p_hc = cai.combined_active_intersection(
        "hard_cap", Q=25, E=600, trials=100, rng=RNG(403),
    )
    p_tr = cai.combined_active_intersection(
        "truncate_only", Q=25, E=600, trials=100, rng=RNG(404),
    )
    p_nz = cai.combined_active_intersection(
        "noisy_hard_cap", Q=25, E=600, trials=120, rng=RNG(405),
    )
    assert p_hc < 0.12
    assert p_tr > p_hc + 0.15
    assert p_nz > p_hc + 0.08


def test_sensitivity_M_hard_cap_tracks_baseline():
    """hard_cap ~ 1/M; low-Q pad_up stays elevated as M grows."""
    sens = cai.sensitivity_to_anonymity_set(
        M_grid=(10, 30), Q=15, E=600, trials=60, rng=RNG(406),
        schemes=("hard_cap", "pad_up", "constant_only"),
    )
    for _m_s, row in sens["results"].items():
        assert abs(row["by_scheme"]["hard_cap"] - row["baseline"]) < 0.15
        assert row["by_scheme"]["pad_up"] > 0.5
        assert row["by_scheme"]["constant_only"] > 0.75


def test_sensitivity_Q_pad_up_improves_but_hard_cap_flat():
    """Low Q: pad_up fails; hard_cap flat. Very high Q: pad_up collapses toward hard_cap."""
    sens = cai.sensitivity_to_padding_budget(
        Q_grid=(15, 40), E=600, trials=60, rng=RNG(407),
        schemes=("hard_cap", "pad_up"),
    )
    hc_lo = sens["results"]["15"]["by_scheme"]["hard_cap"]
    hc_hi = sens["results"]["40"]["by_scheme"]["hard_cap"]
    pu_lo = sens["results"]["15"]["by_scheme"]["pad_up"]
    pu_hi = sens["results"]["40"]["by_scheme"]["pad_up"]
    assert hc_lo < 0.12 and hc_hi < 0.12
    assert pu_lo > 0.5
    assert pu_hi < pu_lo - 0.3


def test_ci_report_omits_heavy_sections_by_flag():
    """CI path must skip sensitivity/offline to avoid hangs."""
    report = cai.combined_attack_defense_report(
        epoch_grid=(200,), trials=40, rng=RNG(408),
        schemes=("hard_cap", "pad_up"),
        include_sensitivity=False, include_offline=False,
    )
    assert "sensitivity" not in report
    assert "offline_long_horizon" not in report
    assert report["sim_to_product"]["exit_tier_exclusion_residual"]


def test_adversaries_reexport_matches_module():
    """Existing adversaries.* entry points stay wired."""
    p1 = adv.combined_active_intersection(
        "hard_cap", E=200, trials=40, rng=RNG(409),
    )
    p2 = cai.combined_active_intersection(
        "hard_cap", E=200, trials=40, rng=RNG(409),
    )
    assert p1 == p2


def test_artifact_has_sensitivity_and_offline_sections():
    """Committed artifact includes extended characterization fields."""
    path = DATA / "combined_active_intersection.analysis.json"
    assert path.is_file()
    art = json.loads(path.read_text(encoding="utf-8"))
    assert art["status"] == "[O] QUANTIFIED"
    assert "sensitivity" in art
    assert "anonymity_set_M" in art["sensitivity"]
    assert "padding_budget_Q" in art["sensitivity"]
    assert "offline_long_horizon" in art
    assert max(art["offline_long_horizon"]["epoch_grid"]) >= 3200
    # Offline hard_cap still near baseline in committed numbers.
    off_hc = art["offline_long_horizon"]["curves"]["hard_cap"]
    last = str(max(int(k) for k in off_hc))
    assert off_hc[last] <= art["baseline"] + 0.08
