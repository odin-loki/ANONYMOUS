"""
Phase 8 (hardening) regression suite -- see docs/AEGIS_phase8_hardening_notes.md
and spec §13 open items. These tests characterize (not "close") the open
items: real-trace-like shapeability, an adaptive compromised-mix-set
adversary, combined active+intersection long horizon, and the guard
stable-vs-adaptive exposure gap. Bounds are looser than the core evidence
ledger in test_evidence_ledger.py because these are exploratory/open findings,
not pinned defenses.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py
"""
import json
from pathlib import Path

import numpy as np
from aegis_sim import adversaries as adv
from aegis_sim import traffic, metrics

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"


# --- real-trace-like shapeability (open item: needs a genuine trace) ------
def test_trace_ingestion_roundtrip():
    """load_trace_counts bins a timestamped event log into per-slot counts."""
    rng = RNG(100)
    events = np.sort(rng.uniform(0, 1000, 5000))
    counts = traffic.load_trace_counts(events, slot_seconds=1.0, t0=0.0, t1=1000.0)
    assert counts.sum() == 5000
    assert len(counts) == 1000


def test_synthetic_c2_like_is_messier_than_gaussian():
    """The C2-like stand-in should have higher CV than clean Gaussian traffic
    (sanity check that it's exercising the harder regime, not a free pass)."""
    rng = RNG(101)
    gauss = traffic.marginal_counts("gaussian", 20000, rng=RNG(101))
    c2like = traffic.synthetic_c2_like_counts(20000, rng=rng)
    assert traffic.cv(c2like) > traffic.cv(gauss)


def test_shapeability_report_labels_are_consistent():
    """shapeability_report's tier label agrees with the underlying CV rule of
    thumb (§6) for both a cheap (Gaussian) and a harder (C2-like) series."""
    cheap = metrics.shapeability_report(traffic.marginal_counts("gaussian", 20000, rng=RNG(102)))
    assert cheap["tier"] == "cheap"
    assert cheap["min_multiple"] is not None and cheap["min_multiple"] <= 1.6

    harder = metrics.shapeability_report(traffic.synthetic_c2_like_counts(40000, rng=RNG(103)))
    assert harder["cv"] > cheap["cv"]
    # harder trace should cost strictly more (or be unshapeable) than the cheap one
    assert harder["tier"] in ("feasible", "unshapeable") or (
        harder["min_multiple"] or 0
    ) >= (cheap["min_multiple"] or 0)


# --- adaptive adversary (open item: compromised-mix set varies over time) --
def test_static_compromised_set_matches_closed_form_plateau():
    """mode='static' must reproduce the closed-form 1-(1-c)^g plateau
    (this is the control -- confirms the simulator agrees with the formula
    already pinned in aegis-topology / spec §12)."""
    c, g = 0.01, 3
    closed_form = 1 - (1 - c) ** g
    sim = adv.adaptive_guard_exposure(c, g, mode="static", trials=20000, rng=RNG(200))
    assert abs(sim - closed_form) < 0.01


def test_adaptive_adversary_increases_exposure_over_horizon():
    """An adversary that can redraw its compromised set every epoch (instead
    of once) accumulates MORE exposure against a stable guard set as the
    horizon grows -- this is exactly the open risk spec §13 flags: static
    guard *membership* does not fully neutralize an adversary that can move
    its *compromise budget* around over time. Quantified here, not solved."""
    c, g = 0.02, 3
    # CI-friendly trial counts; full curves via generate_research_artifacts.py
    static = adv.adaptive_guard_exposure(c, g, epochs=80, mode="static", trials=3000, rng=RNG(201))
    short = adv.adaptive_guard_exposure(c, g, epochs=5, mode="adaptive", trials=3000, rng=RNG(202))
    long = adv.adaptive_guard_exposure(c, g, epochs=80, mode="adaptive", trials=3000, rng=RNG(203))
    assert static < short < long
    assert long > 0.35, "mid-horizon adaptive exposure should be substantial (open risk, not mitigated)"


def test_adaptive_exposure_grows_monotonically_over_long_horizon():
    """Adaptive exposure should increase with epoch count (characterizes [O], not mitigated)."""
    c, g = 0.015, 3
    grid = (5, 50, 200, 400)
    curve = adv.adaptive_guard_exposure_curve(c, g, epoch_grid=grid, trials=2500, rng=RNG(204))
    vals = [curve["adaptive_by_epochs"][str(e)] for e in grid]
    assert vals[0] < vals[-1]
    assert vals[-1] > 0.7
    for i in range(len(vals) - 1):
        assert vals[i + 1] >= vals[i] - 0.03, f"non-monotonic at {grid[i]}->{grid[i+1]}"
    assert abs(curve["static_sim"] - curve["static_plateau_closed_form"]) < 0.03


def test_adaptive_guard_exposure_artifact_is_consistent():
    """Committed JSON artifact has expected schema and sane probabilities."""
    path = DATA / "adaptive_guard_exposure.analysis.json"
    assert path.is_file(), "run sim/scripts/generate_research_artifacts.py to refresh"
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert "adaptive_by_epochs" in artifact
    assert "mitigated_by_epochs" in artifact
    assert "mitigated_first_by_epochs" in artifact
    assert "mitigated_v3_by_epochs" in artifact
    assert "mitigation_params_v2" in artifact
    assert "mitigation_params_v3" in artifact
    assert artifact["best_mitigation_preset"] in ("adaptive_v3", "adaptive_v4")
    for e in artifact["epoch_grid"]:
        a = artifact["adaptive_by_epochs"][str(e)]
        m1 = artifact["mitigated_first_by_epochs"][str(e)]
        m2 = artifact["mitigated_by_epochs"][str(e)]
        m3 = artifact["mitigated_v3_by_epochs"][str(e)]
        assert 0.0 <= m3 <= m2 + 0.02, f"E={e}: v3 should be near/below v2 (allow tiny MC noise)"
        assert 0.0 <= m2 <= m1 <= a <= 1.0 + 1e-9, f"E={e}: v2 should be <= v1 <= adaptive"
        if "mitigated_v4_by_epochs" in artifact:
            m4 = artifact["mitigated_v4_by_epochs"][str(e)]
            assert 0.0 <= m4 <= m3 + 0.03, f"E={e}: v4 should be near/below v3"
    # Spot-check one mid horizon against a cheap live run (not full artifact recompute).
    live = adv.adaptive_guard_exposure(
        artifact["c"], artifact["g"], epochs=200, mode="adaptive", trials=2000, rng=RNG(205),
    )
    assert abs(live - artifact["adaptive_by_epochs"]["200"]) < 0.08


def test_mitigated_adaptive_exposure_lower_than_unmitigated():
    """v2 mitigation reduces mid-horizon exposure vs unmitigated adaptive."""
    c, g = 0.015, 3
    unmit = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="adaptive", trials=4000, rng=RNG(210),
    )
    mit = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated", trials=4000, rng=RNG(211),
    )
    assert unmit > 0.85, "unmitigated adaptive should be high at E=200 (open risk)"
    assert mit < unmit - 0.02, f"mitigation should help: unmit={unmit:.3f} mit={mit:.3f}"
    assert mit > artifact_static_plateau(c, g), "mitigated still above static plateau control"


def test_mitigated_v2_improves_mid_horizon_vs_v1_baseline():
    """v2 sim params should lower E=200 exposure vs v1 first-pass baseline."""
    c, g = 0.015, 3
    v1 = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated_first", trials=4000, rng=RNG(213),
    )
    v2 = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated", trials=4000, rng=RNG(214),
    )
    assert v2 <= v1 + 1e-9, f"v2 {v2:.3f} should be <= v1 baseline {v1:.3f}"
    if v2 < v1 - 0.01:
        return
    # Honest gate: if params tie within noise, v2 aggressive tier must help.
    v2_agg = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated_aggressive", trials=4000, rng=RNG(215),
    )
    assert v2_agg < v1 - 0.01, (
        f"v2 did not beat v1 at E=200 (v1={v1:.3f} v2={v2:.3f} aggressive={v2_agg:.3f}); "
        "retune params or document plateau in adaptive_guard_mitigation.md"
    )


def test_mitigated_v3_improves_mid_horizon_vs_v2():
    """v3 (decaying stickiness + hard cap + reputation soft rotate) beats v2 at E=200."""
    c, g = 0.015, 3
    v2 = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated", trials=3500, rng=RNG(220),
    )
    v3 = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated_v3", trials=3500, rng=RNG(221),
    )
    assert v3 < v2 - 0.08, (
        f"v3 should clearly beat v2 at E=200 (v2={v2:.3f} v3={v3:.3f}); "
        "retune _MITIGATION_V3 or document in adaptive_guard_mitigation.md"
    )
    # Honest residual: still above static plateau; §13 not closed.
    assert v3 > artifact_static_plateau(c, g)


def test_mitigated_v3_still_saturates_long_horizon():
    """v3 lowers the curve but does not close §13 — long horizon remains high."""
    c, g = 0.015, 3
    # Bound epochs/trials for CI; full curve via generate_research_artifacts / sweep script.
    mid = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated_v3", trials=2000, rng=RNG(222),
    )
    long = adv.adaptive_guard_exposure(
        c, g, epochs=800, mode="mitigated_v3", trials=1500, rng=RNG(223),
    )
    assert mid < 0.70, f"v3 mid-horizon should be well below v2 (~0.77); got {mid:.3f}"
    assert long > mid + 0.05, "exposure should still grow with horizon under v3"
    assert long > 0.55, "long-horizon saturation residual remains (open risk)"


def test_mitigated_v4_improves_e2000_vs_v3():
    """S5: v4 targets E=2000 saturation residual vs v3; §13 still open."""
    c, g = 0.015, 3
    v3 = adv.adaptive_guard_exposure(
        c, g, epochs=2000, mode="mitigated_v3", trials=1500, rng=RNG(230),
    )
    v4 = adv.adaptive_guard_exposure(
        c, g, epochs=2000, mode="mitigated_v4", trials=1500, rng=RNG(231),
    )
    assert v4 < v3 - 0.04, (
        f"v4 should beat v3 at E=2000 (v3={v3:.3f} v4={v4:.3f})"
    )
    assert v4 > 0.45, "honest residual: long-horizon exposure remains material"
    mid_v4 = adv.adaptive_guard_exposure(
        c, g, epochs=200, mode="mitigated_v4", trials=2000, rng=RNG(232),
    )
    assert mid_v4 < 0.40, f"v4 mid-horizon should beat v3 (~0.45); got {mid_v4:.3f}"


def test_adaptive_mitigation_param_sweep_ci_bound():
    """CI-friendly sweep ranks locked v3 near the best grid point."""
    sweep = adv.adaptive_mitigation_param_sweep(
        c=0.015, g=3, epochs=200, trials=1200, rng=RNG(224),
    )
    assert sweep["v3_default"] < sweep["v2_baseline"] - 0.05
    best = sweep["points"][0]["exposure"]
    assert sweep["v3_default"] <= best + 0.08, "locked v3 should be near sweep optimum"


def artifact_static_plateau(c, g):
    return 1 - (1 - c) ** g


def test_mitigated_exposure_curve_stays_below_adaptive():
    """Mitigated v2/v3 curves stay below adaptive at mid horizons; may near-saturate later."""
    report = adv.adaptive_guard_exposure_curve(
        c=0.015, g=3, epoch_grid=(100, 200, 400), trials=2000, rng=RNG(212),
    )
    for e in (100, 200, 400):
        a = report["adaptive_by_epochs"][str(e)]
        m = report["mitigated_by_epochs"][str(e)]
        m1 = report["mitigated_first_by_epochs"][str(e)]
        m3 = report["mitigated_v3_by_epochs"][str(e)]
        assert m <= m1 + 1e-9, f"E={e}: v2 {m:.3f} should be <= v1 {m1:.3f}"
        assert m <= a + 1e-9, f"E={e}: mitigated {m:.3f} should be <= adaptive {a:.3f}"
        assert m3 <= m + 0.02, f"E={e}: v3 {m3:.3f} should be <= v2 {m:.3f} (+noise)"
        assert m3 <= a + 1e-9, f"E={e}: v3 {m3:.3f} should be <= adaptive {a:.3f}"
    assert report["mitigation_at_200"]["reduction_v2"] > 0.02
    assert report["mitigation_at_200"]["reduction_v3"] > report["mitigation_at_200"]["reduction_v2"]



# --- combined active(n-1) + intersection (open item, Mode-1 long horizon) ----
def test_combined_attack_constant_only_degrades_over_long_horizon():
    """Without receiver hard-cap, fused attack deanonymizes over long horizons."""
    grid = (100, 400, 800, 1600)
    curve = adv.combined_active_intersection_curve(
        "constant_only", epoch_grid=grid, trials=150, rng=RNG(300),
    )
    assert curve[grid[0]] > 1 / 30
    assert curve[grid[-1]] > 0.75


def test_combined_attack_hardcap_holds_at_baseline_long_horizon():
    """Mode-1 hard-cap receiver padding holds fused attack at random baseline."""
    p = adv.combined_active_intersection(
        "hard_cap", Q=30, E=800, trials=150, rng=RNG(301),
    )
    assert p < 0.12, f"hard_cap combined should stay ~1/M, got {p}"


def test_combined_attack_pad_up_leaks_and_composes():
    """Pad-up fails; combined attack at E=800 should exceed intersection-only."""
    inter = adv.intersection("hardcap", Q=15, E=800, trials=150, rng=RNG(302))
    combined = adv.combined_active_intersection(
        "pad_up", Q=15, E=800, trials=150, rng=RNG(303),
    )
    assert inter > 0.5 and combined > 0.5
    assert combined >= inter - 0.05


def test_combined_attack_defense_report_ranks_hard_cap_first():
    """Defense report ranks schemes and recommends Mode-1 receiver hard-cap."""
    report = adv.combined_attack_defense_report(
        M=30, Q=25, epoch_grid=(200, 800), trials=120, rng=RNG(305),
        schemes=("constant_only", "pad_up", "hard_cap"),
        include_sensitivity=False, include_offline=False,
    )
    ranking = report["defense_ranking"]
    assert ranking[0]["scheme"] == "hard_cap"
    assert ranking[0]["holds_at_baseline"]
    assert ranking[-1]["scheme"] == "constant_only"
    rec = report["recommended_mode1"]
    assert rec["scheme"] == "hard_cap" and rec["receiver_hard_cap"]
    assert rec["Q_recommended_min"] >= int(np.ceil(1.2 * (report["bg"] + report["s_rate"])))


def test_combined_attack_artifact_is_consistent():
    """Committed combined-attack JSON matches live curves within tolerance."""
    path = DATA / "combined_active_intersection.analysis.json"
    assert path.is_file(), (
        "run: cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py "
        "--only combined"
    )
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert artifact["characterizes_not_closes"] is True
    assert artifact["recommended_mode1"]["scheme"] == "hard_cap"
    assert artifact["recommended_mode1"]["beats_hard_cap_in_sim"] is False
    by = {r["scheme"]: r for r in artifact["defense_ranking"]}
    assert by["hard_cap"]["holds_at_baseline"]
    assert by["deferred_hard_cap"]["holds_at_baseline"]
    assert by["constant_only"]["p_confirm_at_long_horizon"] > 0.75
    for scheme in ("constant_only", "pad_up", "hard_cap"):
        live = adv.combined_active_intersection_curve(
            scheme, M=artifact["M"], s_rate=artifact["s_rate"], bg=artifact["bg"],
            Q=artifact["Q"], probe_frac=artifact["probe_frac"],
            epoch_grid=tuple(artifact["epoch_grid"]), trials=80, rng=RNG(304),
        )
        for e in artifact["epoch_grid"]:
            art_v = artifact["curves"][scheme][str(e)]
            assert abs(live[e] - art_v) < 0.15, f"{scheme} E={e}"
    assert "sim_to_product" in artifact
    assert "HardCapPadder" in artifact["sim_to_product"]["rust_type"]
