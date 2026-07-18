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
    static = adv.adaptive_guard_exposure(c, g, epochs=200, mode="static", trials=20000, rng=RNG(201))
    short = adv.adaptive_guard_exposure(c, g, epochs=5, mode="adaptive", trials=20000, rng=RNG(202))
    long = adv.adaptive_guard_exposure(c, g, epochs=200, mode="adaptive", trials=20000, rng=RNG(203))
    assert static < short < long
    assert long > 0.5, "long-horizon adaptive exposure should be substantial (open risk, not mitigated)"


def test_adaptive_exposure_grows_monotonically_over_long_horizon():
    """Adaptive exposure should increase with epoch count and approach
    certainty at very long horizons (characterizes [O], not mitigated)."""
    c, g = 0.015, 3
    grid = (5, 50, 200, 800, 2000)
    curve = adv.adaptive_guard_exposure_curve(c, g, epoch_grid=grid, trials=15000, rng=RNG(204))
    vals = [curve["adaptive_by_epochs"][str(e)] for e in grid]
    assert vals[0] < vals[-1]
    assert vals[-1] > 0.85
    for i in range(len(vals) - 1):
        assert vals[i + 1] >= vals[i] - 0.02, f"non-monotonic at {grid[i]}->{grid[i+1]}"
    assert abs(curve["static_sim"] - curve["static_plateau_closed_form"]) < 0.015


def test_adaptive_guard_exposure_artifact_is_consistent():
    """Committed JSON artifact matches live simulation within MC tolerance."""
    path = DATA / "adaptive_guard_exposure.analysis.json"
    assert path.is_file(), "run sim/scripts/generate_research_artifacts.py to refresh"
    artifact = json.loads(path.read_text(encoding="utf-8"))
    live = adv.adaptive_guard_exposure_curve(
        artifact["c"], artifact["g"],
        epoch_grid=tuple(artifact["epoch_grid"]),
        trials=8000, rng=RNG(205),
    )
    assert abs(live["static_sim"] - artifact["static_sim"]) < 0.02
    for e in artifact["epoch_grid"]:
        live_v = live["adaptive_by_epochs"][str(e)]
        art_v = artifact["adaptive_by_epochs"][str(e)]
        assert abs(live_v - art_v) < 0.03, f"epoch {e}: live={live_v:.3f} art={art_v:.3f}"


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


def test_combined_attack_artifact_is_consistent():
    """Committed combined-attack JSON matches live curves within tolerance."""
    path = DATA / "combined_active_intersection.analysis.json"
    assert path.is_file(), "run sim/scripts/generate_research_artifacts.py to refresh"
    artifact = json.loads(path.read_text(encoding="utf-8"))
    for scheme in ("constant_only", "pad_up", "hard_cap"):
        live = adv.combined_active_intersection_curve(
            scheme, M=artifact["M"], s_rate=artifact["s_rate"], bg=artifact["bg"],
            Q=artifact["Q"], probe_frac=artifact["probe_frac"],
            epoch_grid=tuple(artifact["epoch_grid"]), trials=80, rng=RNG(304),
        )
        for e in artifact["epoch_grid"]:
            art_v = artifact["curves"][scheme][str(e)]
            assert abs(live[e] - art_v) < 0.12, f"{scheme} E={e}"
