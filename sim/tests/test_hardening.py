"""
Phase 8 (hardening) regression suite -- see docs/AEGIS_phase8_hardening_notes.md
and spec §13 open items. These tests characterize (not "close") the open
items: real-trace-like shapeability, an adaptive compromised-mix-set
adversary, and the guard stable-vs-adaptive exposure gap. Bounds are looser
than the core evidence ledger in test_evidence_ledger.py because these are
exploratory/open findings, not pinned defenses.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py
"""
import numpy as np
from aegis_sim import adversaries as adv
from aegis_sim import traffic, metrics

RNG = lambda s=0: np.random.default_rng(s)


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
