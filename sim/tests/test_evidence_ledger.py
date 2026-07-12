"""
Evidence-ledger regression suite.

Each test pins a KEY FINDING from the AEGIS red-team (see Section 12 of
docs/AEGIS_SPEC_v3_consolidated.md). If a future change to a defense weakens it,
the corresponding test fails. Bounds are loose enough to absorb Monte-Carlo noise
at the small trial counts used here, tight enough to catch a real regression.

Run:  cd sim && pip install -r requirements.txt && pytest -q
"""
import numpy as np
import pytest
from aegis_sim import adversaries as adv
from aegis_sim import traffic, shaper, metrics

RNG = lambda s=0: np.random.default_rng(s)


# --- Mode 1: emission ------------------------------------------------------
def test_delay_alone_is_not_enough():
    """Poisson cover (delay-only regime) leaks badly; constant-rate does not."""
    poisson = adv.timing_match("poisson", M=25, rng=RNG(1))
    assert poisson > 0.5, "poisson cover should leak (>0.5)"

def test_constant_rate_kills_timing():
    """Constant-rate emission drives the timing attack to the random baseline."""
    const = adv.timing_match("constant", M=25, rng=RNG(2))
    assert const < 0.12, f"constant-rate should be ~1/M, got {const}"


# --- Mode 1: intersection + hard-cap --------------------------------------
def test_intersection_breaks_constant_rate_alone():
    """Constant-rate ALONE fails long-term intersection (single-window != long-term)."""
    p = adv.intersection("constant", M=30, E=200, trials=120, rng=RNG(3))
    assert p > 0.5, f"constant-only should be deanonymized over epochs, got {p}"

def test_hardcap_high_Q_defeats_intersection():
    """Hard-cap with Q above peak holds intersection at baseline."""
    p = adv.intersection("hardcap", M=30, Q=30, E=200, trials=120, rng=RNG(4))
    assert p < 0.12, f"hardcap Q-high should be ~1/M, got {p}"


# --- Mode 1: active confirmation ------------------------------------------
def test_padup_leaks_under_active_confirmation():
    p = adv.active_confirm("pad_up", Q=15, trials=150, rng=RNG(5))
    assert p > 0.5, f"pad-up at low Q should be confirmable, got {p}"

def test_hardcap_defeats_active_confirmation_any_Q():
    """Hard-cap defeats active confirmation even at low Q (structural)."""
    p = adv.active_confirm("hard_cap", Q=12, trials=150, rng=RNG(6))
    assert p < 0.12, f"hard-cap should be ~1/M at any Q, got {p}"


# --- Shapeability ----------------------------------------------------------
def test_gaussian_is_cheap_to_shape():
    x = traffic.marginal_counts("gaussian", 40000, rng=RNG(7))
    assert shaper.min_multiple(x) <= 1.4

def test_infinite_variance_is_unshapeable():
    """Pareto a<2 (infinite variance) needs impractical overhead (or is unbounded)."""
    x = traffic.marginal_counts("pareto:1.5", 80000, rng=RNG(8))
    c = shaper.min_multiple(x)
    # either unshapeable within c<=6, or only shapeable at an impractical multiple
    assert c is None or c >= 3.5, f"infinite-variance should be costly/unshapeable, got {c}"

def test_multiplexing_smooths_self_similar():
    """Strong self-similarity multiplexes to low CV -> cheap to shape."""
    x = traffic.onoff_aggregate("pareto:1.2", 60000, n_sources=25, rng=RNG(9))
    assert metrics.hurst(x) > 0.65      # LRD present
    assert traffic.cv(x) < 0.4          # but amplitude bounded by multiplexing


# --- Mode 2: bulk ----------------------------------------------------------
def test_raw_bulk_leaks_relationship():
    p = adv.bulk_correlation("raw", k=20, trials=100, rng=RNG(10))
    assert p > 0.8, f"raw rendezvous should expose relationship, got {p}"

def test_uniform_batched_bulk_hides_relationship():
    p = adv.bulk_correlation("uniform", k=40, trials=100, rng=RNG(11))
    assert p < 0.1, f"uniform+batched should approach baseline, got {p}"

def test_bulk_confirmation_needs_relay_cover():
    leak = adv.bulk_confirm("opt_in", trials=120, rng=RNG(12))
    safe = adv.bulk_confirm("const_count", trials=120, rng=RNG(13))
    assert leak > 0.5 and safe < 0.12


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
