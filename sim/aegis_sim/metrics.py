"""Anonymity / traffic metrics used across the suite."""
import numpy as np


def hurst(x):
    """Rough Hurst exponent via variance-of-aggregated-series.
    ~0.5 = short-range dependent (Poisson-like); ->1 = self-similar / LRD."""
    x = np.asarray(x, float)
    x = x - x.mean()
    N = len(x)
    ms = np.array([1, 2, 4, 8, 16, 32, 64])
    var = []
    for m in ms:
        k = N // m
        var.append(x[:k * m].reshape(k, m).mean(axis=1).var())
    slope = np.polyfit(np.log(ms), np.log(np.array(var) + 1e-12), 1)[0]
    return (slope + 2) / 2


def bulk_size_ceiling(cover_bytes_per_s, round_period_s, c_flows=8, avg_real=3):
    """Confirmation-resistant file-size ceiling: F_max = cover_budget * T / slack."""
    return cover_bytes_per_s * round_period_s / max(c_flows - avg_real, 1)


# ---------------------------------------------------------------------------
# Phase 8 (hardening): honest shapeability characterization for a given trace.
# ---------------------------------------------------------------------------
def shapeability_report(counts, budget_slots=5.0, hi=6.0):
    """Summarize the cost-to-shape for an arbitrary count series (real or
    synthetic). Ties together traffic.cv, shaper.min_multiple and hurst so a
    single call gives the honest per-trace characterization the spec's
    epsilon-per-tier language (§8, §10 Phase 8 gate) asks for.

    Returns a dict: cv, hurst, min_multiple (None if unshapeable at c<=hi),
    and a coarse `tier` label ('cheap' | 'feasible' | 'unshapeable') per the
    §6 cost-by-CV rule of thumb (CV<=1 cheap; 1<CV<=~2.5 feasible; else costly
    /unshapeable).
    """
    from . import shaper, traffic as _traffic  # local import: avoid cycle at module load

    x = np.asarray(counts, float)
    c = _traffic.cv(x)
    h = hurst(x) if len(x) >= 128 else float("nan")
    m = shaper.min_multiple(x, budget_slots=budget_slots, hi=hi)
    if c <= 1.0:
        tier = "cheap"
    elif c <= 2.5:
        tier = "feasible"
    else:
        tier = "unshapeable"
    return dict(cv=c, hurst=h, min_multiple=m, tier=tier)
