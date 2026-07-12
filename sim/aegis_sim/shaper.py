"""
Constant-rate hard-cap shaper -- the core Mode-1 defense.

Observable output is EXACTLY the cap every slot; excess real traffic is DEFERRED
(degrade latency, never emission shape). This is what defeats BOTH the passive
long-term intersection attack AND the active confirmation attack, at any cap >=
sustained mean. It supersedes the earlier 'pad up to ~3x mean' scheme: strictly
more secure and ~2.5x cheaper.

Provisioning rules (tested):
  - send side:     keep utilization rho = mean/cap <= 0.7 or the latency tail blows.
  - receiver side: cap Q >= ~1.2x sustained mean (Q = mean is unstable: rho=1).
"""
import numpy as np


def hard_cap(counts, c):
    """Hard-cap the per-slot count at C = c * mean, deferring excess FIFO.

    Returns dict with deferral-latency stats (in slot units) and stability flag.
    Observable output is C every slot by construction (security invariant).
    """
    counts = np.asarray(counts, float)
    m = counts.mean()
    C = c * m
    backlog = 0.0
    lat = np.empty(len(counts))
    for i, x in enumerate(counts):
        backlog += x
        backlog -= min(backlog, C)      # C leave per slot
        lat[i] = backlog / C            # slots-of-work still waiting
    return dict(
        cap=C,
        mean=float(lat.mean()),
        p99=float(np.percentile(lat, 99)),
        p999=float(np.percentile(lat, 99.9)),
        stable=bool(m < C),             # rho < 1
    )


def min_multiple(counts, budget_slots=5.0, hi=6.0, step=0.1):
    """Smallest bandwidth multiple c s.t. p99 deferral <= budget_slots.

    Encodes the shapeability cost curve: returns None if unshapeable within c<=hi
    (the infinite-variance / CV>~4 regime)."""
    c = 1.1
    while c <= hi + 1e-9:
        if hard_cap(counts, c)["p99"] <= budget_slots:
            return round(float(c), 1)
        c += step
    return None
