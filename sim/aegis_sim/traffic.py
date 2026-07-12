"""
Gaussian- and non-Gaussian-capable traffic generators.

Spans the spectrum the shapeability analysis needs:
  - Gaussian (thin tail)  -> cheap to shape
  - Lognormal (moderate)  -> finite variance, tunable via sigma
  - Pareto (heavy)        -> infinite variance when a<2 (the shapeability cliff)
  - ON/OFF aggregate      -> temporal self-similarity (Willinger/Taqqu); exponential
                             ON/OFF => Gaussian/SRD aggregate, Pareto ON/OFF (a in
                             (1,2)) => self-similar/LRD, Hurst = (3-a)/2.

Key finding these encode: hard-cap makes SECURITY invariant to traffic shape; shape
only affects COST. Cost tracks the marginal CV at the shaping point (c ~ 1 + CV for
finite variance); infinite-variance marginals are unshapeable at bounded cost.
"""
import numpy as np


def marginal_counts(kind, n, mean=10.0, rng=None):
    """Per-slot counts from a family whose tail runs Gaussian -> Pareto.

    kind: 'gaussian' | 'lognormal:SIGMA' | 'pareto:ALPHA'
    All normalized to `mean`, clipped to non-negative integers.
    """
    rng = rng or np.random.default_rng()
    if kind == "gaussian":
        x = rng.normal(mean, mean * 0.35, n)
    elif kind.startswith("lognormal"):
        s = float(kind.split(":")[1]) if ":" in kind else 0.75
        x = rng.lognormal(np.log(mean) - s * s / 2, s, n)      # E[x] = mean
    elif kind.startswith("pareto"):
        a = float(kind.split(":")[1])
        xm = mean * (a - 1) / a if a > 1 else mean * 0.3        # E[x] = mean for a>1
        x = (rng.pareto(a, n) + 1) * xm
    else:
        raise ValueError(f"unknown kind {kind}")
    return np.clip(np.round(x), 0, None)


def onoff_aggregate(kind, n_slots, n_sources=25, rng=None):
    """Aggregate active-source count/slot. Preserves burstiness (do not over-average).

    kind: 'exp' (exponential ON/OFF -> Gaussian/SRD) | 'pareto:ALPHA' (self-similar/LRD)
    """
    rng = rng or np.random.default_rng()
    agg = np.zeros(n_slots)
    a = float(kind.split(":")[1]) if kind.startswith("pareto") else None
    for _ in range(n_sources):
        t, on = 0, rng.random() < 0.5
        while t < n_slots:
            if kind == "exp":
                dur = max(1, int(rng.exponential(6)))
            else:
                dur = max(1, int((rng.pareto(a) + 1) * 2))
            if on:
                agg[t:min(t + dur, n_slots)] += 1
            on = not on
            t += dur
    return agg


def cv(x):
    """Coefficient of variation -- the cost driver for shaping."""
    x = np.asarray(x, float)
    return float(x.std() / (x.mean() + 1e-12))


# ---------------------------------------------------------------------------
# Phase 8 (hardening): real-trace ingestion.
#
# Open item (spec §13): "Real-trace shapeability (measure CV/tail on actual
# C2/telemetry, not synthetic)." No real operational trace is available in
# this repo, so this module can only provide the INGESTION path plus a
# synthetic stand-in that is deliberately harder/messier than the clean
# distributions above (diurnal cycle + heavy-tailed bursts + jitter), used to
# sanity-check the shaping pipeline against something resembling real traffic
# shape. Do NOT cite `synthetic_c2_like_counts` results as evidence for real
# deployments -- it is a stand-in for pipeline-testing only, tagged [O] until
# a genuine trace is measured.
# ---------------------------------------------------------------------------
def load_trace_counts(events, slot_seconds, t0=None, t1=None):
    """Bin a real (or real-like) timestamped event trace into per-slot counts.

    `events` is any iterable of event timestamps in seconds (e.g. read from a
    CSV/pcap-derived log upstream of this function -- this module deliberately
    does not parse a specific file format, since none ships with this repo).
    Returns a 1D array of per-slot counts, one element per `slot_seconds`
    bucket between `t0` (default = min(events)) and `t1` (default = max(events)).
    """
    t = np.asarray(sorted(events), float)
    if t.size == 0:
        raise ValueError("empty event trace")
    t0 = float(t[0]) if t0 is None else float(t0)
    t1 = float(t[-1]) if t1 is None else float(t1)
    n_slots = max(1, int(np.ceil((t1 - t0) / slot_seconds)))
    idx = np.clip(((t - t0) / slot_seconds).astype(int), 0, n_slots - 1)
    counts = np.zeros(n_slots, float)
    np.add.at(counts, idx, 1.0)
    return counts


def synthetic_c2_like_counts(n_slots, mean=10.0, rng=None):
    """Synthetic stand-in for a real C2/telemetry trace: diurnal mean cycle +
    Pareto-ish burst multiplier + multiplicative jitter. Messier than the pure
    families in `marginal_counts`/`onoff_aggregate` above; used ONLY to sanity
    check the shaping pipeline end-to-end (spec §13 open item -- this is NOT a
    substitute for measuring a genuine operational trace)."""
    rng = rng or np.random.default_rng()
    t = np.arange(n_slots)
    diurnal = 1.0 + 0.6 * np.sin(2 * np.pi * t / max(1, n_slots // 7) + rng.random() * np.pi)
    diurnal = np.clip(diurnal, 0.1, None)
    burst = (rng.pareto(2.2, n_slots) + 1)
    x = mean * diurnal * burst * np.exp(rng.normal(0, 0.15, n_slots))
    return np.clip(np.round(x), 0, None)
