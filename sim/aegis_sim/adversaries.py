"""
The AEGIS adversary suite (global passive + active confirmation).

Each returns a deanonymization probability to compare against a random baseline.
These are the regression gates: a design change that weakens a defense will move
one of these numbers above its pinned bound (see ../tests/).

Attacks:
  timing_match         - end-to-end timing correlation (Mode-1 sender->receiver)
  intersection         - long-term statistical disclosure over epochs
  active_confirm       - sender-suppression confirmation (pad-up vs hard-cap)
  bulk_correlation     - bulk-flow relationship recovery through a rendezvous
  bulk_confirm         - bulk-plane confirmation via suppression
"""
import numpy as np
from math import lgamma
from scipy.optimize import linear_sum_assignment


def _gamma_pdf(x, L, scale):
    out = np.zeros_like(x)
    m = x > 0
    xv = x[m]
    out[m] = np.exp((L - 1) * np.log(xv) - xv / scale - L * np.log(scale) - lgamma(L))
    return out


# ---------------------------------------------------------------------------
def timing_match(emission, M=25, L=3, mu=1.0, R=2.0, real_frac=0.5, T=60.0,
                 trials=6, rng=None):
    """Timing-correlation matching attack. emission='poisson' | 'constant'.
    Returns mean matching accuracy (random baseline = 1/M).

    Evidence: poisson ~0.86, constant ~0.044 (=baseline); scales to M=100.
    """
    rng = rng or np.random.default_rng(0)
    scale = 1.0 / mu
    accs = []
    for _ in range(trials):
        perm = rng.permutation(M)
        st, recv = [], [[] for _ in range(M)]
        for i in range(M):
            if emission == "constant":
                slots = np.arange(0, T, 1.0 / R)
                tr = slots[rng.random(len(slots)) < real_frac]
                st.append(slots)                      # identical grid -> no signal
            else:  # poisson real + poisson cover
                nr = rng.poisson(real_frac * R * T)
                tr = np.sort(rng.uniform(0, T, nr))
                nc = rng.poisson((1 - real_frac) * R * T)
                st.append(np.sort(np.concatenate([tr, rng.uniform(0, T, nc)])))
            recv[perm[i]].extend((tr + rng.gamma(L, scale, len(tr))).tolist())
        recv = [np.sort(np.array(r)) for r in recv]
        S = np.zeros((M, M))
        for i in range(M):
            ts = st[i]
            for j in range(M):
                ra = recv[j]
                if len(ra) == 0:
                    continue
                d = ra[:, None] - ts[None, :]
                S[i, j] = np.log(_gamma_pdf(d, L, scale).sum(axis=1) / len(ts) + 1e-12).sum()
        r, c = linear_sum_assignment(-S)
        accs.append(np.mean(c == perm[r]))
    return float(np.mean(accs))


# ---------------------------------------------------------------------------
def intersection(defense, M=30, s_rate=3.0, bg=8.0, Q=None, E=400, trials=200,
                 rng=None):
    """Long-term statistical-disclosure attack over E epochs.
    defense='poisson' | 'constant' | 'hardcap' (Q required for hardcap).
    Returns P(rank true receiver #1). Baseline = 1/M.

    Evidence: constant-only fails ~25 epochs; hardcap(Q high) flat at baseline
    through 800 epochs; Q too low fails ~100 epochs.
    """
    rng = rng or np.random.default_rng(0)
    hits = 0
    for _ in range(trials):
        R = rng.integers(M)
        bg_counts = rng.poisson(bg, size=(E, M)).astype(float)
        s = rng.poisson(s_rate, E).astype(float)
        obs = bg_counts.copy()
        obs[:, R] += s
        if defense == "poisson":
            w = s - s.mean()
            stat = (obs * w[:, None])
        else:
            observed = obs.copy()
            if defense == "hardcap":
                observed = np.maximum(observed, Q)    # pad-up variant for testing Q
            stat = observed
        cum = stat.sum(axis=0)
        hits += (np.argmax(cum) == R)
    return hits / trials


# ---------------------------------------------------------------------------
def active_confirm(scheme, M=30, s_rate=3.0, bg=8.0, Q=25, probe_frac=0.5,
                   E=400, trials=200, rng=None):
    """Active confirmation via sender suppression.
    scheme='pad_up' (observable=max(real,Q)) | 'hard_cap' (observable=Q always).
    Returns P(confirm S<->R). Baseline = 1/M.

    Evidence: pad_up needs Q~3x mean and is still weaker; hard_cap = baseline at
    ANY Q >= mean.
    """
    rng = rng or np.random.default_rng(0)
    hits = 0
    for _ in range(trials):
        R = rng.integers(M)
        probe = rng.random(E) < probe_frac
        s = rng.poisson(s_rate, E).astype(float)
        s[probe] = 0
        real = rng.poisson(bg, size=(E, M)).astype(float)
        real[:, R] += s
        obs = np.maximum(real, Q) if scheme == "pad_up" else np.full_like(real, float(Q))
        p = probe.astype(float) - probe.mean()
        score = np.abs((( Q - obs) * p[:, None]).sum(axis=0))
        hits += (np.argmax(score) == R)
    return hits / trials


# ---------------------------------------------------------------------------
def bulk_correlation(config, k=20, W=100.0, n_buckets=4, n_rounds=5, trials=200,
                     rng=None):
    """Bulk-flow relationship recovery through a rendezvous.
    config='raw' | 'size_quantized' | 'quant+rounds' | 'uniform'.
    Returns P(relationship recovered). Baseline = 1/k.

    Evidence: raw ~1.0; uniform ~baseline at k~40.
    """
    rng = rng or np.random.default_rng(0)
    accs = []
    for _ in range(trials):
        sizes = (rng.pareto(1.5, k) + 1) * 100
        starts = rng.uniform(0, W, k)
        a_size, a_time = sizes.copy(), starts.copy()
        if config in ("size_quantized", "quant+rounds", "uniform"):
            edges = np.geomspace(sizes.min(), sizes.max() + 1, n_buckets + 1)
            idx = np.clip(np.digitize(sizes, edges) - 1, 0, n_buckets - 1)
            a_size = edges[idx + 1]
        if config in ("quant+rounds", "uniform"):
            rt = np.linspace(0, W, n_rounds)
            a_time = rt[np.argmin(np.abs(starts[:, None] - rt[None, :]), axis=1)]
        if config == "uniform":
            a_size = np.full(k, a_size.max())
            a_time = np.full(k, 0.0)
        b_size = a_size.copy()
        b_time = a_time + rng.normal(0.5, 0.2, k)
        perm = rng.permutation(k)
        b_size, b_time = b_size[perm], b_time[perm]
        sN = (a_size[:, None] - b_size[None, :]) / (a_size.std() + 1e-9)
        tN = (a_time[:, None] - b_time[None, :]) / (a_time.std() + 1e-9)
        r, c = linear_sum_assignment(sN ** 2 + tN ** 2)
        accs.append(np.mean(c[r] == np.argsort(perm)[r]))
    return float(np.mean(accs))


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Phase 8 (hardening) -- open item: "Adaptive adversary varying the
# compromised-mix set across epochs" (spec §13). Contrasts a STATIC
# compromised-relay set (drawn once) against an ADAPTIVE one (redrawn fresh
# each epoch, modeling an adversary that can compromise/decompromise relays
# over time) for a client with a STABLE guard set of size g held for the
# whole horizon. Returns P(at least one of the client's g guards is
# compromised at some point across E epochs) -- i.e. cumulative exposure.
#
# This is the mechanism behind the pinned "guard rotating P->1.0; stable
# plateau 1-(1-c)^g" finding (§12): a STABLE guard set only needs to survive
# a SINGLE draw's worth of exposure risk if the adversary's compromised set
# is itself static (plateau = 1-(1-c)^g, independent of E); an ADAPTIVE
# adversary that gets to redraw the compromised set every epoch instead
# accumulates exposure across epochs even with a stable guard set, since a
# guard that was clean last epoch may be freshly compromised this epoch.
# Tag: [O] -- this quantifies the open item, it does not close it (real
# adversaries' recompromise *rate* is unknown; here it is a free parameter).
# ---------------------------------------------------------------------------
def adaptive_guard_exposure(c, g, epochs=50, mode="static", trials=2000, rng=None):
    """P(a client's g stable guards include a compromised relay within
    `epochs`), for a large relay pool, per-relay compromise prob `c`.

    mode='static'  : the compromised set is drawn ONCE and held for the whole
                     horizon (matches the closed-form plateau 1-(1-c)^g,
                     independent of `epochs` -- included as the control).
    mode='adaptive': the compromised set is REDRAWN each epoch independently
                     (adversary can move its compromise budget around);
                     exposure now grows with `epochs` even for a stable guard
                     set, since a clean guard this epoch may be dirty next
                     epoch.
    """
    rng = rng or np.random.default_rng(0)
    hits = 0
    for _ in range(trials):
        if mode == "static":
            dirty = rng.random(g) < c
            hits += bool(dirty.any())
        else:
            ever = False
            for _ in range(epochs):
                dirty = rng.random(g) < c
                if dirty.any():
                    ever = True
                    break
            hits += ever
    return hits / trials


def bulk_confirm(regime, M=30, s_rate=0.6, bg=2.0, R=400, probe=0.5, trials=200,
                 rng=None):
    """Bulk-plane confirmation via suppression.
    regime='opt_in' | 'const_partic' | 'const_count'.
    Returns P(confirm A<->B). Baseline = 1/M.

    Evidence: opt_in/const_partic ~0.97; const_count (relay bulk cover) = baseline.
    Confirmation-resistant size ceiling: F_max = cover_budget * round_period.
    """
    rng = rng or np.random.default_rng(0)
    hits = 0
    for _ in range(trials):
        B = rng.integers(M)
        probe_r = rng.random(R) < probe
        a_real = (rng.random(R) < s_rate).astype(float)
        a_real[probe_r] = 0
        obs = rng.poisson(bg, size=(R, M)).astype(float)
        obs[:, B] += a_real
        if regime == "const_count":
            obs[:] = float(round(bg + 1))              # relay cover -> constant
        p = probe_r.astype(float) - probe_r.mean()
        score = np.abs((obs * p[:, None]).sum(axis=0))
        hits += (np.argmax(score) == B)
    return hits / trials
