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

# Combined active+intersection (Mode-1) lives in combined_active_intersection.py;
# re-exported here for existing callers / evidence-ledger imports.
from aegis_sim.combined_active_intersection import (  # noqa: E402
    CI_SCHEMES,
    OFFLINE_EPOCH_GRID,
    combined_active_intersection,
    combined_active_intersection_curve,
    combined_attack_defense_report,
    combined_attack_report,
    sensitivity_to_anonymity_set,
    sensitivity_to_padding_budget,
)


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
# v1 first-pass mitigation params (baseline for v2 comparison).
_MITIGATION_V1 = dict(
    max_sticky_epochs=10, demotion_decay=0.72, demotion_floor=0.15,
    demotion_linger=0, aggressive=False,
    soft_sticky_epochs=10, stickiness_decay=1.0,
    rep_signal_scale=0.0, rep_demotion_extra=1.0,
)
# v2 improved mitigation — tighter sticky cap, stronger demotion, linger after dirty.
_MITIGATION_V2 = dict(
    max_sticky_epochs=8, demotion_decay=0.55, demotion_floor=0.10,
    demotion_linger=5, aggressive=False,
    soft_sticky_epochs=8, stickiness_decay=1.0,
    rep_signal_scale=0.0, rep_demotion_extra=1.0,
)
_MITIGATION_V2_AGGRESSIVE = dict(
    max_sticky_epochs=7, demotion_decay=0.50, demotion_floor=0.08,
    demotion_linger=6, aggressive=True,
    soft_sticky_epochs=7, stickiness_decay=1.0,
    rep_signal_scale=0.0, rep_demotion_extra=1.0,
)
# v3 — hard epoch-age cap + decaying stickiness + reputation-aware soft rotate.
# Strong mid-horizon defense; maps to client GuardMitigationPolicy::adaptive_v3.
# Does NOT close §13 (long horizons still saturate toward 1.0).
_MITIGATION_V3 = dict(
    max_sticky_epochs=4, demotion_decay=0.40, demotion_floor=0.05,
    demotion_linger=10, aggressive=True,
    soft_sticky_epochs=2, stickiness_decay=0.62,
    rep_signal_scale=0.45, rep_demotion_extra=0.88,
)
# v4 — targets E=2000 saturation residual vs v3 (S5): tighter hard/soft sticky,
# stronger demotion + linger, higher reputation soft-rotate pressure.
# Best in-tree long-horizon sim defense; maps to adaptive_v4 Rust preset.
# Does NOT close §13 (still saturates, slower).
_MITIGATION_V4 = dict(
    max_sticky_epochs=2, demotion_decay=0.30, demotion_floor=0.02,
    demotion_linger=24, aggressive=True,
    soft_sticky_epochs=1, stickiness_decay=0.40,
    rep_signal_scale=0.75, rep_demotion_extra=0.78,
)

_MITIGATED_MODES = (
    "mitigated", "mitigated_first", "mitigated_aggressive",
    "mitigated_v3", "mitigated_v4",
)


def _mitigation_params_for_mode(mode, max_sticky_epochs=None, demotion_decay=None,
                                demotion_floor=None, demotion_linger=None,
                                aggressive=None, soft_sticky_epochs=None,
                                stickiness_decay=None, rep_signal_scale=None,
                                rep_demotion_extra=None):
    """Resolve effective mitigation knobs for mitigated* modes."""
    if mode == "mitigated_first":
        p = _MITIGATION_V1.copy()
    elif mode == "mitigated_aggressive":
        p = _MITIGATION_V2_AGGRESSIVE.copy()
    elif mode == "mitigated":
        p = _MITIGATION_V2.copy()
    elif mode == "mitigated_v3":
        p = _MITIGATION_V3.copy()
    elif mode == "mitigated_v4":
        p = _MITIGATION_V4.copy()
    else:
        raise ValueError(f"unknown mitigation mode {mode!r}")
    overrides = {
        "max_sticky_epochs": max_sticky_epochs,
        "demotion_decay": demotion_decay,
        "demotion_floor": demotion_floor,
        "demotion_linger": demotion_linger,
        "aggressive": aggressive,
        "soft_sticky_epochs": soft_sticky_epochs,
        "stickiness_decay": stickiness_decay,
        "rep_signal_scale": rep_signal_scale,
        "rep_demotion_extra": rep_demotion_extra,
    }
    for key, val in overrides.items():
        if val is not None:
            p[key] = val
    return p


def _run_mitigated_trial(c, g, epochs, rng, params):
    """One Monte Carlo trial under sticky-cap / demotion / (v3) soft-signal mitigation."""
    ever = False
    eff_c = float(c)
    sticky = 0
    floor_c = c * params["demotion_floor"]
    linger = 0
    stickiness = 1.0
    soft_e = int(params.get("soft_sticky_epochs", params["max_sticky_epochs"]))
    sdec = float(params.get("stickiness_decay", 1.0))
    rep_p = min(0.45, float(params.get("rep_signal_scale", 0.0)) * g * c)
    rep_extra = float(params.get("rep_demotion_extra", 1.0))
    for _ in range(epochs):
        sticky += 1
        stickiness *= sdec
        dirty = bool((rng.random(g) < eff_c).any())
        if dirty:
            ever = True
        # Reputation / peer-health soft signal: preemptive rotate, not exposure.
        rep_signal = (not dirty) and (rng.random() < rep_p)
        soft = sticky >= soft_e and (rng.random() > stickiness)
        hard = sticky >= params["max_sticky_epochs"]
        if dirty or hard or soft or rep_signal:
            sticky = 0
            stickiness = 1.0
            decay = params["demotion_decay"]
            if dirty and params["aggressive"]:
                decay *= 0.75
            if rep_signal:
                decay *= rep_extra
            eff_c = max(floor_c, eff_c * decay)
            linger = params["demotion_linger"]
        if linger > 0:
            linger -= 1
        else:
            eff_c = max(floor_c, eff_c * (1.0 - 2e-4))
        if ever:
            break
    return ever


def adaptive_guard_exposure(c, g, epochs=50, mode="static", trials=2000, rng=None,
                           max_sticky_epochs=None, demotion_decay=None,
                           demotion_floor=None, demotion_linger=None,
                           aggressive=None, soft_sticky_epochs=None,
                           stickiness_decay=None, rep_signal_scale=None,
                           rep_demotion_extra=None):
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
    mode='mitigated_first': v1 mitigation — sticky cap + re-sample on dirty
                     epoch + effective `c` demotion (baseline for v2).
    mode='mitigated': v2 mitigation — tighter sticky cap, stronger demotion,
                     linger after dirty signal; optional kwargs override presets.
    mode='mitigated_aggressive': v2 second tier — extra demotion on dirty epoch.
    mode='mitigated_v3': v3 — hard epoch-age cap, decaying stickiness,
                     reputation-aware soft rotate + stronger demotion.
                     Reduces mid/long-horizon exposure vs v2 in sim;
                     does NOT close §13 (saturation residual remains).
    mode='mitigated_v4': v4 — tighter sticky (hard=2/soft=1), stronger demotion;
                     targets E=2000 residual vs v3; does NOT close §13.
    """
    rng = rng or np.random.default_rng(0)
    hits = 0
    for _ in range(trials):
        if mode == "static":
            dirty = rng.random(g) < c
            hits += bool(dirty.any())
        elif mode == "adaptive":
            ever = False
            for _ in range(epochs):
                dirty = rng.random(g) < c
                if dirty.any():
                    ever = True
                    break
            hits += ever
        elif mode in _MITIGATED_MODES:
            params = _mitigation_params_for_mode(
                mode, max_sticky_epochs, demotion_decay, demotion_floor,
                demotion_linger, aggressive, soft_sticky_epochs,
                stickiness_decay, rep_signal_scale, rep_demotion_extra,
            )
            hits += _run_mitigated_trial(c, g, epochs, rng, params)
        else:
            raise ValueError(f"unknown mode {mode!r}")
    return hits / trials


def adaptive_guard_exposure_mitigation_report(c, g, epochs=200, trials=20000, rng=None):
    """Compare unmitigated adaptive vs v1/v2/v3/v4 mitigation at one horizon."""
    rng = rng or np.random.default_rng(0)
    adaptive = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="adaptive", trials=trials, rng=rng,
    )
    mitigated_first = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_first", trials=trials, rng=rng,
    )
    mitigated_v2 = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated", trials=trials, rng=rng,
    )
    mitigated_aggressive = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_aggressive", trials=trials, rng=rng,
    )
    mitigated_v3 = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_v3", trials=trials, rng=rng,
    )
    mitigated_v4 = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_v4", trials=trials, rng=rng,
    )
    return {
        "epochs": epochs,
        "adaptive_unmitigated": adaptive,
        "mitigated_first": mitigated_first,
        "mitigated_v2": mitigated_v2,
        "mitigated_aggressive": mitigated_aggressive,
        "mitigated_v3": mitigated_v3,
        "mitigated_v4": mitigated_v4,
        "reduction_v1": adaptive - mitigated_first,
        "reduction_v2": adaptive - mitigated_v2,
        "reduction_v3": adaptive - mitigated_v3,
        "reduction_v4": adaptive - mitigated_v4,
        "v2_improvement_vs_v1": mitigated_first - mitigated_v2,
        "v3_improvement_vs_v2": mitigated_v2 - mitigated_v3,
        "v4_improvement_vs_v3": mitigated_v3 - mitigated_v4,
        "mitigation_params_v1": _MITIGATION_V1,
        "mitigation_params_v2": _MITIGATION_V2,
        "mitigation_params_v2_aggressive": _MITIGATION_V2_AGGRESSIVE,
        "mitigation_params_v3": _MITIGATION_V3,
        "mitigation_params_v4": _MITIGATION_V4,
    }


def adaptive_guard_exposure_curve(c, g, epoch_grid=(5, 20, 50, 100, 200, 500, 800, 2000),
                                  trials=20000, rng=None):
    """Exposure vs horizon for static (plateau) vs adaptive (redrawn each epoch).

    Includes `mitigated_by_epochs` (v2), `mitigated_first_by_epochs` (v1),
    `mitigated_aggressive_by_epochs`, `mitigated_v3_by_epochs`, and
    `mitigated_v4_by_epochs`. Returns a dict suitable for JSON commit under
    sim/data/. Tag [O]: characterizes the open item; mitigation reduces but
    does not close it.
    """
    rng = rng or np.random.default_rng(divmod(hash((c, g)), 2**32)[1])
    static_plateau = 1 - (1 - c) ** g
    static_sim = adaptive_guard_exposure(c, g, mode="static", trials=trials, rng=rng)
    adaptive = {}
    mitigated_first = {}
    mitigated = {}
    mitigated_aggressive = {}
    mitigated_v3 = {}
    mitigated_v4 = {}
    for e in epoch_grid:
        adaptive[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="adaptive", trials=trials, rng=rng
        )
        mitigated_first[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="mitigated_first", trials=trials, rng=rng
        )
        mitigated[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="mitigated", trials=trials, rng=rng
        )
        mitigated_aggressive[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="mitigated_aggressive", trials=trials, rng=rng
        )
        mitigated_v3[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="mitigated_v3", trials=trials, rng=rng
        )
        mitigated_v4[str(e)] = adaptive_guard_exposure(
            c, g, epochs=e, mode="mitigated_v4", trials=trials, rng=rng
        )
    return {
        "tag": "spec_13_O_adaptive_compromised_mix_set",
        "characterizes_not_closes": True,
        "mitigation_partial_not_closed": True,
        "best_mitigation_preset": "adaptive_v4",
        "c": c,
        "g": g,
        "trials": trials,
        "static_plateau_closed_form": static_plateau,
        "static_sim": static_sim,
        "epoch_grid": list(epoch_grid),
        "adaptive_by_epochs": adaptive,
        "mitigated_first_by_epochs": mitigated_first,
        "mitigated_by_epochs": mitigated,
        "mitigated_aggressive_by_epochs": mitigated_aggressive,
        "mitigated_v3_by_epochs": mitigated_v3,
        "mitigated_v4_by_epochs": mitigated_v4,
        "mitigation_params_v1": _MITIGATION_V1,
        "mitigation_params_v2": _MITIGATION_V2,
        "mitigation_params_v2_aggressive": _MITIGATION_V2_AGGRESSIVE,
        "mitigation_params_v3": _MITIGATION_V3,
        "mitigation_params_v4": _MITIGATION_V4,
        "mitigation_at_200": adaptive_guard_exposure_mitigation_report(
            c, g, epochs=200, trials=trials, rng=rng,
        ),
        "mitigation_at_2000": adaptive_guard_exposure_mitigation_report(
            c, g, epochs=2000, trials=min(trials, 8000), rng=rng,
        ),
    }


def adaptive_mitigation_param_sweep(c=0.015, g=3, epochs=200, trials=2500, rng=None,
                                    grid=None):
    """CI-friendly parameter sweep around v3 knobs (bounded trials/epochs).

    Returns dict with per-point exposure and ranking vs v2 baseline at the same
    (c, g, epochs, trials). Not a closure claim.
    """
    rng = rng or np.random.default_rng(4242)
    if grid is None:
        grid = [
            dict(max_sticky_epochs=4, soft_sticky_epochs=2, stickiness_decay=0.62,
                 demotion_decay=0.40, demotion_floor=0.05, demotion_linger=10,
                 rep_signal_scale=0.45, rep_demotion_extra=0.88, aggressive=True),
            dict(max_sticky_epochs=5, soft_sticky_epochs=2, stickiness_decay=0.70,
                 demotion_decay=0.42, demotion_floor=0.05, demotion_linger=10,
                 rep_signal_scale=0.40, rep_demotion_extra=0.90, aggressive=True),
            dict(max_sticky_epochs=4, soft_sticky_epochs=1, stickiness_decay=0.60,
                 demotion_decay=0.38, demotion_floor=0.04, demotion_linger=12,
                 rep_signal_scale=0.50, rep_demotion_extra=0.85, aggressive=True),
            dict(max_sticky_epochs=5, soft_sticky_epochs=2, stickiness_decay=0.65,
                 demotion_decay=0.40, demotion_floor=0.05, demotion_linger=10,
                 rep_signal_scale=0.0, rep_demotion_extra=1.0, aggressive=True),
        ]
    v2 = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated", trials=trials, rng=rng,
    )
    v3_default = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_v3", trials=trials, rng=rng,
    )
    v4_default = adaptive_guard_exposure(
        c, g, epochs=epochs, mode="mitigated_v4", trials=trials, rng=rng,
    )
    points = []
    for i, knobs in enumerate(grid):
        p = adaptive_guard_exposure(
            c, g, epochs=epochs, mode="mitigated_v3", trials=trials, rng=rng,
            **knobs,
        )
        points.append({
            "id": i,
            "exposure": p,
            "improvement_vs_v2": v2 - p,
            "knobs": knobs,
        })
    points.sort(key=lambda x: x["exposure"])
    return {
        "tag": "adaptive_mitigation_param_sweep",
        "characterizes_not_closes": True,
        "c": c,
        "g": g,
        "epochs": epochs,
        "trials": trials,
        "v2_baseline": v2,
        "v3_default": v3_default,
        "v4_default": v4_default,
        "v4_improvement_vs_v3": v3_default - v4_default,
        "points": points,
        "best_point_id": points[0]["id"] if points else None,
        "locked_v3_params": _MITIGATION_V3,
        "locked_v4_params": _MITIGATION_V4,
    }


def adaptive_mitigation_offline_characterization(
    c=0.015, g=3,
    epoch_grid=(50, 100, 200, 500, 800, 2000),
    trials_ci=2000,
    trials_offline=8000,
    rng=None,
):
    """Longer offline curve compare (cap runtime ~5–10 min depending on host).

    Writes-ready dict: CI-scale vs offline-scale v2/v3 exposures. Saturation at
    long horizons is expected and documented — §13 remains open.
    """
    rng = rng or np.random.default_rng(7777)
    def _curve(trials):
        out = {"trials": trials, "by_epochs": {}}
        for e in epoch_grid:
            out["by_epochs"][str(e)] = {
                "adaptive": adaptive_guard_exposure(
                    c, g, epochs=e, mode="adaptive", trials=trials, rng=rng,
                ),
                "mitigated_v2": adaptive_guard_exposure(
                    c, g, epochs=e, mode="mitigated", trials=trials, rng=rng,
                ),
                "mitigated_v3": adaptive_guard_exposure(
                    c, g, epochs=e, mode="mitigated_v3", trials=trials, rng=rng,
                ),
                "mitigated_v4": adaptive_guard_exposure(
                    c, g, epochs=e, mode="mitigated_v4", trials=trials, rng=rng,
                ),
            }
        return out

    ci = _curve(trials_ci)
    offline = _curve(trials_offline)
    e200 = offline["by_epochs"].get("200", {})
    e2000 = offline["by_epochs"].get("2000", {})
    return {
        "tag": "adaptive_mitigation_offline_characterization",
        "characterizes_not_closes": True,
        "mitigation_partial_not_closed": True,
        "c": c,
        "g": g,
        "epoch_grid": list(epoch_grid),
        "ci_scale": ci,
        "offline_scale": offline,
        "summary_at_200": {
            "adaptive": e200.get("adaptive"),
            "mitigated_v2": e200.get("mitigated_v2"),
            "mitigated_v3": e200.get("mitigated_v3"),
            "mitigated_v4": e200.get("mitigated_v4"),
            "v3_improvement_vs_v2": (
                None if e200.get("mitigated_v2") is None
                else e200["mitigated_v2"] - e200["mitigated_v3"]
            ),
            "v4_improvement_vs_v3": (
                None if e200.get("mitigated_v3") is None
                else e200["mitigated_v3"] - e200["mitigated_v4"]
            ),
        },
        "summary_at_2000": {
            "adaptive": e2000.get("adaptive"),
            "mitigated_v3": e2000.get("mitigated_v3"),
            "mitigated_v4": e2000.get("mitigated_v4"),
            "v4_improvement_vs_v3": (
                None if e2000.get("mitigated_v3") is None
                else e2000["mitigated_v3"] - e2000["mitigated_v4"]
            ),
        },
        "mitigation_params_v2": _MITIGATION_V2,
        "mitigation_params_v3": _MITIGATION_V3,
        "mitigation_params_v4": _MITIGATION_V4,
        "honest_limit": (
            "v4 lowers E=2000 exposure vs v3 but long horizons still "
            "saturate toward 1.0; spec §13 remains [O]."
        ),
    }


# Combined active+intersection APIs: see combined_active_intersection.py
# (re-exported at module top). Tag [O] QUANTIFIED — not closed.


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
