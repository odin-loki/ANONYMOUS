"""
Exit-tier anonymity-set / intersection characterization (spec §8 / coverage C2).

Tag: [O] QUANTIFIED — multi-client exit window model; does not close exit-tier
residuals and is not a WAN closed claim.

Model (honest, synthetic):
  - N clients share one exit relay over epochs.
  - Each epoch a subset of clients are "active" toward a clearnet destination.
  - GPA at exit↔clearnet sees unshaped clearnet residual volumes (no receiver
    hard-cap). Sender anonymity is only the co-active exit window set.
  - Long-horizon intersection shrinks candidate client sets across epochs.

Internal Mode-1 hard-cap resistance does NOT transfer here
(see combined_active_intersection.sim_to_product.exit_tier_exclusion_residual).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

DEFAULT_EPOCH_GRID = (20, 50, 100, 200, 400, 800)
OFFLINE_EPOCH_GRID = (1600, 3200)
DEFAULT_N_CLIENTS = 40
DEFAULT_WINDOW = 1  # epochs aggregated into one observation window
DEFAULT_P_ACTIVE = 0.25
DEFAULT_BG_RATE = 2.0
DEFAULT_SIGNAL_RATE = 6.0
# Fraction of target-active windows the adversary can tip-select for ∩
# (sparse external activity knowledge — full-window ∩ collapses immediately).
DEFAULT_TIP_RATE = 0.08


def simulate_exit_window_epochs(
    n_clients=DEFAULT_N_CLIENTS,
    E=400,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    target_client=None,
    rng=None,
):
    """Simulate per-epoch exit volumes and co-active anonymity sets.

    Returns dict with:
      active          - (E, N) bool, client active toward the watched destination
      volume          - (E, N) clearnet residual volume (Poisson; unshaped)
      anonymity_sets  - list[set] per window of clients with volume>0
      target          - true originator client id
    """
    rng = rng or np.random.default_rng(0)
    target = int(rng.integers(n_clients) if target_client is None else target_client)
    active = rng.random((E, n_clients)) < p_active
    # Target is forced active often enough to be a real flow, not always-on
    # (always-on would trivially shrink sets via presence alone).
    force = rng.random(E) < 0.55
    active[:, target] |= force
    volume = rng.poisson(bg_rate, size=(E, n_clients)).astype(float)
    volume[~active] = 0.0
    # Target carries an extra clearnet residual burst when active (no hard-cap).
    volume[active[:, target], target] += rng.poisson(
        signal_rate, size=int(active[:, target].sum())
    ).astype(float)

    sets = []
    for start in range(0, E, max(1, int(window))):
        sl = slice(start, min(E, start + max(1, int(window))))
        present = np.where(volume[sl].sum(axis=0) > 0)[0]
        sets.append(set(int(i) for i in present))
    return {
        "active": active,
        "volume": volume,
        "anonymity_sets": sets,
        "target": target,
        "n_clients": n_clients,
        "E": E,
        "window": int(window),
    }


def anonymity_set_sizes(sim):
    """Per-window anonymity-set sizes (0 if empty window)."""
    return np.array([len(s) for s in sim["anonymity_sets"]], dtype=float)


def intersection_candidate_curve(sim, epoch_grid=None, tip_rate=DEFAULT_TIP_RATE,
                                 tip_mask=None, rng=None):
    """Shrinkage of ∩ anonymity sets containing the true target over horizons.

    Only a sparse tip-selected subset of target-present windows is intersected
    (tip_rate), modeling partial external activity knowledge. Intersecting
    every co-active window collapses to a singleton almost immediately and is
    reported separately as `naive_full_intersection_size` at the longest E.
    """
    rng = rng or np.random.default_rng(0)
    sets = sim["anonymity_sets"]
    target = sim["target"]
    window = max(1, int(sim["window"]))
    Emax = int(sim["E"])
    if epoch_grid is None:
        epoch_grid = tuple(
            e for e in DEFAULT_EPOCH_GRID if e <= Emax
        ) or (Emax,)
    if tip_mask is None:
        tip_mask = np.zeros(len(sets), dtype=bool)
        for i, s in enumerate(sets):
            if target in s and rng.random() < float(tip_rate):
                tip_mask[i] = True
    out = {}
    for E in epoch_grid:
        k = max(1, int(np.ceil(E / window)))
        k = min(k, len(sets))
        cand = None
        tips_used = 0
        for i, s in enumerate(sets[:k]):
            if not tip_mask[i] or target not in s:
                continue
            tips_used += 1
            cand = set(s) if cand is None else (cand & s)
        size = 0 if cand is None else len(cand)
        out[int(E)] = {
            "intersection_size": size,
            "singleton": size == 1,
            "contains_target": bool(cand is not None and target in cand),
            "windows_used": k,
            "tips_used": tips_used,
        }
    # Naive full ∩ at Emax (honest: collapses fast without hard-cap).
    naive = None
    for s in sets:
        if target not in s:
            continue
        naive = set(s) if naive is None else (naive & s)
    out["_naive_full_intersection_size"] = 0 if naive is None else len(naive)
    return out


def volume_ranking_hit(sim, E=None):
    """P-style single-trial: does cumulative clearnet volume rank target #1?"""
    vol = sim["volume"]
    if E is not None:
        vol = vol[: int(E)]
    cum = vol.sum(axis=0)
    return bool(np.argmax(cum) == sim["target"])


def exit_tier_intersection(
    n_clients=DEFAULT_N_CLIENTS,
    E=400,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    trials=200,
    rng=None,
):
    """Monte Carlo exit-tier metrics at a single horizon E.

    Returns:
      mean_anonymity_set       — average co-active set size over windows
      p_intersection_singleton — P(tip-sparse ∩ candidate set is {target})
      p_volume_rank_top        — P(cumulative volume ranks target #1)
      mean_intersection_size   — E[|∩ candidates|]
      baseline_uniform         — 1/n_clients
    """
    rng = rng or np.random.default_rng(0)
    sizes = []
    inter_sizes = []
    singletons = 0
    vol_hits = 0
    naive_sizes = []
    for t in range(trials):
        trial_rng = np.random.default_rng(int(rng.integers(1 << 31)))
        sim = simulate_exit_window_epochs(
            n_clients=n_clients, E=E, p_active=p_active, bg_rate=bg_rate,
            signal_rate=signal_rate, window=window, rng=trial_rng,
        )
        asizes = anonymity_set_sizes(sim)
        sizes.append(float(asizes.mean()) if asizes.size else 0.0)
        curve = intersection_candidate_curve(
            sim, epoch_grid=(E,), tip_rate=tip_rate, rng=trial_rng,
        )
        row = curve[int(E)]
        isize = row["intersection_size"] if row["tips_used"] > 0 else n_clients
        inter_sizes.append(isize)
        singletons += int(row["singleton"] and row["tips_used"] > 0)
        vol_hits += int(volume_ranking_hit(sim, E=E))
        naive_sizes.append(curve["_naive_full_intersection_size"])
    return {
        "n_clients": n_clients,
        "E": E,
        "p_active": p_active,
        "bg_rate": bg_rate,
        "signal_rate": signal_rate,
        "window": window,
        "tip_rate": tip_rate,
        "trials": trials,
        "baseline_uniform": 1.0 / n_clients,
        "mean_anonymity_set": float(np.mean(sizes)),
        "mean_intersection_size": float(np.mean(inter_sizes)),
        "p_intersection_singleton": singletons / trials,
        "p_volume_rank_top": vol_hits / trials,
        "mean_naive_full_intersection_size": float(np.mean(naive_sizes)),
    }


def exit_tier_intersection_curve(
    n_clients=DEFAULT_N_CLIENTS,
    epoch_grid=DEFAULT_EPOCH_GRID,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    trials=200,
    rng=None,
):
    """Long-horizon curves for anonymity-set / intersection / volume ranking."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    Emax = max(epoch_grid)
    acc = {
        E: {
            "anonymity_sum": 0.0,
            "inter_sum": 0.0,
            "singleton": 0,
            "vol_hit": 0,
            "naive_sum": 0.0,
        }
        for E in epoch_grid
    }
    for _ in range(trials):
        trial_rng = np.random.default_rng(int(rng.integers(1 << 31)))
        sim = simulate_exit_window_epochs(
            n_clients=n_clients, E=Emax, p_active=p_active, bg_rate=bg_rate,
            signal_rate=signal_rate, window=window, rng=trial_rng,
        )
        asizes = anonymity_set_sizes(sim)
        curve = intersection_candidate_curve(
            sim, epoch_grid=epoch_grid, tip_rate=tip_rate, rng=trial_rng,
        )
        naive = curve.pop("_naive_full_intersection_size")
        for E in epoch_grid:
            k = max(1, int(np.ceil(E / max(1, window))))
            k = min(k, len(asizes))
            acc[E]["anonymity_sum"] += float(asizes[:k].mean()) if k else 0.0
            row = curve[E]
            # Empty tip set → treat as full anonymity pool (no disclosure yet).
            isize = row["intersection_size"] if row["tips_used"] > 0 else n_clients
            acc[E]["inter_sum"] += isize
            acc[E]["singleton"] += int(row["singleton"] and row["tips_used"] > 0)
            acc[E]["vol_hit"] += int(volume_ranking_hit(sim, E=E))
            acc[E]["naive_sum"] += naive
    out = {}
    for E in epoch_grid:
        out[E] = {
            "mean_anonymity_set": acc[E]["anonymity_sum"] / trials,
            "mean_intersection_size": acc[E]["inter_sum"] / trials,
            "p_intersection_singleton": acc[E]["singleton"] / trials,
            "p_volume_rank_top": acc[E]["vol_hit"] / trials,
            "mean_naive_full_intersection_size": acc[E]["naive_sum"] / trials,
        }
    return out


def sensitivity_to_coactivity(
    p_active_grid=(0.1, 0.25, 0.5, 0.8),
    n_clients=DEFAULT_N_CLIENTS,
    E=400,
    trials=80,
    rng=None,
    **kwargs,
):
    """How co-activity rate changes anonymity set and singleton risk."""
    rng = rng or np.random.default_rng(0)
    results = {}
    for p in p_active_grid:
        m = exit_tier_intersection(
            n_clients=n_clients, E=E, p_active=p, trials=trials, rng=rng, **kwargs,
        )
        results[str(p)] = {
            "mean_anonymity_set": round(m["mean_anonymity_set"], 4),
            "mean_intersection_size": round(m["mean_intersection_size"], 4),
            "p_intersection_singleton": round(m["p_intersection_singleton"], 4),
            "p_volume_rank_top": round(m["p_volume_rank_top"], 4),
        }
    return {
        "E": E,
        "n_clients": n_clients,
        "trials": trials,
        "p_active_grid": list(p_active_grid),
        "results": results,
        "note": (
            "Higher co-activity enlarges per-window anonymity sets but can "
            "still leave volume ranking / long-horizon intersection above "
            "uniform baseline when clearnet residual is unshaped."
        ),
    }


def sensitivity_to_client_pool(
    n_grid=(10, 20, 40, 80),
    E=400,
    p_active=DEFAULT_P_ACTIVE,
    trials=80,
    rng=None,
    **kwargs,
):
    """Pool size vs exit anonymity / intersection metrics."""
    rng = rng or np.random.default_rng(0)
    results = {}
    for n in n_grid:
        m = exit_tier_intersection(
            n_clients=n, E=E, p_active=p_active, trials=trials, rng=rng, **kwargs,
        )
        results[str(n)] = {
            "baseline_uniform": round(m["baseline_uniform"], 6),
            "mean_anonymity_set": round(m["mean_anonymity_set"], 4),
            "mean_intersection_size": round(m["mean_intersection_size"], 4),
            "p_intersection_singleton": round(m["p_intersection_singleton"], 4),
            "p_volume_rank_top": round(m["p_volume_rank_top"], 4),
        }
    return {
        "E": E,
        "p_active": p_active,
        "trials": trials,
        "n_grid": list(n_grid),
        "results": results,
        "note": (
            "Larger exit client pools grow mean anonymity sets; volume ranking "
            "on unshaped clearnet residual can still beat 1/N over long E."
        ),
    }


def exit_tier_report(
    n_clients=DEFAULT_N_CLIENTS,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    epoch_grid=DEFAULT_EPOCH_GRID,
    trials=200,
    rng=None,
    include_sensitivity=True,
    include_offline=True,
    sensitivity_trials=80,
    offline_epoch_grid=OFFLINE_EPOCH_GRID,
    offline_trials=100,
):
    """Full exit-tier characterization report (CI-safe with flags off)."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    curve = exit_tier_intersection_curve(
        n_clients=n_clients, epoch_grid=epoch_grid, p_active=p_active,
        bg_rate=bg_rate, signal_rate=signal_rate, window=window,
        tip_rate=tip_rate, trials=trials, rng=rng,
    )
    curves = {
        str(E): {
            "mean_anonymity_set": round(v["mean_anonymity_set"], 4),
            "mean_intersection_size": round(v["mean_intersection_size"], 4),
            "p_intersection_singleton": round(v["p_intersection_singleton"], 4),
            "p_volume_rank_top": round(v["p_volume_rank_top"], 4),
            "mean_naive_full_intersection_size": round(
                v["mean_naive_full_intersection_size"], 4
            ),
        }
        for E, v in curve.items()
    }
    long_e = str(max(epoch_grid))
    report = {
        "tag": "coverage_C2_exit_tier_intersection",
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "wan_closed": False,
        "n_clients": n_clients,
        "p_active": p_active,
        "bg_rate": bg_rate,
        "signal_rate": signal_rate,
        "window": window,
        "tip_rate": tip_rate,
        "trials": trials,
        "epoch_grid": list(epoch_grid),
        "baseline_uniform": 1.0 / n_clients,
        "curves": curves,
        "summary_at_long_horizon": {
            "E": int(long_e),
            **curves[long_e],
        },
        "honest_limits": [
            "Synthetic Poisson clearnet residual — not WAN / operational C2.",
            "No multi-hop mix delay, Sphinx crypto, or real exit operator traces.",
            "Receiver hard-cap cannot apply on clearnet; residual is by design.",
            "Sender anonymity = co-active exit window set, not Mode-1 receiver guarantees.",
            "Tip-sparse ∩ uses partial activity knowledge; naive full-window ∩ collapses faster.",
        ],
        "positioning": (
            "Exit is a weaker tier: multi-client exit windows provide a sender "
            "anonymity set; long-horizon volume ranking and tip-sparse "
            "intersection on unshaped clearnet residual beat uniform baseline."
        ),
    }
    if include_sensitivity:
        report["sensitivity"] = {
            "coactivity_p_active": sensitivity_to_coactivity(
                n_clients=n_clients, E=max(epoch_grid), trials=sensitivity_trials,
                bg_rate=bg_rate, signal_rate=signal_rate, window=window,
                tip_rate=tip_rate, rng=rng,
            ),
            "client_pool_N": sensitivity_to_client_pool(
                E=max(epoch_grid), p_active=p_active, trials=sensitivity_trials,
                bg_rate=bg_rate, signal_rate=signal_rate, window=window,
                tip_rate=tip_rate, rng=rng,
            ),
        }
    if include_offline:
        off = exit_tier_intersection_curve(
            n_clients=n_clients, epoch_grid=tuple(offline_epoch_grid),
            p_active=p_active, bg_rate=bg_rate, signal_rate=signal_rate,
            window=window, tip_rate=tip_rate, trials=offline_trials, rng=rng,
        )
        report["offline_long_horizon"] = {
            "characterizes_not_closes": True,
            "wan_closed": False,
            "epoch_grid": list(offline_epoch_grid),
            "trials": offline_trials,
            "curves": {
                str(E): {
                    "mean_anonymity_set": round(v["mean_anonymity_set"], 4),
                    "mean_intersection_size": round(v["mean_intersection_size"], 4),
                    "p_intersection_singleton": round(v["p_intersection_singleton"], 4),
                    "p_volume_rank_top": round(v["p_volume_rank_top"], 4),
                    "mean_naive_full_intersection_size": round(
                        v["mean_naive_full_intersection_size"], 4
                    ),
                }
                for E, v in off.items()
            },
            "note": (
                "Offline-only extension. Tip-sparse ∩ / volume ranking rise with "
                "E on unshaped clearnet residual; naive full ∩ stays collapsed. "
                "Not a WAN close."
            ),
        }
    return report


def write_exit_tier_artifact(path, report=None, **kwargs):
    """Write JSON artifact; returns the report dict."""
    report = report if report is not None else exit_tier_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
