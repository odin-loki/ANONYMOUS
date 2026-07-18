"""
Exit-tier anonymity defenses (research wave S4 / coverage C2 extension).

Tag: [O] QUANTIFIED — ranks synthetic defenses against tip-sparse ∩ and volume
ranking; does **not** close exit-tier residuals or claim WAN C2.

Imports public APIs from `exit_tier_intersection` (does not rewrite that core).
Clearnet receivers cannot apply Mode-1 `HardCapPadder`; defenses here are
exit-window / sender-side pad *models* of what an exit relay or client pool
could emit before the clearnet handoff.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import exit_tier_intersection as eti

# Evaluation order (not rank).
CI_SCHEMES = (
    "baseline",
    "volume_equalize",
    "exit_window_pad_up",
    "exit_window_hard_cap",
    "presence_pad",
    "matched_decoy",
    "pool_hard_cap",
)

# Rank / recommend at this horizon (C2 tip-∩ still differentiating).
# Long-horizon E in epoch_grid is reported as residual, not the sole rank key.
DEFAULT_DECISION_HORIZON = 100

DEFAULT_EPOCH_GRID = eti.DEFAULT_EPOCH_GRID
OFFLINE_EPOCH_GRID = eti.OFFLINE_EPOCH_GRID
DEFAULT_N_CLIENTS = eti.DEFAULT_N_CLIENTS
DEFAULT_P_ACTIVE = eti.DEFAULT_P_ACTIVE
DEFAULT_BG_RATE = eti.DEFAULT_BG_RATE
DEFAULT_SIGNAL_RATE = eti.DEFAULT_SIGNAL_RATE
DEFAULT_WINDOW = eti.DEFAULT_WINDOW
DEFAULT_TIP_RATE = eti.DEFAULT_TIP_RATE
DEFAULT_PAD_Q = 10.0
DEFAULT_PRESENCE_RATE = 0.55
DEFAULT_MATCHED_DECOYS = 4

# Composite score weights (lower is better after ranking transform).
W_SINGLETON = 0.55
W_VOL_RANK = 0.45


def _rebuild_anonymity_sets(volume, window):
    """Rebuild co-active sets from a (possibly defended) volume matrix."""
    E, _N = volume.shape
    w = max(1, int(window))
    sets = []
    for start in range(0, E, w):
        sl = slice(start, min(E, start + w))
        present = np.where(volume[sl].sum(axis=0) > 0)[0]
        sets.append(set(int(i) for i in present))
    return sets


def apply_exit_defense(sim, scheme, *, pad_q=DEFAULT_PAD_Q,
                       presence_rate=DEFAULT_PRESENCE_RATE,
                       matched_decoys=DEFAULT_MATCHED_DECOYS, rng=None):
    """Transform a raw exit-window sim under a named defense scheme.

    Returns a new sim dict compatible with `intersection_candidate_curve` /
    `volume_ranking_hit`.
    """
    rng = rng or np.random.default_rng(0)
    if scheme not in CI_SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}; expected one of {CI_SCHEMES}")

    active = sim["active"].copy()
    volume = sim["volume"].copy()
    target = sim["target"]
    n_clients = sim["n_clients"]
    window = sim["window"]
    E = sim["E"]
    q = float(pad_q)

    if scheme == "baseline":
        pass
    elif scheme == "volume_equalize":
        # Kill per-client volume ranking among co-active clients each epoch.
        for e in range(E):
            present = volume[e] > 0
            k = int(present.sum())
            if k <= 0:
                continue
            mean_v = float(volume[e, present].mean())
            volume[e, present] = mean_v
    elif scheme == "exit_window_pad_up":
        # Pad active clients up to Q (inactive stay silent).
        for e in range(E):
            present = volume[e] > 0
            volume[e, present] = np.maximum(volume[e, present], q)
    elif scheme == "exit_window_hard_cap":
        # Flat Q whenever a client is active toward the watched destination.
        # Models exit-relay egress shaping — not clearnet receiver hard-cap.
        for e in range(E):
            present = active[e] | (volume[e] > 0)
            volume[e, present] = q
            volume[e, ~present] = 0.0
    elif scheme == "presence_pad":
        # Enlarge co-active sets: activate idle clients at flat Q (matched level).
        for e in range(E):
            idle = volume[e] <= 0
            inject = idle & (rng.random(n_clients) < float(presence_rate))
            volume[e, inject] = q
            active[e, inject] = True
            # Also flatten real actives to Q so decoys are volume-indistinguishable.
            present = volume[e] > 0
            volume[e, present] = q
    elif scheme == "matched_decoy":
        # When target is active, force K other clients to emit matching volume.
        k = max(0, int(matched_decoys))
        for e in range(E):
            if volume[e, target] <= 0:
                continue
            others = [i for i in range(n_clients) if i != target]
            rng.shuffle(others)
            pick = others[:k]
            tgt_v = float(volume[e, target])
            for i in pick:
                volume[e, i] = max(volume[e, i], tgt_v)
                active[e, i] = True
    elif scheme == "pool_hard_cap":
        # Strongest egress model: every client emits exactly Q every epoch.
        # Kills volume ranking and tip-sparse presence ∩ (set size = N).
        volume[:, :] = q
        active[:, :] = True

    return {
        "active": active,
        "volume": volume,
        "anonymity_sets": _rebuild_anonymity_sets(volume, window),
        "target": target,
        "n_clients": n_clients,
        "E": E,
        "window": int(window),
        "defense": scheme,
    }


def evaluate_exit_defense(
    scheme,
    *,
    n_clients=DEFAULT_N_CLIENTS,
    E=400,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    pad_q=DEFAULT_PAD_Q,
    presence_rate=DEFAULT_PRESENCE_RATE,
    matched_decoys=DEFAULT_MATCHED_DECOYS,
    trials=120,
    rng=None,
):
    """Monte Carlo tip-sparse ∩ / volume-rank metrics under one defense."""
    rng = rng or np.random.default_rng(0)
    sizes = []
    inter_sizes = []
    singletons = 0
    vol_hits = 0
    for _ in range(trials):
        trial_rng = np.random.default_rng(int(rng.integers(1 << 31)))
        raw = eti.simulate_exit_window_epochs(
            n_clients=n_clients, E=E, p_active=p_active, bg_rate=bg_rate,
            signal_rate=signal_rate, window=window, rng=trial_rng,
        )
        sim = apply_exit_defense(
            raw, scheme, pad_q=pad_q, presence_rate=presence_rate,
            matched_decoys=matched_decoys, rng=trial_rng,
        )
        asizes = eti.anonymity_set_sizes(sim)
        sizes.append(float(asizes.mean()) if asizes.size else 0.0)
        curve = eti.intersection_candidate_curve(
            sim, epoch_grid=(E,), tip_rate=tip_rate, rng=trial_rng,
        )
        row = curve[int(E)]
        isize = row["intersection_size"] if row["tips_used"] > 0 else n_clients
        inter_sizes.append(isize)
        singletons += int(row["singleton"] and row["tips_used"] > 0)
        vol_hits += int(eti.volume_ranking_hit(sim, E=E))
    p_sing = singletons / trials
    p_vol = vol_hits / trials
    return {
        "scheme": scheme,
        "n_clients": n_clients,
        "E": E,
        "trials": trials,
        "baseline_uniform": 1.0 / n_clients,
        "mean_anonymity_set": float(np.mean(sizes)),
        "mean_intersection_size": float(np.mean(inter_sizes)),
        "p_intersection_singleton": p_sing,
        "p_volume_rank_top": p_vol,
        "composite_risk": float(W_SINGLETON * p_sing + W_VOL_RANK * p_vol),
    }


def exit_defense_curve(
    scheme,
    *,
    n_clients=DEFAULT_N_CLIENTS,
    epoch_grid=DEFAULT_EPOCH_GRID,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    pad_q=DEFAULT_PAD_Q,
    presence_rate=DEFAULT_PRESENCE_RATE,
    matched_decoys=DEFAULT_MATCHED_DECOYS,
    trials=120,
    rng=None,
):
    """Long-horizon curves for one defense scheme."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    Emax = max(epoch_grid)
    acc = {
        E: {"aset": 0.0, "inter": 0.0, "sing": 0, "vol": 0}
        for E in epoch_grid
    }
    for _ in range(trials):
        trial_rng = np.random.default_rng(int(rng.integers(1 << 31)))
        raw = eti.simulate_exit_window_epochs(
            n_clients=n_clients, E=Emax, p_active=p_active, bg_rate=bg_rate,
            signal_rate=signal_rate, window=window, rng=trial_rng,
        )
        sim = apply_exit_defense(
            raw, scheme, pad_q=pad_q, presence_rate=presence_rate,
            matched_decoys=matched_decoys, rng=trial_rng,
        )
        asizes = eti.anonymity_set_sizes(sim)
        curve = eti.intersection_candidate_curve(
            sim, epoch_grid=epoch_grid, tip_rate=tip_rate, rng=trial_rng,
        )
        for E in epoch_grid:
            k = max(1, int(np.ceil(E / max(1, window))))
            k = min(k, len(asizes))
            acc[E]["aset"] += float(asizes[:k].mean()) if k else 0.0
            row = curve[E]
            isize = row["intersection_size"] if row["tips_used"] > 0 else n_clients
            acc[E]["inter"] += isize
            acc[E]["sing"] += int(row["singleton"] and row["tips_used"] > 0)
            acc[E]["vol"] += int(eti.volume_ranking_hit(sim, E=E))
    out = {}
    for E in epoch_grid:
        p_sing = acc[E]["sing"] / trials
        p_vol = acc[E]["vol"] / trials
        out[E] = {
            "mean_anonymity_set": acc[E]["aset"] / trials,
            "mean_intersection_size": acc[E]["inter"] / trials,
            "p_intersection_singleton": p_sing,
            "p_volume_rank_top": p_vol,
            "composite_risk": float(W_SINGLETON * p_sing + W_VOL_RANK * p_vol),
        }
    return out


def _rank_schemes(metrics_by_scheme, baseline_uniform):
    ranking = []
    for sch, m in metrics_by_scheme.items():
        ranking.append({
            "scheme": sch,
            "p_intersection_singleton": round(m["p_intersection_singleton"], 4),
            "p_volume_rank_top": round(m["p_volume_rank_top"], 4),
            "mean_intersection_size": round(m["mean_intersection_size"], 4),
            "mean_anonymity_set": round(m["mean_anonymity_set"], 4),
            "composite_risk": round(m["composite_risk"], 4),
            "beats_baseline": m["composite_risk"]
            < metrics_by_scheme["baseline"]["composite_risk"] - 0.02,
            "volume_near_uniform": m["p_volume_rank_top"]
            <= baseline_uniform + 0.08,
        })
    ranking.sort(key=lambda r: (
        r["composite_risk"],
        r["p_intersection_singleton"],
        r["p_volume_rank_top"],
        r["scheme"],
    ))
    return ranking


def _recommend(ranking, decision_horizon):
    """Prefer schemes that cut tip-∩ and/or volume ranking at the decision horizon."""
    by = {r["scheme"]: r for r in ranking}
    # Prefer deployable-cost order; pool_hard_cap is strongest but most expensive.
    prefer = (
        "presence_pad",
        "matched_decoy",
        "pool_hard_cap",
        "exit_window_hard_cap",
        "exit_window_pad_up",
        "volume_equalize",
    )
    beaters = [r for r in ranking if r["beats_baseline"] and r["scheme"] != "baseline"]
    if not beaters:
        return {
            "scheme": "baseline",
            "decision_horizon": decision_horizon,
            "note": "No evaluated defense beat baseline composite risk in this run.",
        }
    strongest = ranking[0]["scheme"] if ranking else "baseline"
    for name in prefer:
        if name in by and by[name]["beats_baseline"]:
            return {
                "scheme": name,
                "decision_horizon": decision_horizon,
                "composite_risk": by[name]["composite_risk"],
                "p_intersection_singleton": by[name]["p_intersection_singleton"],
                "p_volume_rank_top": by[name]["p_volume_rank_top"],
                "strongest_composite_scheme": strongest,
                "note": (
                    f"Recommend `{name}` in-sim at E={decision_horizon}: preference-"
                    "ordered practical scheme that reduces tip-sparse ∩ / volume "
                    f"ranking vs baseline (strongest composite: `{strongest}`). "
                    "Not a clearnet receiver hard-cap; long-horizon residual may "
                    "still rise (see metrics_at_long_horizon)."
                ),
            }
    best = beaters[0]
    return {
        "scheme": best["scheme"],
        "decision_horizon": decision_horizon,
        "composite_risk": best["composite_risk"],
        "p_intersection_singleton": best["p_intersection_singleton"],
        "p_volume_rank_top": best["p_volume_rank_top"],
        "note": "Best composite-risk beater at decision horizon (see defense_ranking).",
    }


def exit_tier_defense_report(
    n_clients=DEFAULT_N_CLIENTS,
    p_active=DEFAULT_P_ACTIVE,
    bg_rate=DEFAULT_BG_RATE,
    signal_rate=DEFAULT_SIGNAL_RATE,
    window=DEFAULT_WINDOW,
    tip_rate=DEFAULT_TIP_RATE,
    pad_q=DEFAULT_PAD_Q,
    presence_rate=DEFAULT_PRESENCE_RATE,
    matched_decoys=DEFAULT_MATCHED_DECOYS,
    epoch_grid=DEFAULT_EPOCH_GRID,
    decision_horizon=DEFAULT_DECISION_HORIZON,
    trials=120,
    schemes=CI_SCHEMES,
    rng=None,
    include_curves=True,
    include_offline=False,
    offline_epoch_grid=OFFLINE_EPOCH_GRID,
    offline_trials=80,
):
    """Rank exit-tier defenses; CI-safe with short grids / modest trials."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    schemes = tuple(schemes)
    long_e = max(epoch_grid)
    decision_e = int(decision_horizon)
    if decision_e not in epoch_grid:
        # Snap to nearest grid point ≤ decision horizon, else min grid.
        candidates = [e for e in epoch_grid if e <= decision_e]
        decision_e = max(candidates) if candidates else min(epoch_grid)
    metrics_decision = {}
    metrics_long = {}
    curves = {}
    for sch in schemes:
        if include_curves:
            curve = exit_defense_curve(
                sch, n_clients=n_clients, epoch_grid=epoch_grid,
                p_active=p_active, bg_rate=bg_rate, signal_rate=signal_rate,
                window=window, tip_rate=tip_rate, pad_q=pad_q,
                presence_rate=presence_rate, matched_decoys=matched_decoys,
                trials=trials, rng=rng,
            )
            curves[sch] = {
                str(E): {
                    "mean_anonymity_set": round(v["mean_anonymity_set"], 4),
                    "mean_intersection_size": round(v["mean_intersection_size"], 4),
                    "p_intersection_singleton": round(v["p_intersection_singleton"], 4),
                    "p_volume_rank_top": round(v["p_volume_rank_top"], 4),
                    "composite_risk": round(v["composite_risk"], 4),
                }
                for E, v in curve.items()
            }
            metrics_decision[sch] = {
                **curve[decision_e],
                "scheme": sch,
                "baseline_uniform": 1.0 / n_clients,
            }
            metrics_long[sch] = {
                **curve[long_e],
                "scheme": sch,
                "baseline_uniform": 1.0 / n_clients,
            }
        else:
            metrics_decision[sch] = evaluate_exit_defense(
                sch, n_clients=n_clients, E=decision_e, p_active=p_active,
                bg_rate=bg_rate, signal_rate=signal_rate, window=window,
                tip_rate=tip_rate, pad_q=pad_q, presence_rate=presence_rate,
                matched_decoys=matched_decoys, trials=trials, rng=rng,
            )
            metrics_long[sch] = evaluate_exit_defense(
                sch, n_clients=n_clients, E=long_e, p_active=p_active,
                bg_rate=bg_rate, signal_rate=signal_rate, window=window,
                tip_rate=tip_rate, pad_q=pad_q, presence_rate=presence_rate,
                matched_decoys=matched_decoys, trials=trials, rng=rng,
            )
    ranking = _rank_schemes(metrics_decision, 1.0 / n_clients)
    recommended = _recommend(ranking, decision_e)

    def _compact(m):
        return {
            "mean_anonymity_set": round(m["mean_anonymity_set"], 4),
            "mean_intersection_size": round(m["mean_intersection_size"], 4),
            "p_intersection_singleton": round(m["p_intersection_singleton"], 4),
            "p_volume_rank_top": round(m["p_volume_rank_top"], 4),
            "composite_risk": round(m["composite_risk"], 4),
        }

    report = {
        "tag": "wave_S4_exit_tier_defense",
        "extends": "coverage_C2_exit_tier_intersection",
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "wan_closed": False,
        "n_clients": n_clients,
        "p_active": p_active,
        "bg_rate": bg_rate,
        "signal_rate": signal_rate,
        "window": window,
        "tip_rate": tip_rate,
        "pad_q": pad_q,
        "presence_rate": presence_rate,
        "matched_decoys": matched_decoys,
        "trials": trials,
        "epoch_grid": list(epoch_grid),
        "decision_horizon": decision_e,
        "baseline_uniform": 1.0 / n_clients,
        "schemes_evaluated": list(schemes),
        "metrics_at_decision_horizon": {
            sch: _compact(m) for sch, m in metrics_decision.items()
        },
        "metrics_at_long_horizon": {
            sch: _compact(m) for sch, m in metrics_long.items()
        },
        "defense_ranking": ranking,
        "recommended": recommended,
        "honest_residuals": [
            "Synthetic Poisson model — not WAN / operational exit C2.",
            "Clearnet destination cannot run HardCapPadder; exit_window_* / "
            "pool_hard_cap are egress-shaping models at the exit tier.",
            "presence_pad / matched_decoy / pool_hard_cap burn bandwidth; "
            "adversarial idle clients may refuse decoy participation.",
            "Ranking uses decision_horizon (mid E); long-horizon tip-∩ can "
            "re-collapse when pads are intermittent (see metrics_at_long_horizon).",
            "volume_equalize alone does not stop tip-sparse presence ∩.",
        ],
        "sim_to_product": {
            "baseline": "unshaped exit↔clearnet residual (today)",
            "exit_window_hard_cap": (
                "Optional exit-relay per-destination egress pad to flat Q among "
                "co-active clients — product hook not shipped; sim-only."
            ),
            "presence_pad": (
                "Product (wave A2): opt-in [exit].presence_pad on aegis-node exit "
                "sink — matched-Q active pad-up + idle decoy inject (default off; "
                "exit hops only). Clearnet residual / cost remain."
            ),
            "matched_decoy": (
                "Emit K matched-volume companions when a real flow is active — "
                "closest analogue to receiver-side cover without clearnet pad."
            ),
            "pool_hard_cap": (
                "Always-on flat-Q egress for the entire exit client pool — "
                "strongest sim defense; highest bandwidth cost."
            ),
            "mapping_doc": "docs/ops/exit_tier_defense.md",
        },
    }
    if include_curves:
        report["curves"] = curves
    if include_offline:
        off = {}
        for sch in schemes:
            curve = exit_defense_curve(
                sch, n_clients=n_clients, epoch_grid=tuple(offline_epoch_grid),
                p_active=p_active, bg_rate=bg_rate, signal_rate=signal_rate,
                window=window, tip_rate=tip_rate, pad_q=pad_q,
                presence_rate=presence_rate, matched_decoys=matched_decoys,
                trials=offline_trials, rng=rng,
            )
            off[sch] = {
                str(E): {
                    "p_intersection_singleton": round(v["p_intersection_singleton"], 4),
                    "p_volume_rank_top": round(v["p_volume_rank_top"], 4),
                    "composite_risk": round(v["composite_risk"], 4),
                    "mean_intersection_size": round(v["mean_intersection_size"], 4),
                }
                for E, v in curve.items()
            }
        report["offline_long_horizon"] = {
            "characterizes_not_closes": True,
            "wan_closed": False,
            "epoch_grid": list(offline_epoch_grid),
            "trials": offline_trials,
            "curves": off,
            "note": (
                "Offline-only. Defenses may delay tip-∩ collapse vs baseline but "
                "do not claim a WAN close."
            ),
        }
    return report


def write_exit_tier_defense_artifact(path, report=None, **kwargs):
    """Write JSON artifact; returns the report dict."""
    report = report if report is not None else exit_tier_defense_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
