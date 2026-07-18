"""
Joint adaptive-guard × gossip-eclipse adversary (leftovers wave B3).

Tag: [O] QUANTIFIED — couples adaptive compromised-mix redraw with gossip
eclipse / majority_k collusion over shared epochs. Does **not** close §13;
field recompromise / eclipse rates unmeasured; multi-org BFT still External.

Baselines (imported public APIs; cores not rewritten):
  - adaptive-only: adversaries.adaptive_guard_exposure (+ committed artifact)
  - gossip-only: gossip_eclipse.profile_cell / simulate_victim_epoch
  - optional defenses: fused_defense.mitigated_dirty_epochs (adaptive_v4) +
    gossip_eclipse_defense.simulate_defended_epoch (stacked)

Coupling (honest synthetic):
  Each epoch redraws per-guard compromise with probability c. Concurrently the
  victim runs one coordinated gossip-eclipse round on an N-neighbor peer table
  at adversary fraction f and majority_k. On dirty epochs (boosted coupling),
  compromised guards join the eclipse reporter set — effective f rises so
  adaptive exposure unlocks stronger pure-adv quorums. Clean epochs use baseline f.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import numpy as np

from aegis_sim.adversaries import (
    _mitigation_params_for_mode,
    adaptive_guard_exposure,
)
from aegis_sim import gossip_eclipse as ge
from aegis_sim import gossip_eclipse_defense as ged
from aegis_sim.fused_defense import mitigated_dirty_epochs

DEFAULT_C = 0.015
DEFAULT_G = 3
DEFAULT_N = 8
# f=0.125 → 1/8 adv; K=2 blocks solo eclipse until boosted dirty seats +1 reporter.
DEFAULT_F = 0.125
DEFAULT_K = 2
DEFAULT_EPOCH_GRID = (20, 50, 100, 200)
OFFLINE_EPOCH_GRID = (400, 800)

# CI-friendly Monte Carlo (pytest must stay fast).
CI_TRIALS = 80
CI_EPOCH_GRID = (20, 50, 100)
CI_DEFENSE_TRIALS = 60

# Offline / artifact defaults.
ARTIFACT_TRIALS = 200
ARTIFACT_EPOCH_GRID = DEFAULT_EPOCH_GRID


def _effective_f_on_dirty(
    f: float,
    n_neighbors: int,
    g: int,
    dirty_guards: int,
) -> float:
    """Raise peer-table adversary fraction when compromised guards join eclipse."""
    n = max(int(n_neighbors), 1)
    base_adv = ge.n_adversarial(n, f)
    # Compromised guards become additional eclipse reporters (clamped to N).
    boost = min(int(dirty_guards), n - base_adv)
    return (base_adv + boost) / n


def joint_trial(
    E: int,
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    n_neighbors: int = DEFAULT_N,
    f: float = DEFAULT_F,
    majority_k: int = DEFAULT_K,
    *,
    coupling: str = "boosted",
    adaptive_mode: str = "adaptive",
    gossip_defense: str = "baseline",
    epoch_grid: Optional[Sequence[int]] = None,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    attack_fail: float = ge.ATTACK_FAIL_RATE,
    local_samples_per_epoch: int = 0,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """One Monte Carlo trial: adaptive dirtiness + gossip eclipse over epochs.

    coupling:
      'independent' — gossip always uses baseline f (parallel surfaces)
      'boosted'     — dirty epochs raise effective f via compromised guards
    adaptive_mode: 'adaptive' | 'mitigated_v4' (sticky/demotion dirtiness)
    gossip_defense: 'baseline' | 'stacked' (raised_k + diverse_org + eclipse_detect)
    """
    rng = rng or np.random.default_rng(0)
    if coupling not in ("independent", "boosted"):
        raise ValueError("coupling must be 'independent' or 'boosted'")
    if adaptive_mode not in ("adaptive", "mitigated_v4"):
        raise ValueError("adaptive_mode must be 'adaptive' or 'mitigated_v4'")
    if gossip_defense not in ("baseline", "stacked"):
        raise ValueError("gossip_defense must be 'baseline' or 'stacked'")

    epoch_grid = tuple(int(x) for x in (epoch_grid if epoch_grid is not None else (E,)))
    Emax = max(int(E), max(epoch_grid))

    # Precompute mitigated dirtiness; adaptive mode redraws per epoch below.
    mitigated = None
    if adaptive_mode == "mitigated_v4":
        params = _mitigation_params_for_mode("mitigated_v4")
        mitigated = mitigated_dirty_epochs(Emax, c, g, params, rng)

    gcfg = ged.defense_config(gossip_defense)
    k_eff = int(gcfg["majority_k"])
    min_orgs = int(gcfg["min_orgs"])
    eclipse_detect = bool(gcfg["eclipse_detect"])
    # Baseline defense_config uses CI_BASELINE_K; honor caller majority_k for baseline.
    if gossip_defense == "baseline":
        k_eff = max(int(majority_k), 1)

    window_ok = 0
    window_fail = 0
    eclipse_epochs = 0
    ever_exposed = False
    dirty_hist = np.zeros(Emax, dtype=bool)
    exposed_at: Dict[int, bool] = {}
    gossip_fp_at: Dict[int, bool] = {}
    eclipse_any_at: Dict[int, bool] = {}
    mean_bias_at: Dict[int, Optional[float]] = {}
    biases: List[float] = []

    grid_set = set(epoch_grid)
    for e in range(Emax):
        if adaptive_mode == "adaptive":
            guard_bits = rng.random(g) < c
            is_dirty = bool(guard_bits.any())
            dirty_guards = int(guard_bits.sum())
        else:
            assert mitigated is not None
            is_dirty = bool(mitigated[e])
            # Conservative boost: all g seats count when sticky process marks dirty.
            dirty_guards = int(g) if is_dirty else 0

        dirty_hist[e] = is_dirty
        ever_exposed = ever_exposed or is_dirty

        if coupling == "boosted" and is_dirty:
            f_ep = _effective_f_on_dirty(f, n_neighbors, g, dirty_guards)
        else:
            f_ep = float(f)

        local_ok = local_fail = 0
        if local_samples_per_epoch > 0:
            for _ in range(int(local_samples_per_epoch)):
                if rng.random() < honest_fail:
                    local_fail += 1
                else:
                    local_ok += 1

        if gossip_defense == "baseline":
            ep = ge.simulate_victim_epoch(
                n_neighbors,
                f_ep,
                k_eff,
                honest_fail=honest_fail,
                attack_fail=attack_fail,
                local_ok=local_ok,
                local_fail=local_fail,
                eclipse_order=True,
                rng=rng,
            )
        else:
            ep = ged.simulate_defended_epoch(
                n_neighbors,
                f_ep,
                k_eff,
                min_orgs=min_orgs,
                n_orgs=4,
                eclipse_detect=eclipse_detect,
                honest_fail=honest_fail,
                attack_fail=attack_fail,
                local_ok=local_ok,
                local_fail=local_fail,
                eclipse_order=True,
                rng=rng,
            )

        window_ok += int(ep["window_ok"])
        window_fail += int(ep["window_fail"])
        if ep["eclipse_this_epoch"]:
            eclipse_epochs += 1
        if ep.get("median_bias") is not None:
            biases.append(float(ep["median_bias"]))

        t = e + 1
        if t in grid_set:
            win_rate = ge.failure_rate(window_ok, window_fail)
            exposed_at[t] = bool(np.any(dirty_hist[:t]))
            gossip_fp_at[t] = bool(
                win_rate is not None and win_rate >= ge.FALSE_PROBATION_THRESHOLD
            )
            eclipse_any_at[t] = eclipse_epochs > 0
            mean_bias_at[t] = float(np.mean(biases)) if biases else None

    return {
        "ever_exposed": ever_exposed,
        "exposed_at": exposed_at,
        "gossip_fp_at": gossip_fp_at,
        "eclipse_any_at": eclipse_any_at,
        "mean_bias_at": mean_bias_at,
        "eclipse_epoch_fraction": eclipse_epochs / max(Emax, 1),
        "coupling": coupling,
        "adaptive_mode": adaptive_mode,
        "gossip_defense": gossip_defense,
    }


def joint_long_horizon(
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    n_neighbors: int = DEFAULT_N,
    f: float = DEFAULT_F,
    majority_k: int = DEFAULT_K,
    *,
    coupling: str = "boosted",
    adaptive_mode: str = "adaptive",
    gossip_defense: str = "baseline",
    epoch_grid: Sequence[int] = DEFAULT_EPOCH_GRID,
    trials: int = CI_TRIALS,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    attack_fail: float = ge.ATTACK_FAIL_RATE,
    local_samples_per_epoch: int = 0,
    rng: Optional[np.random.Generator] = None,
) -> Dict[int, Dict[str, float]]:
    """Monte Carlo joint curves vs epoch checkpoints.

    Metrics per epoch E:
      p_adaptive_exposed — P(ever dirty within E)
      p_gossip_success   — P(eclipse_any OR false_probation)
      p_gossip_fp        — P(false probation on accumulated gossip window)
      p_eclipse_any      — P(≥1 pure-adv eclipse epoch within E)
      p_union_success    — P(exposed OR gossip_success)
      p_joint_success    — P(exposed AND gossip_success)
    """
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    hits_exp = {E: 0 for E in epoch_grid}
    hits_fp = {E: 0 for E in epoch_grid}
    hits_ecl = {E: 0 for E in epoch_grid}
    hits_goss = {E: 0 for E in epoch_grid}
    hits_union = {E: 0 for E in epoch_grid}
    hits_joint = {E: 0 for E in epoch_grid}
    bias_acc = {E: [] for E in epoch_grid}  # type: ignore[var-annotated]

    for _ in range(int(trials)):
        trial = joint_trial(
            E=max(epoch_grid),
            c=c,
            g=g,
            n_neighbors=n_neighbors,
            f=f,
            majority_k=majority_k,
            coupling=coupling,
            adaptive_mode=adaptive_mode,
            gossip_defense=gossip_defense,
            epoch_grid=epoch_grid,
            honest_fail=honest_fail,
            attack_fail=attack_fail,
            local_samples_per_epoch=local_samples_per_epoch,
            rng=np.random.default_rng(int(rng.integers(1 << 31))),
        )
        for E in epoch_grid:
            ex = trial["exposed_at"][E]
            fp = trial["gossip_fp_at"][E]
            ecl = trial["eclipse_any_at"][E]
            # Gossip attack success: pure-adv eclipse and/or false probation.
            goss = bool(ecl or fp)
            hits_exp[E] += int(ex)
            hits_fp[E] += int(fp)
            hits_ecl[E] += int(ecl)
            hits_goss[E] += int(goss)
            hits_union[E] += int(ex or goss)
            hits_joint[E] += int(ex and goss)
            if trial["mean_bias_at"][E] is not None:
                bias_acc[E].append(float(trial["mean_bias_at"][E]))

    curves: Dict[int, Dict[str, float]] = {}
    for E in epoch_grid:
        curves[E] = {
            "p_adaptive_exposed": hits_exp[E] / trials,
            "p_gossip_success": hits_goss[E] / trials,
            "p_gossip_fp": hits_fp[E] / trials,
            "p_eclipse_any": hits_ecl[E] / trials,
            "p_union_success": hits_union[E] / trials,
            "p_joint_success": hits_joint[E] / trials,
            "mean_median_bias": (
                float(np.mean(bias_acc[E])) if bias_acc[E] else 0.0
            ),
        }
    return curves


def baseline_adaptive_only(
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    epoch_grid: Sequence[int] = DEFAULT_EPOCH_GRID,
    trials: int = 400,
    mode: str = "adaptive",
    rng: Optional[np.random.Generator] = None,
) -> Dict[int, float]:
    """Public-API adaptive-only baseline (no gossip coupling)."""
    rng = rng or np.random.default_rng(0)
    out: Dict[int, float] = {}
    for E in epoch_grid:
        out[int(E)] = adaptive_guard_exposure(
            c, g, epochs=int(E), mode=mode, trials=trials, rng=rng,
        )
    return out


def baseline_gossip_only(
    n_neighbors: int = DEFAULT_N,
    f: float = DEFAULT_F,
    majority_k: int = DEFAULT_K,
    epoch_grid: Sequence[int] = DEFAULT_EPOCH_GRID,
    trials: int = 120,
    rng: Optional[np.random.Generator] = None,
) -> Dict[int, Dict[str, float]]:
    """Public-API gossip-only baseline via profile_cell at each horizon."""
    rng = rng or np.random.default_rng(0)
    out: Dict[int, Dict[str, float]] = {}
    for E in epoch_grid:
        cell = ge.profile_cell(
            n_neighbors,
            f,
            majority_k,
            trials=trials,
            epochs=int(E),
            eclipse_order=True,
            rng=np.random.default_rng(int(rng.integers(1 << 31))),
        )
        out[int(E)] = {
            "false_probation_rate": float(cell["false_probation_rate"]),
            "mean_eclipse_epoch_fraction": float(cell["mean_eclipse_epoch_fraction"]),
            "mean_median_bias": float(cell["mean_median_bias"] or 0.0),
        }
    return out


def load_committed_baselines(
    data_dir: Optional[Path] = None,
    adaptive_name: str = "adaptive_guard_exposure.analysis.json",
    gossip_name: str = "gossip_eclipse.analysis.json",
) -> Dict[str, Any]:
    """Reuse committed artifact numbers where present."""
    root = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent / "data"
    out: Dict[str, Any] = {
        "adaptive_artifact": None,
        "gossip_artifact": None,
        "notes": [],
    }
    ap = root / adaptive_name
    gp = root / gossip_name
    if ap.is_file():
        art = json.loads(ap.read_text(encoding="utf-8"))
        out["adaptive_artifact"] = {
            "path": ap.name,
            "c": art.get("c"),
            "g": art.get("g"),
            "adaptive_by_epochs": art.get("adaptive_by_epochs"),
            "mitigated_v4_by_epochs": art.get("mitigated_v4_by_epochs"),
            "characterizes_not_closes": art.get("characterizes_not_closes", True),
        }
    else:
        out["notes"].append(f"missing adaptive artifact: {ap}")
    if gp.is_file():
        art = json.loads(gp.read_text(encoding="utf-8"))
        # Representative C1 cells near the joint default (N=8, K=2).
        highlights = {}
        for target_f, key in ((0.125, "n8_f0125_k2"), (0.25, "n8_f025_k2")):
            for cell in art.get("cells", []):
                if (
                    cell.get("n_neighbors") == 8
                    and abs(float(cell.get("f", -1)) - target_f) < 1e-9
                    and cell.get("majority_k") == 2
                ):
                    highlights[key] = {
                        "n_neighbors": 8,
                        "f": target_f,
                        "majority_k": 2,
                        "false_probation_rate": cell.get("false_probation_rate"),
                        "mean_eclipse_epoch_fraction": cell.get(
                            "mean_eclipse_epoch_fraction"
                        ),
                        "mean_median_bias": cell.get("mean_median_bias"),
                    }
                    break
        out["gossip_artifact"] = {
            "path": gp.name,
            "status": art.get("status"),
            "claim_closed": art.get("claim_closed", False),
            "multi_org_bft": art.get("multi_org_bft", "External"),
            "highlights": highlights,
            "highlight_n8_f025_k2": highlights.get("n8_f025_k2"),
            "characterizes_not_closes": True,
        }
    else:
        out["notes"].append(f"missing gossip artifact: {gp}")
    return out


def joint_defense_curve(
    epoch_grid: Sequence[int] = DEFAULT_EPOCH_GRID,
    trials: int = CI_DEFENSE_TRIALS,
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    n_neighbors: int = DEFAULT_N,
    f: float = DEFAULT_F,
    majority_k: int = DEFAULT_K,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """Optional stacked gossip + adaptive_v4 joint defense vs undefended joint."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    undef = joint_long_horizon(
        c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
        coupling="boosted", adaptive_mode="adaptive", gossip_defense="baseline",
        epoch_grid=epoch_grid, trials=trials, rng=rng,
    )
    defended = joint_long_horizon(
        c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
        coupling="boosted", adaptive_mode="mitigated_v4", gossip_defense="stacked",
        epoch_grid=epoch_grid, trials=trials,
        local_samples_per_epoch=12,
        rng=rng,
    )
    deltas = {}
    for E in epoch_grid:
        deltas[str(E)] = {
            "delta_p_union": round(
                undef[E]["p_union_success"] - defended[E]["p_union_success"], 4
            ),
            "delta_p_joint": round(
                undef[E]["p_joint_success"] - defended[E]["p_joint_success"], 4
            ),
            "delta_p_adaptive": round(
                undef[E]["p_adaptive_exposed"] - defended[E]["p_adaptive_exposed"], 4
            ),
            "delta_p_gossip_success": round(
                undef[E]["p_gossip_success"] - defended[E]["p_gossip_success"], 4
            ),
            "delta_p_gossip_fp": round(
                undef[E]["p_gossip_fp"] - defended[E]["p_gossip_fp"], 4
            ),
        }
    return {
        "undefended_boosted": {
            str(E): {k: round(v, 4) for k, v in undef[E].items()} for E in epoch_grid
        },
        "joint_v4_stacked": {
            str(E): {k: round(v, 4) for k, v in defended[E].items()} for E in epoch_grid
        },
        "deltas_undefended_minus_defended": deltas,
        "note": (
            "joint_v4_stacked = adaptive mitigated_v4 dirtiness + stacked gossip "
            "defense (raised_k + min_orgs + eclipse_detect). Cuts joint/union at "
            "partial f; does not close §13; f→1 still saturates gossip FP."
        ),
    }


def joint_guard_gossip_report(
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    n_neighbors: int = DEFAULT_N,
    f: float = DEFAULT_F,
    majority_k: int = DEFAULT_K,
    epoch_grid: Sequence[int] = ARTIFACT_EPOCH_GRID,
    trials: int = ARTIFACT_TRIALS,
    coupling: str = "boosted",
    rng: Optional[np.random.Generator] = None,
    include_live_baselines: bool = True,
    include_committed_baselines: bool = True,
    include_joint_defense: bool = True,
    include_offline: bool = False,
    baseline_adaptive_trials: int = 400,
    baseline_gossip_trials: int = 100,
    defense_trials: int = CI_DEFENSE_TRIALS,
    offline_epoch_grid: Sequence[int] = OFFLINE_EPOCH_GRID,
    offline_trials: int = 80,
    data_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Compare joint coupling against adaptive-only and gossip-only baselines."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)

    joint = joint_long_horizon(
        c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
        coupling=coupling, adaptive_mode="adaptive", gossip_defense="baseline",
        epoch_grid=epoch_grid, trials=trials, rng=rng,
    )
    indep = joint_long_horizon(
        c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
        coupling="independent", adaptive_mode="adaptive", gossip_defense="baseline",
        epoch_grid=epoch_grid, trials=max(trials // 2, 40), rng=rng,
    )

    curves = {
        str(E): {k: round(v, 4) for k, v in joint[E].items()} for E in epoch_grid
    }
    report: Dict[str, Any] = {
        "tag": "leftovers_B3_joint_guard_gossip",
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "claim_closed": False,
        "section_13_closed": False,
        "wan_closed": False,
        "multi_org_bft": "External",
        "wave": "B3",
        "c": c,
        "g": g,
        "n_neighbors": n_neighbors,
        "f": f,
        "majority_k": majority_k,
        "coupling": coupling,
        "trials": trials,
        "epoch_grid": list(epoch_grid),
        "joint_curves": curves,
        "independent_coupling_curves": {
            str(E): {k: round(v, 4) for k, v in indep[E].items()} for E in epoch_grid
        },
        "coupling_model": (
            "Per epoch: redraw g-guard compromise with prob c. Concurrent "
            f"coordinated gossip eclipse on N={n_neighbors} peers at baseline f={f}, "
            f"majority_k={majority_k}. Boosted coupling: dirty epochs raise effective f "
            "by seating compromised guards as eclipse reporters. Default f=0.125 "
            "(1 adv of 8) is below K=2 so solo eclipse needs the boost. Gossip "
            "success = eclipse_any OR false_probation."
        ),
        "honest_limits": [
            "Synthetic independent per-epoch recompromise; field rate unknown.",
            "Gossip twin of Rust merge math only; multi-org BFT still External.",
            "Boosted coupling is a characterization aid, not measured field collusion.",
            "Does not claim adaptive_v4 or stacked gossip product defenses closed §13.",
            "No Docker / WAN adversary; CI artifacts are sim-only.",
        ],
        "field_residual": (
            "Field recompromise rate and real peer-table eclipse incidence are "
            "unmeasured — sim c and f are free parameters. Operators should treat "
            "joint union curves as upper-bound characterization, not operational C2."
        ),
    }

    if include_live_baselines:
        adapt = baseline_adaptive_only(
            c=c, g=g, epoch_grid=epoch_grid,
            trials=baseline_adaptive_trials, rng=rng,
        )
        goss = baseline_gossip_only(
            n_neighbors=n_neighbors, f=f, majority_k=majority_k,
            epoch_grid=epoch_grid, trials=baseline_gossip_trials, rng=rng,
        )
        report["baselines_live"] = {
            "adaptive_only": {str(E): round(adapt[E], 4) for E in epoch_grid},
            "gossip_only": {
                str(E): {k: round(v, 4) for k, v in goss[E].items()}
                for E in epoch_grid
            },
            "note": (
                "Live recompute via public APIs (adaptive_guard_exposure, "
                "gossip_eclipse.profile_cell). Prefer committed artifacts for "
                "pinned numbers when present."
            ),
        }

    if include_committed_baselines:
        report["baselines_committed"] = load_committed_baselines(data_dir=data_dir)

    long_e = str(max(epoch_grid))
    live = report.get("baselines_live", {})
    committed = report.get("baselines_committed", {})
    adapt_c = (committed.get("adaptive_artifact") or {}).get("adaptive_by_epochs") or {}
    goss_h = (committed.get("gossip_artifact") or {}).get("highlight_n8_f025_k2")

    report["comparison_at_long_horizon"] = {
        "E": int(long_e),
        "joint_p_union_success": curves[long_e]["p_union_success"],
        "joint_p_joint_success": curves[long_e]["p_joint_success"],
        "joint_p_adaptive_exposed": curves[long_e]["p_adaptive_exposed"],
        "joint_p_gossip_success": curves[long_e]["p_gossip_success"],
        "joint_p_gossip_fp": curves[long_e]["p_gossip_fp"],
        "joint_p_eclipse_any": curves[long_e]["p_eclipse_any"],
        "independent_p_union": report["independent_coupling_curves"][long_e][
            "p_union_success"
        ],
        "independent_p_gossip_success": report["independent_coupling_curves"][long_e][
            "p_gossip_success"
        ],
        "adaptive_only_live": live.get("adaptive_only", {}).get(long_e),
        "adaptive_only_committed": adapt_c.get(long_e) or adapt_c.get(str(long_e)),
        "gossip_only_eclipse_frac_live": (
            live.get("gossip_only", {}).get(long_e, {}) or {}
        ).get("mean_eclipse_epoch_fraction"),
        "gossip_only_fp_live": (
            live.get("gossip_only", {}).get(long_e, {}) or {}
        ).get("false_probation_rate"),
        "gossip_committed_highlight_fp": (
            goss_h.get("false_probation_rate") if goss_h else None
        ),
        "reading": (
            "At f below solo-quorum (default 0.125 with K=2), independent gossip "
            "rarely eclipses; boosted dirty epochs seat compromised guards so "
            "adv≥K and eclipse rises with adaptive exposure — joint success tracks "
            "that unlock. Union ≥ either surface. Stacked+v4 lowers mid-horizon "
            "rates; field c/f residual and §13 remain open."
        ),
    }

    if include_joint_defense:
        report["joint_defense"] = joint_defense_curve(
            epoch_grid=epoch_grid,
            trials=defense_trials,
            c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
            rng=rng,
        )

    if include_offline:
        off = joint_long_horizon(
            c=c, g=g, n_neighbors=n_neighbors, f=f, majority_k=majority_k,
            coupling=coupling, epoch_grid=tuple(offline_epoch_grid),
            trials=offline_trials, rng=rng,
        )
        report["offline_long_horizon"] = {
            "characterizes_not_closes": True,
            "section_13_closed": False,
            "epoch_grid": list(offline_epoch_grid),
            "trials": offline_trials,
            "joint_curves": {
                str(E): {k: round(v, 4) for k, v in off[E].items()}
                for E in offline_epoch_grid
            },
            "note": (
                "Offline-only extension. Expect adaptive exposure → 1 and union "
                "saturation; gossip FP saturates when boosted f keeps adv ≥ K. "
                "Not a close claim."
            ),
        }
    return report


def write_joint_guard_gossip_artifact(
    path: Path | str,
    report: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Write JSON artifact; returns the report dict."""
    report_dict = (
        dict(report) if report is not None else joint_guard_gossip_report(**kwargs)
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_dict, indent=2) + "\n", encoding="utf-8")
    return report_dict
