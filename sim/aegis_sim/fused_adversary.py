"""
Fused long-horizon adversary: adaptive recompromise ∩ active/intersection (C2).

Tag: [O] QUANTIFIED — couples adaptive compromised-mix redraw with Mode-1-like
active suppression + intersection. Does not close §13 and is not WAN closed.

Baselines (imported, not rewritten):
  - adaptive-only: adversaries.adaptive_guard_exposure / committed artifact
  - combined-only: combined_active_intersection.combined_active_intersection
                   / committed artifact

Coupling (honest synthetic):
  Each epoch redraws per-guard compromise with probability c. On dirty epochs
  the adversary observes leaky Mode-1 counts (constant_only / pad_up family)
  and may apply sender suppression. On clean epochs observables match hard_cap
  (no fused volume/drop signal). Cumulative z-scored intersection+active score
  is evaluated at epoch checkpoints; exposure is the adaptive ever-dirty event.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim.adversaries import adaptive_guard_exposure
from aegis_sim.combined_active_intersection import combined_active_intersection_curve

DEFAULT_EPOCH_GRID = (50, 100, 200, 400, 800)
OFFLINE_EPOCH_GRID = (1600, 3200)
DEFAULT_C = 0.015
DEFAULT_G = 3
DEFAULT_M = 30
DEFAULT_S_RATE = 3.0
DEFAULT_BG = 8.0
DEFAULT_Q = 25
DEFAULT_PROBE_FRAC = 0.5

# Leaky Mode-1 schemes used when a guard is compromised this epoch.
LEAKY_ON_COMPROMISE = ("constant_only", "pad_up")


def _zscore(x):
    x = np.asarray(x, dtype=float)
    s = float(x.std())
    return (x - float(x.mean())) / (s + 1e-12)


def _obs_drop_for_epoch(scheme, real_row, Q, probe, rng):
    """Single-epoch observable + drop signal (minimal helper; not CAI internals)."""
    real_row = np.asarray(real_row, dtype=float)
    if scheme == "constant_only":
        obs = real_row.copy()
        drop = real_row.mean() - real_row
    elif scheme == "pad_up":
        obs = np.maximum(real_row, float(Q))
        drop = float(Q) - obs
    elif scheme == "hard_cap":
        obs = np.full_like(real_row, float(Q))
        drop = np.zeros_like(real_row)
    else:
        raise ValueError(f"unsupported fused scheme {scheme!r}")
    return obs, drop


def fused_trial_scores(
    E,
    c=DEFAULT_C,
    g=DEFAULT_G,
    M=DEFAULT_M,
    s_rate=DEFAULT_S_RATE,
    bg=DEFAULT_BG,
    Q=DEFAULT_Q,
    probe_frac=DEFAULT_PROBE_FRAC,
    leaky_scheme="constant_only",
    epoch_grid=None,
    rng=None,
):
    """One Monte Carlo trial: adaptive dirtiness + Mode-1 fused score curve.

    Returns dict with ever_exposed, and per-checkpoint confirm / exposed flags.
    """
    rng = rng or np.random.default_rng(0)
    if leaky_scheme not in LEAKY_ON_COMPROMISE and leaky_scheme != "hard_cap":
        raise ValueError(
            f"leaky_scheme must be one of {LEAKY_ON_COMPROMISE + ('hard_cap',)}"
        )
    epoch_grid = tuple(epoch_grid) if epoch_grid is not None else (E,)
    Emax = max(int(E), max(epoch_grid))

    R = int(rng.integers(M))
    probe = rng.random(Emax) < probe_frac
    s = rng.poisson(s_rate, Emax).astype(float)
    s[probe] = 0.0
    real = rng.poisson(bg, size=(Emax, M)).astype(float)
    real[:, R] += s

    dirty_epochs = np.zeros(Emax, dtype=bool)
    ever = False
    for e in range(Emax):
        dirty = bool((rng.random(g) < c).any())
        dirty_epochs[e] = dirty
        ever = ever or dirty

    obs = np.zeros_like(real)
    drop = np.zeros_like(real)
    for e in range(Emax):
        scheme = leaky_scheme if dirty_epochs[e] else "hard_cap"
        obs[e], drop[e] = _obs_drop_for_epoch(
            scheme, real[e], Q, probe[e], rng,
        )

    p_full = probe.astype(float) - float(probe.mean())
    confirms = {}
    exposed_at = {}
    for Ep in epoch_grid:
        Ep = int(Ep)
        if Ep > Emax:
            continue
        sl = slice(0, Ep)
        cum_inter = obs[sl].sum(axis=0)
        p = p_full[sl] - float(p_full[sl].mean())
        active = np.abs((drop[sl] * p[:, None]).sum(axis=0))
        # If no dirty epochs yet, active/inter are flat → random guess.
        if not dirty_epochs[sl].any():
            combined = rng.random(M)
        else:
            combined = _zscore(cum_inter) + _zscore(active)
        confirms[Ep] = bool(np.argmax(combined) == R)
        exposed_at[Ep] = bool(dirty_epochs[sl].any())
    return {
        "ever_exposed": ever,
        "confirms": confirms,
        "exposed_at": exposed_at,
        "target": R,
    }


def fused_long_horizon(
    c=DEFAULT_C,
    g=DEFAULT_G,
    M=DEFAULT_M,
    s_rate=DEFAULT_S_RATE,
    bg=DEFAULT_BG,
    Q=DEFAULT_Q,
    probe_frac=DEFAULT_PROBE_FRAC,
    leaky_scheme="constant_only",
    epoch_grid=DEFAULT_EPOCH_GRID,
    trials=200,
    rng=None,
):
    """Monte Carlo fused curves vs epoch checkpoints.

    Metrics per epoch E:
      p_adaptive_exposed  — P(ever dirty within E)  [adaptive component]
      p_mode1_confirm     — P(fused score ranks true receiver) when coupling
      p_union_success     — P(exposed OR confirm)
      p_joint_success     — P(exposed AND confirm)
    """
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    hits_exp = {E: 0 for E in epoch_grid}
    hits_conf = {E: 0 for E in epoch_grid}
    hits_union = {E: 0 for E in epoch_grid}
    hits_joint = {E: 0 for E in epoch_grid}
    for _ in range(trials):
        trial = fused_trial_scores(
            E=max(epoch_grid), c=c, g=g, M=M, s_rate=s_rate, bg=bg, Q=Q,
            probe_frac=probe_frac, leaky_scheme=leaky_scheme,
            epoch_grid=epoch_grid,
            rng=np.random.default_rng(int(rng.integers(1 << 31))),
        )
        for E in epoch_grid:
            ex = trial["exposed_at"][E]
            cf = trial["confirms"][E]
            hits_exp[E] += int(ex)
            hits_conf[E] += int(cf)
            hits_union[E] += int(ex or cf)
            hits_joint[E] += int(ex and cf)
    curves = {}
    for E in epoch_grid:
        curves[E] = {
            "p_adaptive_exposed": hits_exp[E] / trials,
            "p_mode1_confirm": hits_conf[E] / trials,
            "p_union_success": hits_union[E] / trials,
            "p_joint_success": hits_joint[E] / trials,
        }
    return curves


def baseline_adaptive_only(c=DEFAULT_C, g=DEFAULT_G, epoch_grid=DEFAULT_EPOCH_GRID,
                           trials=400, rng=None):
    """Public-API adaptive-only baseline (no Mode-1 coupling)."""
    rng = rng or np.random.default_rng(0)
    out = {}
    for E in epoch_grid:
        out[int(E)] = adaptive_guard_exposure(
            c, g, epochs=int(E), mode="adaptive", trials=trials, rng=rng,
        )
    return out


def baseline_combined_only(
    scheme="constant_only",
    M=DEFAULT_M,
    s_rate=DEFAULT_S_RATE,
    bg=DEFAULT_BG,
    Q=DEFAULT_Q,
    probe_frac=DEFAULT_PROBE_FRAC,
    epoch_grid=DEFAULT_EPOCH_GRID,
    trials=200,
    rng=None,
):
    """Public-API combined-only baseline (no adaptive coupling)."""
    rng = rng or np.random.default_rng(0)
    return combined_active_intersection_curve(
        scheme, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
        epoch_grid=tuple(epoch_grid), trials=trials, rng=rng,
    )


def load_committed_baselines(
    data_dir=None,
    adaptive_name="adaptive_guard_exposure.analysis.json",
    combined_name="combined_active_intersection.analysis.json",
):
    """Reuse committed artifact numbers where present (no rewrite of modules)."""
    root = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent / "data"
    out = {"adaptive_artifact": None, "combined_artifact": None, "notes": []}
    ap = root / adaptive_name
    cp = root / combined_name
    if ap.is_file():
        art = json.loads(ap.read_text(encoding="utf-8"))
        out["adaptive_artifact"] = {
            "path": ap.name,
            "c": art.get("c"),
            "g": art.get("g"),
            "adaptive_by_epochs": art.get("adaptive_by_epochs"),
            "mitigated_v3_by_epochs": art.get("mitigated_v3_by_epochs"),
            "characterizes_not_closes": art.get("characterizes_not_closes", True),
        }
    else:
        out["notes"].append(f"missing adaptive artifact: {ap}")
    if cp.is_file():
        art = json.loads(cp.read_text(encoding="utf-8"))
        out["combined_artifact"] = {
            "path": cp.name,
            "M": art.get("M"),
            "baseline": art.get("baseline"),
            "curves": {
                k: art["curves"][k]
                for k in ("constant_only", "pad_up", "hard_cap")
                if k in art.get("curves", {})
            },
            "recommended_mode1": art.get("recommended_mode1"),
            "characterizes_not_closes": art.get("characterizes_not_closes", True),
        }
    else:
        out["notes"].append(f"missing combined artifact: {cp}")
    return out


def fused_adversary_report(
    c=DEFAULT_C,
    g=DEFAULT_G,
    M=DEFAULT_M,
    s_rate=DEFAULT_S_RATE,
    bg=DEFAULT_BG,
    Q=DEFAULT_Q,
    probe_frac=DEFAULT_PROBE_FRAC,
    leaky_scheme="constant_only",
    epoch_grid=DEFAULT_EPOCH_GRID,
    trials=200,
    rng=None,
    include_live_baselines=True,
    include_committed_baselines=True,
    include_offline=True,
    baseline_adaptive_trials=400,
    baseline_combined_trials=120,
    offline_epoch_grid=OFFLINE_EPOCH_GRID,
    offline_trials=100,
    data_dir=None,
):
    """Compare fused coupling against adaptive-only and combined-only baselines."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    fused = fused_long_horizon(
        c=c, g=g, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
        leaky_scheme=leaky_scheme, epoch_grid=epoch_grid, trials=trials, rng=rng,
    )
    curves = {
        str(E): {k: round(v, 4) for k, v in fused[E].items()}
        for E in epoch_grid
    }
    report = {
        "tag": "coverage_C2_fused_adaptive_active_intersection",
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "wan_closed": False,
        "c": c,
        "g": g,
        "M": M,
        "baseline_receiver_uniform": 1.0 / M,
        "s_rate": s_rate,
        "bg": bg,
        "Q": Q,
        "probe_frac": probe_frac,
        "leaky_scheme_on_compromise": leaky_scheme,
        "clean_epoch_scheme": "hard_cap",
        "trials": trials,
        "epoch_grid": list(epoch_grid),
        "fused_curves": curves,
        "coupling_model": (
            "Per epoch: redraw g-guard compromise with prob c. Dirty epochs "
            f"expose Mode-1 observables as `{leaky_scheme}`; clean epochs use "
            "hard_cap (no drop/volume signal). Score = z(cum volume)+z(active)."
        ),
        "honest_limits": [
            "Synthetic Poisson Mode-1 + independent per-epoch recompromise.",
            "Not WAN closed; exit clearnet residual is a separate weaker tier.",
            "Does not claim adaptive_v3 or hard_cap product mitigation closed.",
            "Union/joint metrics are characterization aids, not operational C2.",
        ],
    }

    if include_live_baselines:
        adapt = baseline_adaptive_only(
            c=c, g=g, epoch_grid=epoch_grid, trials=baseline_adaptive_trials, rng=rng,
        )
        comb_const = baseline_combined_only(
            scheme="constant_only", M=M, s_rate=s_rate, bg=bg, Q=Q,
            probe_frac=probe_frac, epoch_grid=epoch_grid,
            trials=baseline_combined_trials, rng=rng,
        )
        comb_hc = baseline_combined_only(
            scheme="hard_cap", M=M, s_rate=s_rate, bg=bg, Q=Q,
            probe_frac=probe_frac, epoch_grid=epoch_grid,
            trials=baseline_combined_trials, rng=rng,
        )
        report["baselines_live"] = {
            "adaptive_only": {str(E): round(adapt[E], 4) for E in epoch_grid},
            "combined_only_constant": {
                str(E): round(comb_const[E], 4) for E in epoch_grid
            },
            "combined_only_hard_cap": {
                str(E): round(comb_hc[E], 4) for E in epoch_grid
            },
            "note": (
                "Live recompute via public APIs (adaptive_guard_exposure, "
                "combined_active_intersection_curve). Prefer committed "
                "artifacts for pinned numbers when present."
            ),
        }

    if include_committed_baselines:
        report["baselines_committed"] = load_committed_baselines(data_dir=data_dir)

    # Comparison table at shared checkpoints.
    long_e = str(max(epoch_grid))
    live = report.get("baselines_live", {})
    committed = report.get("baselines_committed", {})
    adapt_c = (committed.get("adaptive_artifact") or {}).get("adaptive_by_epochs") or {}
    comb_c = ((committed.get("combined_artifact") or {}).get("curves") or {}).get(
        "constant_only", {}
    )
    report["comparison_at_long_horizon"] = {
        "E": int(long_e),
        "fused_p_union_success": curves[long_e]["p_union_success"],
        "fused_p_joint_success": curves[long_e]["p_joint_success"],
        "fused_p_adaptive_exposed": curves[long_e]["p_adaptive_exposed"],
        "fused_p_mode1_confirm": curves[long_e]["p_mode1_confirm"],
        "adaptive_only_live": live.get("adaptive_only", {}).get(long_e),
        "adaptive_only_committed": adapt_c.get(long_e),
        "combined_constant_live": live.get("combined_only_constant", {}).get(long_e),
        "combined_constant_committed": comb_c.get(long_e),
        "combined_hard_cap_live": live.get("combined_only_hard_cap", {}).get(long_e),
        "reading": (
            "Fused union is at least as large as either component alone when "
            "compromise epochs unlock leaky Mode-1 observables. hard_cap on "
            "clean epochs delays Mode-1 confirm until exposure occurs — the "
            "adaptive surface is the gate for Mode-1 leakage in this model."
        ),
    }

    if include_offline:
        off = fused_long_horizon(
            c=c, g=g, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
            leaky_scheme=leaky_scheme, epoch_grid=tuple(offline_epoch_grid),
            trials=offline_trials, rng=rng,
        )
        report["offline_long_horizon"] = {
            "characterizes_not_closes": True,
            "wan_closed": False,
            "epoch_grid": list(offline_epoch_grid),
            "trials": offline_trials,
            "fused_curves": {
                str(E): {k: round(v, 4) for k, v in off[E].items()}
                for E in offline_epoch_grid
            },
            "note": (
                "Offline-only extension (~minutes). Expect adaptive exposure "
                "and union success to saturate; Mode-1 confirm tracks dirty "
                "epochs. Not a close claim."
            ),
        }
    return report


def write_fused_adversary_artifact(path, report=None, **kwargs):
    """Write JSON artifact; returns the report dict."""
    report = report if report is not None else fused_adversary_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


# Convenience single-horizon confirm probability (CI helper).
def fused_mode1_confirm_prob(**kwargs):
    """P(mode1 confirm) at max epoch_grid under fused coupling."""
    grid = tuple(kwargs.pop("epoch_grid", DEFAULT_EPOCH_GRID))
    curves = fused_long_horizon(epoch_grid=grid, **kwargs)
    E = max(grid)
    return curves[E]["p_mode1_confirm"]
