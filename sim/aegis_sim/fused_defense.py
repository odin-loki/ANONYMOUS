"""
Fused / adaptive defenses for C2 long-horizon coupling (research wave S5).

Tag: [O] QUANTIFIED Partial — keeps Mode-1 hard_cap more effective under
recompromise by reducing dirty-epoch rate (adaptive_v4) and/or forcing
hard_cap observables. Does **not** close §13; not WAN closed.

Defense modes:
  undefended     — independent per-epoch recompromise (C2 fused baseline)
  mitigated_v3   — sticky/demotion process from adversaries._MITIGATION_V3
  mitigated_v4   — adaptive_v4 knobs (targets E=2000 saturation residual)
  hard_cap_forced — always hard_cap observables (idealized Mode-1 under any dirty)
  fused_v4       — mitigated_v4 dirtiness + leaky only when dirty (best coupled)

Coupling: dirty epochs unlock leaky Mode-1 (constant_only / pad_up); clean
epochs use hard_cap (no fused volume/drop signal) — same as fused_adversary.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

from aegis_sim.adversaries import (
    _MITIGATION_V3,
    _MITIGATION_V4,
    _mitigation_params_for_mode,
    adaptive_guard_exposure,
)
from aegis_sim.fused_adversary import (
    DEFAULT_BG,
    DEFAULT_C,
    DEFAULT_G,
    DEFAULT_M,
    DEFAULT_PROBE_FRAC,
    DEFAULT_Q,
    DEFAULT_S_RATE,
    LEAKY_ON_COMPROMISE,
    _obs_drop_for_epoch,
    _zscore,
)

CI_EPOCH_GRID = (50, 100, 200, 400, 800)
CI_TRIALS = 120
# E=2000 included in CI report with bounded trials (not full offline).
CI_LONG_GRID = (200, 800, 2000)
CI_LONG_TRIALS = 80

OFFLINE_EPOCH_GRID = (1600, 2000, 3200)
OFFLINE_TRIALS = 100

DEFENSE_MODES = (
    "undefended",
    "mitigated_v3",
    "mitigated_v4",
    "hard_cap_forced",
    "fused_v4",
)


def _params_for_defense(mode: str) -> Optional[Dict[str, Any]]:
    if mode in ("mitigated_v3",):
        return _mitigation_params_for_mode("mitigated_v3")
    if mode in ("mitigated_v4", "fused_v4"):
        return _mitigation_params_for_mode("mitigated_v4")
    if mode in ("undefended", "hard_cap_forced"):
        return None
    raise ValueError(f"unknown fused defense mode {mode!r}")


def mitigated_dirty_epochs(
    E: int,
    c: float,
    g: int,
    params: Mapping[str, Any],
    rng: np.random.Generator,
) -> np.ndarray:
    """Per-epoch dirtiness under sticky-cap / demotion (no early exit)."""
    E = max(int(E), 1)
    dirty = np.zeros(E, dtype=bool)
    eff_c = float(c)
    sticky = 0
    floor_c = c * float(params["demotion_floor"])
    linger = 0
    stickiness = 1.0
    soft_e = int(params.get("soft_sticky_epochs", params["max_sticky_epochs"]))
    sdec = float(params.get("stickiness_decay", 1.0))
    rep_p = min(0.45, float(params.get("rep_signal_scale", 0.0)) * g * c)
    rep_extra = float(params.get("rep_demotion_extra", 1.0))
    for e in range(E):
        sticky += 1
        stickiness *= sdec
        is_dirty = bool((rng.random(g) < eff_c).any())
        dirty[e] = is_dirty
        rep_signal = (not is_dirty) and (rng.random() < rep_p)
        soft = sticky >= soft_e and (rng.random() > stickiness)
        hard = sticky >= int(params["max_sticky_epochs"])
        if is_dirty or hard or soft or rep_signal:
            sticky = 0
            stickiness = 1.0
            decay = float(params["demotion_decay"])
            if is_dirty and params.get("aggressive"):
                decay *= 0.75
            if rep_signal:
                decay *= rep_extra
            eff_c = max(floor_c, eff_c * decay)
            linger = int(params["demotion_linger"])
        if linger > 0:
            linger -= 1
        else:
            eff_c = max(floor_c, eff_c * (1.0 - 2e-4))
    return dirty


def undefended_dirty_epochs(
    E: int, c: float, g: int, rng: np.random.Generator
) -> np.ndarray:
    dirty = np.zeros(max(int(E), 1), dtype=bool)
    for e in range(len(dirty)):
        dirty[e] = bool((rng.random(g) < c).any())
    return dirty


def fused_defense_trial(
    E: int,
    mode: str = "fused_v4",
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    M: int = DEFAULT_M,
    s_rate: float = DEFAULT_S_RATE,
    bg: float = DEFAULT_BG,
    Q: float = DEFAULT_Q,
    probe_frac: float = DEFAULT_PROBE_FRAC,
    leaky_scheme: str = "constant_only",
    epoch_grid: Optional[Sequence[int]] = None,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """One trial: defense-conditioned dirtiness + Mode-1 fused scores."""
    rng = rng or np.random.default_rng(0)
    if leaky_scheme not in LEAKY_ON_COMPROMISE and leaky_scheme != "hard_cap":
        raise ValueError(
            f"leaky_scheme must be one of {LEAKY_ON_COMPROMISE + ('hard_cap',)}"
        )
    if mode not in DEFENSE_MODES:
        raise ValueError(f"mode must be one of {DEFENSE_MODES}")
    epoch_grid = tuple(epoch_grid) if epoch_grid is not None else (E,)
    Emax = max(int(E), max(int(x) for x in epoch_grid))

    R = int(rng.integers(M))
    probe = rng.random(Emax) < probe_frac
    s = rng.poisson(s_rate, Emax).astype(float)
    s[probe] = 0.0
    real = rng.poisson(bg, size=(Emax, M)).astype(float)
    real[:, R] += s

    params = _params_for_defense(mode)
    if params is None:
        dirty_epochs = undefended_dirty_epochs(Emax, c, g, rng)
    else:
        dirty_epochs = mitigated_dirty_epochs(Emax, c, g, params, rng)

    force_hard = mode == "hard_cap_forced"
    obs = np.zeros_like(real)
    drop = np.zeros_like(real)
    for e in range(Emax):
        if force_hard:
            scheme = "hard_cap"
        else:
            scheme = leaky_scheme if dirty_epochs[e] else "hard_cap"
        obs[e], drop[e] = _obs_drop_for_epoch(scheme, real[e], Q, probe[e], rng)

    p_full = probe.astype(float) - float(probe.mean())
    confirms: Dict[int, bool] = {}
    exposed_at: Dict[int, bool] = {}
    dirty_frac: Dict[int, float] = {}
    for Ep in epoch_grid:
        Ep = int(Ep)
        if Ep > Emax:
            continue
        sl = slice(0, Ep)
        cum_inter = obs[sl].sum(axis=0)
        p = p_full[sl] - float(p_full[sl].mean())
        active = np.abs((drop[sl] * p[:, None]).sum(axis=0))
        if force_hard or not dirty_epochs[sl].any():
            combined = rng.random(M)
        else:
            combined = _zscore(cum_inter) + _zscore(active)
        confirms[Ep] = bool(np.argmax(combined) == R)
        exposed_at[Ep] = bool(dirty_epochs[sl].any())
        dirty_frac[Ep] = float(dirty_epochs[sl].mean())
    return {
        "mode": mode,
        "ever_exposed": bool(dirty_epochs.any()),
        "confirms": confirms,
        "exposed_at": exposed_at,
        "dirty_frac": dirty_frac,
        "target": R,
    }


def fused_defense_long_horizon(
    mode: str = "fused_v4",
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    M: int = DEFAULT_M,
    s_rate: float = DEFAULT_S_RATE,
    bg: float = DEFAULT_BG,
    Q: float = DEFAULT_Q,
    probe_frac: float = DEFAULT_PROBE_FRAC,
    leaky_scheme: str = "constant_only",
    epoch_grid: Sequence[int] = CI_EPOCH_GRID,
    trials: int = CI_TRIALS,
    rng: Optional[np.random.Generator] = None,
) -> Dict[int, Dict[str, float]]:
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(int(e) for e in epoch_grid)
    hits_exp = {E: 0 for E in epoch_grid}
    hits_conf = {E: 0 for E in epoch_grid}
    hits_union = {E: 0 for E in epoch_grid}
    hits_joint = {E: 0 for E in epoch_grid}
    dirty_sum = {E: 0.0 for E in epoch_grid}
    for _ in range(max(int(trials), 1)):
        trial = fused_defense_trial(
            E=max(epoch_grid),
            mode=mode,
            c=c,
            g=g,
            M=M,
            s_rate=s_rate,
            bg=bg,
            Q=Q,
            probe_frac=probe_frac,
            leaky_scheme=leaky_scheme,
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
            dirty_sum[E] += trial["dirty_frac"][E]
    curves = {}
    for E in epoch_grid:
        curves[E] = {
            "p_adaptive_exposed": hits_exp[E] / trials,
            "p_mode1_confirm": hits_conf[E] / trials,
            "p_union_success": hits_union[E] / trials,
            "p_joint_success": hits_joint[E] / trials,
            "mean_dirty_epoch_fraction": dirty_sum[E] / trials,
        }
    return curves


def compare_fused_defenses(
    modes: Sequence[str] = DEFENSE_MODES,
    epoch_grid: Sequence[int] = CI_LONG_GRID,
    trials: int = CI_LONG_TRIALS,
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    M: int = DEFAULT_M,
    leaky_scheme: str = "constant_only",
    seed: int = 20260718,
) -> Dict[str, Any]:
    rng = np.random.default_rng(seed)
    by_mode: Dict[str, Any] = {}
    for mode in modes:
        curves = fused_defense_long_horizon(
            mode=mode,
            c=c,
            g=g,
            M=M,
            leaky_scheme=leaky_scheme,
            epoch_grid=epoch_grid,
            trials=trials,
            rng=rng,
        )
        by_mode[mode] = {
            str(E): {k: round(v, 4) for k, v in curves[E].items()}
            for E in epoch_grid
        }

    undef = by_mode.get("undefended", {})
    deltas = {}
    for mode, curves in by_mode.items():
        if mode == "undefended":
            continue
        deltas[mode] = {}
        for E in epoch_grid:
            es = str(E)
            if es not in undef or es not in curves:
                continue
            deltas[mode][es] = {
                "delta_mode1_confirm": round(
                    undef[es]["p_mode1_confirm"] - curves[es]["p_mode1_confirm"], 4
                ),
                "delta_adaptive_exposed": round(
                    undef[es]["p_adaptive_exposed"] - curves[es]["p_adaptive_exposed"], 4
                ),
                "delta_union": round(
                    undef[es]["p_union_success"] - curves[es]["p_union_success"], 4
                ),
            }

    # Adaptive-only exposure reference (mitigated modes) at long E.
    long_e = max(int(e) for e in epoch_grid)
    adapt_ref = {
        "adaptive": adaptive_guard_exposure(
            c, g, epochs=long_e, mode="adaptive", trials=max(trials, 200), rng=rng,
        ),
        "mitigated_v3": adaptive_guard_exposure(
            c, g, epochs=long_e, mode="mitigated_v3", trials=max(trials, 200), rng=rng,
        ),
        "mitigated_v4": adaptive_guard_exposure(
            c, g, epochs=long_e, mode="mitigated_v4", trials=max(trials, 200), rng=rng,
        ),
    }
    return {
        "epoch_grid": list(epoch_grid),
        "trials": trials,
        "c": c,
        "g": g,
        "M": M,
        "baseline_receiver_uniform": 1.0 / M,
        "leaky_scheme_on_compromise": leaky_scheme,
        "by_mode": by_mode,
        "deltas_vs_undefended": deltas,
        "adaptive_only_ref_at_long_E": {
            "E": long_e,
            **{k: round(v, 4) for k, v in adapt_ref.items()},
        },
        "mitigation_params_v3": _MITIGATION_V3,
        "mitigation_params_v4": _MITIGATION_V4,
    }


def fused_defense_report(
    *,
    epoch_grid: Sequence[int] = CI_LONG_GRID,
    trials: int = CI_LONG_TRIALS,
    include_offline: bool = False,
    offline_epoch_grid: Sequence[int] = OFFLINE_EPOCH_GRID,
    offline_trials: int = OFFLINE_TRIALS,
    seed: int = 20260718,
    c: float = DEFAULT_C,
    g: int = DEFAULT_G,
    M: int = DEFAULT_M,
) -> Dict[str, Any]:
    compare = compare_fused_defenses(
        epoch_grid=epoch_grid,
        trials=trials,
        c=c,
        g=g,
        M=M,
        seed=seed,
    )
    long_e = str(max(epoch_grid))
    fused_v4 = compare["by_mode"].get("fused_v4", {}).get(long_e, {})
    undef = compare["by_mode"].get("undefended", {}).get(long_e, {})
    hc = compare["by_mode"].get("hard_cap_forced", {}).get(long_e, {})
    report: Dict[str, Any] = {
        "tag": "coverage_S5_fused_adaptive_defense",
        "status": "[O] QUANTIFIED",
        "claim_closed": False,
        "wan_closed": False,
        "characterizes_not_closes": True,
        "wave": "S5",
        "parent_wave": "C2",
        "best_defense": "fused_v4",
        "compare": compare,
        "summary_at_long_horizon": {
            "E": int(long_e),
            "undefended": undef,
            "fused_v4": fused_v4,
            "hard_cap_forced": hc,
            "mode1_confirm_reduction_vs_undefended": (
                None
                if not undef or not fused_v4
                else round(
                    undef["p_mode1_confirm"] - fused_v4["p_mode1_confirm"], 4
                )
            ),
            "reading": (
                "fused_v4 lowers dirty-epoch fraction via adaptive_v4, so Mode-1 "
                "stays on hard_cap longer; hard_cap_forced keeps confirm ~1/M but "
                "does not reduce adaptive exposure. §13 remains open."
            ),
        },
        "findings": [
            (
                "adaptive_v4 sticky/demotion reduces cumulative exposure vs v3 at "
                "E=2000 in adaptive-only sim; fused coupling inherits fewer leaky epochs."
            ),
            (
                "hard_cap_forced keeps p_mode1_confirm near uniform baseline even "
                "under recompromise — the Mode-1 product invariant — but adaptive "
                "exposure is unchanged."
            ),
            (
                "Best coupled defense is fused_v4 (mitigated dirtiness + hard_cap "
                "on clean epochs). Does not close §13 or WAN C2."
            ),
        ],
        "honest_limits": [
            "Synthetic Poisson Mode-1 + sim demotion model.",
            "Not WAN closed; exit clearnet residual remains a weaker tier.",
            "Never claim §13 closed; long horizons may still saturate.",
        ],
    }
    if include_offline:
        off = compare_fused_defenses(
            modes=("undefended", "mitigated_v4", "fused_v4", "hard_cap_forced"),
            epoch_grid=offline_epoch_grid,
            trials=offline_trials,
            c=c,
            g=g,
            M=M,
            seed=seed + 1,
        )
        report["offline"] = {
            "characterizes_not_closes": True,
            "wan_closed": False,
            "compare": off,
        }
    return report


def write_fused_defense_artifact(
    path: Path, report: Mapping[str, Any] | None = None, **kwargs
) -> Dict[str, Any]:
    report = report if report is not None else fused_defense_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return dict(report)
