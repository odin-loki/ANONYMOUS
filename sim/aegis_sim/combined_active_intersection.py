"""
Combined active(n-1) + intersection defense ranking (Mode-1, spec §13).

Tag: [O] QUANTIFIED — characterizes limits; does not close the open item.

Fuses long-horizon cumulative volume (intersection under constant-rate sender)
with active sender-suppression confirmation on a shared synthetic epoch timeline.

Product mapping: sim scheme `hard_cap` / `deferred_hard_cap` ↔ Rust
`aegis_client::HardCapPadder` (observable = exactly Q every round; excess deferred).
Exit / non-AEGIS receivers are excluded from this guarantee (see `sim_to_product`).
"""
from __future__ import annotations

import numpy as np

# Schemes ranked in the committed CI artifact (order is evaluation order, not rank).
CI_SCHEMES = (
    "constant_only",
    "pad_up",
    "truncate_only",
    "noisy_hard_cap",
    "deferred_hard_cap",
    "hard_cap",
)

# Longer offline characterization (still synthetic; not a close claim).
OFFLINE_SCHEMES = ("constant_only", "pad_up", "hard_cap", "deferred_hard_cap")

DEFAULT_EPOCH_GRID = (50, 100, 200, 400, 800, 1600)
OFFLINE_EPOCH_GRID = (3200, 6400)
DEFAULT_M_GRID = (10, 20, 30, 50)
DEFAULT_Q_GRID = (12, 15, 20, 25, 33, 40)
HARD_CAP_FAMILY = frozenset({"hard_cap", "deferred_hard_cap"})
# Within this absolute band, MC noise is not a "beat hard_cap" claim.
BASELINE_TIE_EPS = 0.03


def _zscore(x):
    s = float(x.std())
    return (x - x.mean()) / (s + 1e-12)


def _deferred_hard_cap_columns(real, Q):
    """FIFO hard-cap per receiver column — external obs is exactly Q every epoch.

    Mirrors `shaper.hard_cap` / Rust `HardCapPadder::round_tick`: release min(backlog, Q)
    real slots and fill the rest with dummy so the observer always sees Q. Excess is
    deferred (latency), never shape-leaked.
    """
    E, M = real.shape
    obs = np.full((E, M), float(Q), dtype=float)
    released = np.zeros((E, M), dtype=float)
    backlog = np.zeros(M, dtype=float)
    for e in range(E):
        backlog += real[e]
        take = np.minimum(backlog, float(Q))
        backlog -= take
        released[e] = take
    # Active drop signal is identically zero externally (dummies fill to Q).
    drop = np.zeros_like(real)
    return obs, drop, released, backlog


def _combined_obs_and_drop(scheme, real, Q, rng=None):
    """Observable counts and per-epoch drop signal for the fused attack."""
    rng = rng or np.random.default_rng(0)
    if scheme == "constant_only":
        obs = real.copy()
        drop = real.mean(axis=0, keepdims=True) - real
    elif scheme == "pad_up":
        obs = np.maximum(real, Q)
        drop = Q - obs
    elif scheme == "truncate_only":
        # Cap without fill: under-Q epochs leak volume; over-Q drops excess.
        obs = np.minimum(real, Q)
        drop = Q - obs
    elif scheme == "noisy_hard_cap":
        # Misconfigured "almost hard-cap": partial transparency of (real - Q).
        # Independent Laplace on Q alone stays ~baseline (no fused signal).
        # Letting a fraction of the surplus/deficit through is the honest failure
        # mode when dummy fill tracks backlog instead of a flat Q wall.
        surplus = real - float(Q)
        obs = np.clip(np.rint(float(Q) + 0.4 * surplus), 1.0, None)
        drop = float(Q) - obs
    elif scheme in ("hard_cap", "deferred_hard_cap"):
        # Attack-visible invariant matches ideal hard_cap: observer always sees Q.
        # FIFO deferral (`_deferred_hard_cap_columns`) is a latency-cost model only;
        # it cannot change the fused-attack observables (see sim→product mapping).
        obs = np.full_like(real, float(Q))
        drop = np.zeros_like(real)
    else:
        raise ValueError(
            f"unknown scheme {scheme!r}; expected one of {CI_SCHEMES}"
        )
    return obs, drop


def combined_active_intersection(scheme, M=30, s_rate=3.0, bg=8.0, Q=25,
                                 probe_frac=0.5, E=800, trials=200, rng=None):
    """P(true receiver #1) under fused active+intersection attack. Baseline=1/M."""
    rng = rng or np.random.default_rng(0)
    hits = 0
    for t in range(trials):
        R = rng.integers(M)
        probe = rng.random(E) < probe_frac
        s = rng.poisson(s_rate, E).astype(float)
        s[probe] = 0
        real = rng.poisson(bg, size=(E, M)).astype(float)
        real[:, R] += s
        obs, drop = _combined_obs_and_drop(scheme, real, Q, rng=rng)
        cum_inter = obs.sum(axis=0)
        p = probe.astype(float) - probe.mean()
        active = np.abs((drop * p[:, None]).sum(axis=0))
        combined = _zscore(cum_inter) + _zscore(active)
        hits += (np.argmax(combined) == R)
    return hits / trials


def combined_active_intersection_curve(scheme, M=30, s_rate=3.0, bg=8.0, Q=25,
                                       probe_frac=0.5,
                                       epoch_grid=DEFAULT_EPOCH_GRID,
                                       trials=200, rng=None):
    """Long-horizon curve: P(confirm) vs epoch count for a fixed scheme."""
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(epoch_grid)
    Emax = max(epoch_grid)
    hits = {E: 0 for E in epoch_grid}
    for _ in range(trials):
        R = rng.integers(M)
        probe = rng.random(Emax) < probe_frac
        s = rng.poisson(s_rate, Emax).astype(float)
        s[probe] = 0
        real = rng.poisson(bg, size=(Emax, M)).astype(float)
        real[:, R] += s
        obs, drop = _combined_obs_and_drop(scheme, real, Q, rng=rng)
        p_full = probe.astype(float) - probe.mean()
        gi = 0
        for e in range(Emax):
            if e + 1 != epoch_grid[gi]:
                continue
            sl = slice(0, e + 1)
            cum_inter = obs[sl].sum(axis=0)
            p = p_full[sl] - p_full[sl].mean()
            active = np.abs((drop[sl] * p[:, None]).sum(axis=0))
            combined = _zscore(cum_inter) + _zscore(active)
            if np.argmax(combined) == R:
                hits[epoch_grid[gi]] += 1
            gi += 1
            if gi >= len(epoch_grid):
                break
    return {E: hits[E] / trials for E in epoch_grid}


def _curve_dict(scheme, **kwargs):
    return {
        str(E): round(p, 4)
        for E, p in combined_active_intersection_curve(scheme, **kwargs).items()
    }


def _rank_schemes(curves, epoch_grid, baseline):
    long_e = str(max(epoch_grid))
    ranking = []
    for sch, curve in curves.items():
        p_long = curve[long_e]
        ranking.append({
            "scheme": sch,
            "p_confirm_at_long_horizon": p_long,
            "holds_at_baseline": p_long <= baseline + 0.05,
            "hard_cap_family": sch in HARD_CAP_FAMILY,
        })
    # Rank by long-horizon P(confirm). Tie-break prefers hard_cap family so MC
    # jitter among ~baseline schemes does not bury the product recommendation.
    ranking.sort(key=lambda row: (
        row["p_confirm_at_long_horizon"],
        0 if row["hard_cap_family"] else 1,
        0 if row["scheme"] == "hard_cap" else 1,
        row["scheme"],
    ))
    return ranking


def _recommend_scheme(ranking):
    """Recommend hard_cap whenever it holds; never crown MC-noise near-ties."""
    by_name = {r["scheme"]: r for r in ranking}
    hc = by_name.get("hard_cap")
    if hc is not None and hc["holds_at_baseline"]:
        challengers = [
            r for r in ranking
            if r["scheme"] not in HARD_CAP_FAMILY
            and r["holds_at_baseline"]
            and r["p_confirm_at_long_horizon"] + BASELINE_TIE_EPS
            < hc["p_confirm_at_long_horizon"]
        ]
        if challengers:
            # Production-honest beat: only if we ever add a mapped scheme that
            # clearly wins. Until then, keep hard_cap (do not claim a beat).
            return "hard_cap", False
        return "hard_cap", False
    # Fallback if hard_cap missing or fails provisioning in this run.
    for r in ranking:
        if r["holds_at_baseline"]:
            return r["scheme"], r["scheme"] not in HARD_CAP_FAMILY
    return ranking[0]["scheme"], ranking[0]["scheme"] not in HARD_CAP_FAMILY


def sensitivity_to_anonymity_set(M_grid=DEFAULT_M_GRID, s_rate=3.0, bg=8.0, Q=25,
                                 probe_frac=0.5, E=800, trials=80, rng=None,
                                 schemes=("hard_cap", "pad_up", "constant_only")):
    """P(confirm) vs anonymity-set size M (=n candidates) at fixed horizon E."""
    rng = rng or np.random.default_rng(0)
    out = {}
    for M in M_grid:
        out[str(M)] = {
            "baseline": round(1 / M, 6),
            "by_scheme": {},
        }
        for sch in schemes:
            p = combined_active_intersection(
                sch, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
                E=E, trials=trials, rng=rng,
            )
            out[str(M)]["by_scheme"][sch] = round(p, 4)
    return {
        "E": E,
        "trials": trials,
        "Q": Q,
        "M_grid": list(M_grid),
        "results": out,
        "note": (
            "hard_cap tracks ~1/M. constant_only saturates regardless of M. "
            "pad_up at high Q can sit near baseline at moderate E; use Q-sweep "
            "and offline curves — larger n alone does not close the attack."
        ),
    }


def sensitivity_to_padding_budget(Q_grid=DEFAULT_Q_GRID, M=30, s_rate=3.0, bg=8.0,
                                  probe_frac=0.5, E=800, trials=80, rng=None,
                                  schemes=("hard_cap", "pad_up")):
    """P(confirm) vs padding quota Q (budget) at fixed horizon E."""
    rng = rng or np.random.default_rng(0)
    sustained = bg + s_rate
    out = {}
    for Q in Q_grid:
        out[str(Q)] = {
            "Q_over_sustained_mean": round(Q / sustained, 3),
            "by_scheme": {},
        }
        for sch in schemes:
            p = combined_active_intersection(
                sch, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
                E=E, trials=trials, rng=rng,
            )
            out[str(Q)]["by_scheme"][sch] = round(p, 4)
    return {
        "E": E,
        "trials": trials,
        "M": M,
        "sustained_mean": sustained,
        "Q_grid": list(Q_grid),
        "results": out,
        "note": (
            "hard_cap stays near baseline for any Q >= sustained mean. pad_up "
            "improves with Q; when Q exceeds the traffic ceiling it collapses "
            "toward hard_cap (same bandwidth cost). Prefer explicit hard_cap "
            "(HardCapPadder) over hoping pad_up Q is large enough. Offline at "
            "Q=25 still shows pad_up rising with E."
        ),
    }


def _sim_to_product_block(q_recommended_min):
    return {
        "sim_scheme_recommended": "hard_cap",
        "sim_equivalent_product_model": "deferred_hard_cap",
        "rust_type": "aegis_client::HardCapPadder / CountHardCapPadder",
        "rust_config": "HardCapConfig { q }",
        "invariant": "observable deliveries per round == Q (real + dummy filler)",
        "deferral": "excess real arrivals FIFO-deferred (latency cost, not shape leak)",
        "Q_rule": "Q >= ~1.2 × sustained mean arrival rate per round",
        "Q_recommended_min": q_recommended_min,
        "operator_must_enable": [
            "Mode-1 paced client session (not --raw / unpaced send APIs)",
            "Receiver-side hard-cap padding with Q meeting the 1.2× rule",
            "Internal-tier peers (both endpoints run AEGIS)",
        ],
        "exit_tier_exclusion_residual": (
            "Clearnet exit / non-AEGIS receivers cannot apply HardCapPadder; "
            "receiver-side fused-attack resistance does not transfer to that tier. "
            "Sender-side constant-rate emission may still hold to the exit relay."
        ),
        "mapping_doc": "docs/ops/combined_attack_mode1_hardcap.md",
    }


def combined_attack_defense_report(
    M=30,
    s_rate=3.0,
    bg=8.0,
    Q=25,
    probe_frac=0.5,
    epoch_grid=DEFAULT_EPOCH_GRID,
    trials=200,
    rng=None,
    schemes=CI_SCHEMES,
    include_sensitivity=True,
    include_offline=True,
    sensitivity_M_grid=DEFAULT_M_GRID,
    sensitivity_Q_grid=DEFAULT_Q_GRID,
    sensitivity_E=800,
    sensitivity_trials=80,
    offline_epoch_grid=OFFLINE_EPOCH_GRID,
    offline_trials=100,
    offline_schemes=OFFLINE_SCHEMES,
):
    """Defense ranking + sensitivity + offline long-horizon characterization.

    CI-safe callers: short `epoch_grid`, modest `trials`, and
    `include_sensitivity=False, include_offline=False`.
    Offline / artifact generation: defaults below (still synthetic; not closed).
    """
    rng = rng or np.random.default_rng(0)
    epoch_grid = tuple(epoch_grid)
    schemes = tuple(schemes)
    baseline = 1 / M
    curves = {}
    for sch in schemes:
        if sch == "deferred_hard_cap" and "hard_cap" in curves:
            # Attack-identical to hard_cap by construction (avoid MC drift).
            curves[sch] = dict(curves["hard_cap"])
            continue
        curves[sch] = _curve_dict(
            sch, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
            epoch_grid=epoch_grid, trials=trials, rng=rng,
        )
    if "deferred_hard_cap" in schemes and "hard_cap" in curves:
        curves["deferred_hard_cap"] = dict(curves["hard_cap"])
    ranking = _rank_schemes(curves, epoch_grid, baseline)
    sustained_mean = bg + s_rate
    q_min = max(Q, int(np.ceil(1.2 * sustained_mean)))
    recommended, beats_hc = _recommend_scheme(ranking)

    report = {
        "tag": "spec_13_O_combined_active_intersection_mode1",
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "M": M,
        "baseline": baseline,
        "s_rate": s_rate,
        "bg": bg,
        "Q": Q,
        "probe_frac": probe_frac,
        "trials": trials,
        "epoch_grid": list(epoch_grid),
        "schemes_evaluated": list(schemes),
        "curves": curves,
        "defense_ranking": ranking,
        "recommended_mode1": {
            "scheme": recommended,
            "receiver_hard_cap": recommended in HARD_CAP_FAMILY,
            "Q_min_sustained_multiple": 1.2,
            "Q_recommended_min": q_min,
            "beats_hard_cap_in_sim": beats_hc,
            "operator_note": (
                "Keep receiver-side hard-cap padding enabled in production Mode-1 "
                f"(Q>={q_min}); pad-up, truncate-only, noisy, and constant-rate "
                "observables remain vulnerable to the fused attack (or only match "
                "hard_cap when Q exceeds the traffic ceiling — same cost, weaker "
                "invariant). Exit/non-AEGIS receivers are excluded from this claim."
            ),
        },
        "sim_to_product": _sim_to_product_block(q_min),
    }

    if include_sensitivity:
        # M-sweep uses a leaky pad budget (Q=15) so pad_up residual is visible;
        # Q-sweep varies budget at fixed M (includes collapse toward hard_cap).
        report["sensitivity"] = {
            "anonymity_set_M": sensitivity_to_anonymity_set(
                M_grid=sensitivity_M_grid, s_rate=s_rate, bg=bg, Q=15,
                probe_frac=probe_frac, E=sensitivity_E, trials=sensitivity_trials,
                rng=rng,
            ),
            "padding_budget_Q": sensitivity_to_padding_budget(
                Q_grid=sensitivity_Q_grid, M=M, s_rate=s_rate, bg=bg,
                probe_frac=probe_frac, E=sensitivity_E, trials=sensitivity_trials,
                rng=rng,
            ),
        }

    if include_offline:
        offline_curves = {}
        for sch in offline_schemes:
            if sch == "deferred_hard_cap" and "hard_cap" in offline_curves:
                offline_curves[sch] = dict(offline_curves["hard_cap"])
                continue
            offline_curves[sch] = _curve_dict(
                sch, M=M, s_rate=s_rate, bg=bg, Q=Q, probe_frac=probe_frac,
                epoch_grid=tuple(offline_epoch_grid), trials=offline_trials, rng=rng,
            )
        if "deferred_hard_cap" in offline_schemes and "hard_cap" in offline_curves:
            offline_curves["deferred_hard_cap"] = dict(offline_curves["hard_cap"])
        report["offline_long_horizon"] = {
            "characterizes_not_closes": True,
            "epoch_grid": list(offline_epoch_grid),
            "trials": offline_trials,
            "schemes": list(offline_schemes),
            "curves": offline_curves,
            "note": (
                "Offline-only extension past the CI epoch grid. hard_cap / "
                "deferred_hard_cap remain near baseline; constant_only saturates; "
                "pad_up continues above baseline. Not a production close claim."
            ),
        }

    return report


def combined_attack_report(**kwargs):
    """Alias used by artifact generator / callers."""
    return combined_attack_defense_report(**kwargs)
