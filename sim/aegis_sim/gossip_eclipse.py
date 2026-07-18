"""
Gossip eclipse + majority_k collusion profiling (research coverage wave C1).

Tag: [O] QUANTIFIED Partial — characterizes bias / false probation / eclipse rates.
Does **not** close multi-org BFT reputation (still External).

Fidelity target (pure Python twin of Rust merge math):
  - PeerHealthTracker::ingest_gossip_observation — buffer until K distinct reporters
  - median_outcome_counts — median failure rate → synthetic (ok, fail) via mean total
  - apply_gossip_outcomes at GOSSIP_WEIGHT = 1/2
  - Coordinated eclipse: adversarial neighbors report first so a pure-adv quorum
    can fire before honest reporters enter the pending map

See: docs/ops/health_gossip.md, crates/aegis-relay/src/peer_health.rs
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

GOSSIP_WEIGHT = 0.5
DEFAULT_SAMPLE_TOTAL = 100
HONEST_FAIL_RATE = 0.10
ATTACK_FAIL_RATE = 1.0
# Window fail-rate above which an honest subject is treated as falsely demoted.
FALSE_PROBATION_THRESHOLD = 0.40
PATH_REPUTATION_FLOOR = 0.3

# CI-friendly grids (pytest must stay fast).
CI_F_GRID = (0.0, 0.125, 0.25, 0.5, 0.75, 1.0)
CI_K_GRID = (1, 2, 3)
CI_N_GRID = (4, 8, 12)
CI_TRIALS = 80
CI_EPOCHS = 6

# Offline characterization (still synthetic; not a close claim).
OFFLINE_F_GRID = (0.0, 0.125, 0.25, 0.375, 0.5, 0.625, 0.75, 0.875, 1.0)
OFFLINE_K_GRID = (1, 2, 3, 4, 5)
OFFLINE_N_GRID = (4, 6, 8, 12, 16, 24)
OFFLINE_TRIALS = 400
OFFLINE_EPOCHS = 12


def _counts_from_rate(fail_rate: float, total: int = DEFAULT_SAMPLE_TOTAL) -> Tuple[int, int]:
    fail_rate = float(np.clip(fail_rate, 0.0, 1.0))
    total = max(int(total), 1)
    fail = int(round(fail_rate * total))
    fail = min(max(fail, 0), total)
    return total - fail, fail


def median_outcome_counts(obs: Sequence[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """Rust `median_outcome_counts` twin: median fail-rate → synthetic counts."""
    rates: List[float] = []
    totals: List[int] = []
    for ok, fail in obs:
        total = int(ok) + int(fail)
        if total <= 0:
            continue
        rates.append(fail / total)
        totals.append(total)
    if not rates:
        return None
    rates_sorted = sorted(rates)
    n = len(rates_sorted)
    mid = n // 2
    if n % 2 == 1:
        median_rate = rates_sorted[mid]
    else:
        median_rate = 0.5 * (rates_sorted[mid - 1] + rates_sorted[mid])
    avg_total = sum(totals) / len(totals)
    sample_total = max(int(round(avg_total)), 1)
    fail = min(int(round(median_rate * sample_total)), sample_total)
    ok = sample_total - fail
    if ok == 0 and fail == 0:
        return None
    return ok, fail


def apply_gossip_half_weight(
    window_ok: int, window_fail: int, ok: int, fail: int
) -> Tuple[int, int]:
    """Floor-scaled half-weight merge (GOSSIP_WEIGHT_NUM/DEN = 1/2)."""
    add_ok = (int(ok) * 1) // 2
    add_fail = (int(fail) * 1) // 2
    if add_ok == 0 and add_fail == 0:
        return window_ok, window_fail
    return window_ok + add_ok, window_fail + add_fail


def failure_rate(ok: int, fail: int) -> Optional[float]:
    total = int(ok) + int(fail)
    if total <= 0:
        return None
    return fail / total


class GossipMergeBuffer:
    """Pending reporter → observation map; apply median when len >= majority_k."""

    def __init__(self, majority_k: int):
        self.majority_k = max(int(majority_k), 1)
        self.pending: Dict[int, Tuple[int, int]] = {}

    def ingest(
        self, reporter: int, ok: int, fail: int
    ) -> Tuple[str, Optional[Tuple[int, int]], int, int]:
        """
        Returns (status, median_counts|None, have, honest_in_merge).
        status is 'buffered' or 'applied'.
        """
        self.pending[reporter] = (int(ok), int(fail))
        have = len(self.pending)
        if have < self.majority_k:
            return "buffered", None, have, 0
        observations = list(self.pending.values())
        # honest reporters use non-negative ids; adversaries use negative ids in sim
        honest_in = sum(1 for r in self.pending if r >= 0)
        self.pending.clear()
        med = median_outcome_counts(observations)
        return "applied", med, have, honest_in


def n_adversarial(n_neighbors: int, f: float) -> int:
    """Adversary count from fraction f (rounded, clamped)."""
    n = max(int(n_neighbors), 0)
    if n == 0:
        return 0
    adv = int(round(float(f) * n))
    return int(np.clip(adv, 0, n))


def simulate_victim_epoch(
    n_neighbors: int,
    f: float,
    majority_k: int,
    *,
    honest_fail: float = HONEST_FAIL_RATE,
    attack_fail: float = ATTACK_FAIL_RATE,
    sample_total: int = DEFAULT_SAMPLE_TOTAL,
    local_ok: int = 0,
    local_fail: int = 0,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """
    One victim / one honest subject / one gossip epoch.

    Neighbors: adv_count adversarial (ids < 0), remainder honest (ids >= 0).
    Coordinated eclipse (`eclipse_order=True`): adversaries report first so a
    pure-adv K-quorum can fire before honest adverts enter the buffer.
    """
    rng = rng or np.random.default_rng(0)
    n = max(int(n_neighbors), 1)
    k = max(int(majority_k), 1)
    adv_count = n_adversarial(n, f)
    honest_count = n - adv_count

    honest_obs = _counts_from_rate(honest_fail, sample_total)
    attack_obs = _counts_from_rate(attack_fail, sample_total)

    # Optional observation noise so trials are not bit-identical.
    def _noisy(obs: Tuple[int, int], is_attack: bool) -> Tuple[int, int]:
        ok, fail = obs
        jitter = int(rng.integers(-2, 3))
        fail2 = int(np.clip(fail + jitter, 0 if not is_attack else max(fail - 5, 0), sample_total))
        return sample_total - fail2, fail2

    reporters: List[Tuple[int, Tuple[int, int]]] = []
    for i in range(adv_count):
        reporters.append((-(i + 1), _noisy(attack_obs, True)))
    for i in range(honest_count):
        reporters.append((i, _noisy(honest_obs, False)))

    if eclipse_order:
        # adversaries first (coordinated), then honest
        pass
    else:
        order = np.arange(len(reporters))
        rng.shuffle(order)
        reporters = [reporters[j] for j in order]

    buf = GossipMergeBuffer(k)
    window_ok, window_fail = int(local_ok), int(local_fail)
    merges: List[Dict[str, Any]] = []
    pure_adv_merges = 0
    honest_included_merges = 0

    for reporter, (ok, fail) in reporters:
        status, med, have, honest_in = buf.ingest(reporter, ok, fail)
        if status != "applied" or med is None:
            continue
        mok, mfail = med
        median_rate = mfail / max(mok + mfail, 1)
        window_ok, window_fail = apply_gossip_half_weight(window_ok, window_fail, mok, mfail)
        pure = honest_in == 0
        if pure:
            pure_adv_merges += 1
        else:
            honest_included_merges += 1
        merges.append(
            {
                "reporters": have,
                "honest_in_merge": honest_in,
                "median_rate": median_rate,
                "pure_adversarial": pure,
            }
        )

    win_rate = failure_rate(window_ok, window_fail)
    # Pending honest-only leftover that never reached K this epoch.
    pending_honest = sum(1 for r in buf.pending if r >= 0)
    pending_adv = sum(1 for r in buf.pending if r < 0)

    return {
        "n_neighbors": n,
        "f": float(f),
        "majority_k": k,
        "adv_count": adv_count,
        "honest_count": honest_count,
        "true_fail_rate": float(honest_fail),
        "window_ok": window_ok,
        "window_fail": window_fail,
        "window_fail_rate": win_rate,
        "median_bias": None if win_rate is None else win_rate - float(honest_fail),
        "n_merges": len(merges),
        "pure_adv_merges": pure_adv_merges,
        "honest_included_merges": honest_included_merges,
        # Eclipse success: adversaries formed ≥1 pure-adv K-quorum this epoch
        # (honest may still merge later in the same epoch after the buffer clears).
        "eclipse_this_epoch": pure_adv_merges > 0,
        "honest_fully_suppressed": pure_adv_merges > 0 and honest_included_merges == 0,
        "pending_honest": pending_honest,
        "pending_adv": pending_adv,
        "false_probation": bool(
            win_rate is not None and win_rate >= FALSE_PROBATION_THRESHOLD
        ),
        "merges": merges,
    }


def simulate_trial(
    n_neighbors: int,
    f: float,
    majority_k: int,
    epochs: int = CI_EPOCHS,
    *,
    honest_fail: float = HONEST_FAIL_RATE,
    attack_fail: float = ATTACK_FAIL_RATE,
    local_samples_per_epoch: int = 0,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """Multi-epoch accumulation into one victim window for one honest subject."""
    rng = rng or np.random.default_rng(0)
    window_ok = 0
    window_fail = 0
    pure_adv = 0
    honest_merges = 0
    n_merges = 0
    eclipse_epochs = 0
    biases: List[float] = []

    for _ in range(max(int(epochs), 1)):
        local_ok = local_fail = 0
        if local_samples_per_epoch > 0:
            # Victim's own honest observations of the subject (not eclipsable).
            for _s in range(local_samples_per_epoch):
                if rng.random() < honest_fail:
                    local_fail += 1
                else:
                    local_ok += 1
        ep = simulate_victim_epoch(
            n_neighbors,
            f,
            majority_k,
            honest_fail=honest_fail,
            attack_fail=attack_fail,
            local_ok=local_ok,
            local_fail=local_fail,
            eclipse_order=eclipse_order,
            rng=rng,
        )
        window_ok += ep["window_ok"]
        window_fail += ep["window_fail"]
        pure_adv += ep["pure_adv_merges"]
        honest_merges += ep["honest_included_merges"]
        n_merges += ep["n_merges"]
        if ep["eclipse_this_epoch"]:
            eclipse_epochs += 1
        if ep["median_bias"] is not None:
            biases.append(float(ep["median_bias"]))

    win_rate = failure_rate(window_ok, window_fail)
    return {
        "window_fail_rate": win_rate,
        "median_bias": None if win_rate is None else win_rate - float(honest_fail),
        "mean_epoch_bias": float(np.mean(biases)) if biases else None,
        "false_probation": bool(
            win_rate is not None and win_rate >= FALSE_PROBATION_THRESHOLD
        ),
        "eclipse_epoch_fraction": eclipse_epochs / max(int(epochs), 1),
        "pure_adv_merge_fraction": (pure_adv / n_merges) if n_merges else 0.0,
        "honest_merge_fraction": (honest_merges / n_merges) if n_merges else 0.0,
        "n_merges": n_merges,
        "adv_count": n_adversarial(n_neighbors, f),
        "can_solo_quorum": n_adversarial(n_neighbors, f) >= max(int(majority_k), 1),
    }


def profile_cell(
    n_neighbors: int,
    f: float,
    majority_k: int,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    *,
    honest_fail: float = HONEST_FAIL_RATE,
    attack_fail: float = ATTACK_FAIL_RATE,
    local_samples_per_epoch: int = 0,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """Monte-Carlo metrics for one (N, f, K) cell."""
    rng = rng or np.random.default_rng(0)
    biases: List[float] = []
    fp = 0
    eclipse_fracs: List[float] = []
    pure_fracs: List[float] = []
    rates: List[float] = []

    for t in range(max(int(trials), 1)):
        trial_rng = np.random.default_rng(rng.integers(0, 2**31 - 1))
        out = simulate_trial(
            n_neighbors,
            f,
            majority_k,
            epochs=epochs,
            honest_fail=honest_fail,
            attack_fail=attack_fail,
            local_samples_per_epoch=local_samples_per_epoch,
            eclipse_order=eclipse_order,
            rng=trial_rng,
        )
        if out["median_bias"] is not None:
            biases.append(float(out["median_bias"]))
        if out["window_fail_rate"] is not None:
            rates.append(float(out["window_fail_rate"]))
        fp += int(out["false_probation"])
        eclipse_fracs.append(float(out["eclipse_epoch_fraction"]))
        pure_fracs.append(float(out["pure_adv_merge_fraction"]))

    adv = n_adversarial(n_neighbors, f)
    return {
        "n_neighbors": int(n_neighbors),
        "f": float(f),
        "majority_k": int(majority_k),
        "adv_count": adv,
        "honest_count": int(n_neighbors) - adv,
        "can_solo_quorum": adv >= max(int(majority_k), 1),
        "trials": int(trials),
        "epochs": int(epochs),
        "true_fail_rate": float(honest_fail),
        "attack_fail_rate": float(attack_fail),
        "mean_window_fail_rate": float(np.mean(rates)) if rates else None,
        "mean_median_bias": float(np.mean(biases)) if biases else None,
        "p50_median_bias": float(np.median(biases)) if biases else None,
        "p90_median_bias": float(np.percentile(biases, 90)) if biases else None,
        "false_probation_rate": fp / max(int(trials), 1),
        "mean_eclipse_epoch_fraction": float(np.mean(eclipse_fracs)) if eclipse_fracs else 0.0,
        "mean_pure_adv_merge_fraction": float(np.mean(pure_fracs)) if pure_fracs else 0.0,
        "false_probation_threshold": FALSE_PROBATION_THRESHOLD,
        "gossip_weight": GOSSIP_WEIGHT,
    }


def sweep_profiles(
    f_grid: Sequence[float] = CI_F_GRID,
    k_grid: Sequence[int] = CI_K_GRID,
    n_grid: Sequence[int] = CI_N_GRID,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    *,
    honest_fail: float = HONEST_FAIL_RATE,
    attack_fail: float = ATTACK_FAIL_RATE,
    local_samples_per_epoch: int = 0,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> List[Dict[str, Any]]:
    rng = rng or np.random.default_rng(0)
    cells: List[Dict[str, Any]] = []
    for n in n_grid:
        for k in k_grid:
            for f in f_grid:
                cells.append(
                    profile_cell(
                        n,
                        f,
                        k,
                        trials=trials,
                        epochs=epochs,
                        honest_fail=honest_fail,
                        attack_fail=attack_fail,
                        local_samples_per_epoch=local_samples_per_epoch,
                        eclipse_order=eclipse_order,
                        rng=rng,
                    )
                )
    return cells


def _key_slices(cells: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Highlight operator-relevant slices for the artifact summary."""
    def find(n: int, f: float, k: int) -> Optional[Mapping[str, Any]]:
        for c in cells:
            if c["n_neighbors"] == n and c["majority_k"] == k and abs(c["f"] - f) < 1e-9:
                return c
        return None

    highlights = []
    for n, f, k, note in (
        (8, 0.0, 2, "baseline honest neighbors, production default K"),
        (8, 0.5, 2, "half adversarial; K=2 solo-quorum possible"),
        (8, 1.0, 2, "full eclipse of neighbor set"),
        (8, 0.125, 3, "1 adv of 8; K=3 honest-majority median resists"),
        (8, 0.25, 3, "2 adv of 8; cannot solo K=3 but 2-of-3 median still attack"),
        (12, 0.5, 3, "mid-size peer table, K=3"),
        (4, 1.0, 1, "lab majority_k=1 under full eclipse"),
    ):
        cell = find(n, f, k)
        if cell is None:
            continue
        highlights.append(
            {
                "note": note,
                "n_neighbors": n,
                "f": f,
                "majority_k": k,
                "mean_median_bias": cell["mean_median_bias"],
                "false_probation_rate": cell["false_probation_rate"],
                "mean_eclipse_epoch_fraction": cell["mean_eclipse_epoch_fraction"],
                "can_solo_quorum": cell["can_solo_quorum"],
            }
        )
    return {"highlights": highlights}


def gossip_eclipse_report(
    *,
    f_grid: Sequence[float] = CI_F_GRID,
    k_grid: Sequence[int] = CI_K_GRID,
    n_grid: Sequence[int] = CI_N_GRID,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    include_offline: bool = False,
    offline_f_grid: Sequence[float] = OFFLINE_F_GRID,
    offline_k_grid: Sequence[int] = OFFLINE_K_GRID,
    offline_n_grid: Sequence[int] = OFFLINE_N_GRID,
    offline_trials: int = OFFLINE_TRIALS,
    offline_epochs: int = OFFLINE_EPOCHS,
    honest_fail: float = HONEST_FAIL_RATE,
    attack_fail: float = ATTACK_FAIL_RATE,
    seed: int = 20260718,
) -> Dict[str, Any]:
    """CI (+ optional offline) characterization report."""
    rng = np.random.default_rng(seed)
    cells = sweep_profiles(
        f_grid=f_grid,
        k_grid=k_grid,
        n_grid=n_grid,
        trials=trials,
        epochs=epochs,
        honest_fail=honest_fail,
        attack_fail=attack_fail,
        eclipse_order=True,
        rng=rng,
    )

    # Analytical: when adv >= K, coordinated eclipse yields median ≈ attack_fail.
    # Half-weight alone does not change the *rate* (ratio preserved); bias vs true
    # is therefore ≈ attack_fail - honest_fail when pure-adv merges dominate.
    expected_pure_bias = float(attack_fail) - float(honest_fail)

    report: Dict[str, Any] = {
        "status": "[O] QUANTIFIED",
        "claim_closed": False,
        "multi_org_bft": "External",
        "wave": "C1",
        "model": {
            "description": (
                "Victim with N peer-table neighbors; fraction f adversarial; "
                "majority_k=K distinct reporters before median merge at half weight. "
                "Coordinated eclipse: adversaries report first each epoch."
            ),
            "rust_fidelity": [
                "PeerHealthTracker::ingest_gossip_observation",
                "median_outcome_counts",
                "apply_gossip_outcomes GOSSIP_WEIGHT=1/2",
            ],
            "honest_fail_rate": honest_fail,
            "attack_fail_rate": attack_fail,
            "false_probation_threshold": FALSE_PROBATION_THRESHOLD,
            "gossip_weight": GOSSIP_WEIGHT,
            "expected_pure_adv_bias": expected_pure_bias,
        },
        "grids": {
            "f": list(f_grid),
            "majority_k": list(k_grid),
            "n_neighbors": list(n_grid),
            "trials": trials,
            "epochs": epochs,
        },
        "cells": cells,
        "summary": _key_slices(cells),
        "findings": [
            (
                "When adv_count >= K under coordinated eclipse, adversaries fire "
                "pure-adv median merges before honest reporters enter the buffer; "
                "half-weight preserves the attack failure ratio."
            ),
            (
                "Raising K above adv_count blocks *solo* (pure-adv) quorum. It does "
                "not by itself guarantee a low median: if adversaries hold a majority "
                "inside a mixed K-set (e.g. 2-of-3), the median remains attack-rate."
            ),
            (
                "Honest-majority quorums (adv_count < ceil(K/2) in the merge set) "
                "keep mean_median_bias near zero — the intended majority_k benefit."
            ),
            (
                "majority_k=1 (lab) applies every adversarial advert immediately — "
                "highest false_probation under any f>0."
            ),
            (
                "Multi-org BFT reputation consensus remains External; this sim only "
                "quantifies single-victim peer-table eclipse within one org."
            ),
        ],
        "residuals": [
            "K colluding admitted neighbors still shift the median (not BFT).",
            "No cross-relay global quorum / multi-org BFT.",
            "Clock skew / replay within age window not modeled.",
            "AnomalyDetector z-score demotion approximated by fail-rate threshold.",
        ],
    }

    if include_offline:
        off_rng = np.random.default_rng(seed + 1)
        off_cells = sweep_profiles(
            f_grid=offline_f_grid,
            k_grid=offline_k_grid,
            n_grid=offline_n_grid,
            trials=offline_trials,
            epochs=offline_epochs,
            honest_fail=honest_fail,
            attack_fail=attack_fail,
            eclipse_order=True,
            rng=off_rng,
        )
        report["offline"] = {
            "grids": {
                "f": list(offline_f_grid),
                "majority_k": list(offline_k_grid),
                "n_neighbors": list(offline_n_grid),
                "trials": offline_trials,
                "epochs": offline_epochs,
            },
            "cells": off_cells,
            "summary": _key_slices(off_cells),
        }
    return report


def write_artifact(path: Path, report: Mapping[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path


def cell_lookup(
    cells: Iterable[Mapping[str, Any]], n: int, f: float, k: int
) -> Mapping[str, Any]:
    for c in cells:
        if c["n_neighbors"] == n and c["majority_k"] == k and abs(c["f"] - f) < 1e-9:
            return c
    raise KeyError(f"no cell n={n} f={f} k={k}")
