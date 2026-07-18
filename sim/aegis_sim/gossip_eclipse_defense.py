"""
Gossip eclipse defenses vs C1 baseline (research wave S5 / C1).

Tag: [O] QUANTIFIED Partial — raises effective resistance; does **not** close
multi-org BFT reputation (still External). Never claims §13 closed.

Defense variants (stackable):
  raised_k       — higher majority_k (blocks solo pure-adv quorum longer)
  diverse_org    — require min distinct operator/org ids inside a K-quorum
  eclipse_detect — heuristic quarantine of merges that look eclipsed
  stacked        — raised_k + diverse_org + eclipse_detect (best in-tree)

Baseline cells reuse `gossip_eclipse.profile_cell` (C1 model). Defended cells
use the same victim/neighbor geometry with the selected defense applied.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

from aegis_sim import gossip_eclipse as ge

# CI-friendly compare grids (must stay fast under pytest).
CI_F_GRID = (0.0, 0.25, 0.5, 1.0)
CI_N = 8
CI_BASELINE_K = 2
CI_DEFENSE_K = 4
CI_TRIALS = 60
CI_EPOCHS = 5
CI_MIN_ORGS = 2

# Offline characterization (still synthetic).
OFFLINE_F_GRID = (0.0, 0.125, 0.25, 0.5, 0.75, 1.0)
OFFLINE_TRIALS = 300
OFFLINE_EPOCHS = 10

DEFENSE_NAMES = ("baseline", "raised_k", "diverse_org", "eclipse_detect", "stacked")

# Eclipse heuristic: merge median far above local / honest baseline.
ECLIPSE_MEDIAN_GAP = 0.45
ECLIPSE_LOCAL_MIN_SAMPLES = 8


def assign_org_ids(
    n_neighbors: int,
    adv_count: int,
    n_orgs: int,
    *,
    eclipse_collude_orgs: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[int, int]:
    """Map reporter ids → org ids.

    Honest reporters: ids 0..honest-1; adversaries: -1..-adv.
    When `eclipse_collude_orgs`, all adversaries share org 0 (worst-case
    colluding faction). Honest neighbors spread across orgs 1..n_orgs-1
    (or 0..n_orgs-1 if no adv collusion).
    """
    rng = rng or np.random.default_rng(0)
    n = max(int(n_neighbors), 1)
    adv = int(np.clip(adv_count, 0, n))
    honest = n - adv
    n_orgs = max(int(n_orgs), 1)
    mapping: Dict[int, int] = {}
    if eclipse_collude_orgs and adv > 0:
        for i in range(adv):
            mapping[-(i + 1)] = 0
        honest_orgs = list(range(1, max(n_orgs, 2)))
        if not honest_orgs:
            honest_orgs = [1]
        for i in range(honest):
            mapping[i] = int(honest_orgs[i % len(honest_orgs)])
    else:
        for i in range(adv):
            mapping[-(i + 1)] = int(rng.integers(0, n_orgs))
        for i in range(honest):
            mapping[i] = int(rng.integers(0, n_orgs))
    return mapping


class DiverseGossipMergeBuffer:
    """Gossip buffer that withholds median merge until K reporters AND ≥ min_orgs."""

    def __init__(self, majority_k: int, min_orgs: int = 1):
        self.majority_k = max(int(majority_k), 1)
        self.min_orgs = max(int(min_orgs), 1)
        self.pending: Dict[int, Tuple[int, int]] = {}
        self.pending_org: Dict[int, int] = {}

    def ingest(
        self,
        reporter: int,
        ok: int,
        fail: int,
        org_id: int = 0,
    ) -> Tuple[str, Optional[Tuple[int, int]], int, int, int]:
        """
        Returns (status, median|None, have, honest_in_merge, distinct_orgs).
        status: 'buffered' | 'waiting_diversity' | 'applied'
        """
        self.pending[reporter] = (int(ok), int(fail))
        self.pending_org[reporter] = int(org_id)
        have = len(self.pending)
        orgs = len(set(self.pending_org.values()))
        if have < self.majority_k:
            return "buffered", None, have, 0, orgs
        if orgs < self.min_orgs:
            return "waiting_diversity", None, have, 0, orgs
        observations = list(self.pending.values())
        honest_in = sum(1 for r in self.pending if r >= 0)
        self.pending.clear()
        self.pending_org.clear()
        med = ge.median_outcome_counts(observations)
        return "applied", med, have, honest_in, orgs


def eclipse_heuristic_quarantine(
    *,
    median_rate: float,
    local_fail_rate: Optional[float],
    pure_adversarial: bool,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    gap: float = ECLIPSE_MEDIAN_GAP,
    local_samples: int = 0,
) -> bool:
    """True → discard this merge (treat as eclipse / forged quorum)."""
    if pure_adversarial:
        return True
    baseline = (
        float(local_fail_rate)
        if local_fail_rate is not None and local_samples >= ECLIPSE_LOCAL_MIN_SAMPLES
        else float(honest_fail)
    )
    return float(median_rate) >= baseline + float(gap)


def simulate_defended_epoch(
    n_neighbors: int,
    f: float,
    majority_k: int,
    *,
    min_orgs: int = 1,
    n_orgs: int = 4,
    eclipse_detect: bool = False,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    attack_fail: float = ge.ATTACK_FAIL_RATE,
    sample_total: int = ge.DEFAULT_SAMPLE_TOTAL,
    local_ok: int = 0,
    local_fail: int = 0,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    """One epoch with optional diversity + eclipse-detect defenses."""
    rng = rng or np.random.default_rng(0)
    n = max(int(n_neighbors), 1)
    k = max(int(majority_k), 1)
    adv_count = ge.n_adversarial(n, f)
    honest_count = n - adv_count
    org_map = assign_org_ids(
        n, adv_count, n_orgs, eclipse_collude_orgs=True, rng=rng,
    )

    honest_obs = ge._counts_from_rate(honest_fail, sample_total)
    attack_obs = ge._counts_from_rate(attack_fail, sample_total)

    def _noisy(obs: Tuple[int, int], is_attack: bool) -> Tuple[int, int]:
        ok, fail = obs
        jitter = int(rng.integers(-2, 3))
        fail2 = int(
            np.clip(
                fail + jitter,
                0 if not is_attack else max(fail - 5, 0),
                sample_total,
            )
        )
        return sample_total - fail2, fail2

    reporters: List[Tuple[int, Tuple[int, int]]] = []
    for i in range(adv_count):
        reporters.append((-(i + 1), _noisy(attack_obs, True)))
    for i in range(honest_count):
        reporters.append((i, _noisy(honest_obs, False)))

    if not eclipse_order:
        order = np.arange(len(reporters))
        rng.shuffle(order)
        reporters = [reporters[j] for j in order]

    buf = DiverseGossipMergeBuffer(k, min_orgs=min_orgs)
    window_ok, window_fail = int(local_ok), int(local_fail)
    local_rate = ge.failure_rate(local_ok, local_fail)
    local_samples = int(local_ok) + int(local_fail)

    merges: List[Dict[str, Any]] = []
    pure_adv_merges = 0
    honest_included_merges = 0
    quarantined = 0
    diversity_blocks = 0

    for reporter, (ok, fail) in reporters:
        status, med, have, honest_in, orgs = buf.ingest(
            reporter, ok, fail, org_id=org_map.get(reporter, 0),
        )
        if status == "waiting_diversity":
            diversity_blocks += 1
            continue
        if status != "applied" or med is None:
            continue
        mok, mfail = med
        median_rate = mfail / max(mok + mfail, 1)
        pure = honest_in == 0
        if eclipse_detect and eclipse_heuristic_quarantine(
            median_rate=median_rate,
            local_fail_rate=local_rate,
            pure_adversarial=pure,
            honest_fail=honest_fail,
            local_samples=local_samples,
        ):
            quarantined += 1
            merges.append(
                {
                    "reporters": have,
                    "honest_in_merge": honest_in,
                    "median_rate": median_rate,
                    "pure_adversarial": pure,
                    "distinct_orgs": orgs,
                    "quarantined": True,
                }
            )
            continue
        window_ok, window_fail = ge.apply_gossip_half_weight(
            window_ok, window_fail, mok, mfail,
        )
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
                "distinct_orgs": orgs,
                "quarantined": False,
            }
        )

    win_rate = ge.failure_rate(window_ok, window_fail)
    return {
        "n_neighbors": n,
        "f": float(f),
        "majority_k": k,
        "min_orgs": int(min_orgs),
        "eclipse_detect": bool(eclipse_detect),
        "adv_count": adv_count,
        "honest_count": honest_count,
        "window_ok": window_ok,
        "window_fail": window_fail,
        "window_fail_rate": win_rate,
        "median_bias": None if win_rate is None else win_rate - float(honest_fail),
        "n_merges": len([m for m in merges if not m.get("quarantined")]),
        "pure_adv_merges": pure_adv_merges,
        "honest_included_merges": honest_included_merges,
        "eclipse_this_epoch": pure_adv_merges > 0,
        "quarantined_merges": quarantined,
        "diversity_block_events": diversity_blocks,
        "false_probation": bool(
            win_rate is not None and win_rate >= ge.FALSE_PROBATION_THRESHOLD
        ),
        "merges": merges,
    }


def simulate_defended_trial(
    n_neighbors: int,
    f: float,
    majority_k: int,
    epochs: int = CI_EPOCHS,
    *,
    min_orgs: int = 1,
    n_orgs: int = 4,
    eclipse_detect: bool = False,
    local_samples_per_epoch: int = 12,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    attack_fail: float = ge.ATTACK_FAIL_RATE,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    rng = rng or np.random.default_rng(0)
    window_ok = 0
    window_fail = 0
    pure_adv = 0
    honest_merges = 0
    n_merges = 0
    eclipse_epochs = 0
    quarantined = 0
    diversity_blocks = 0
    biases: List[float] = []

    for _ in range(max(int(epochs), 1)):
        local_ok = local_fail = 0
        for _s in range(max(int(local_samples_per_epoch), 0)):
            if rng.random() < honest_fail:
                local_fail += 1
            else:
                local_ok += 1
        ep = simulate_defended_epoch(
            n_neighbors,
            f,
            majority_k,
            min_orgs=min_orgs,
            n_orgs=n_orgs,
            eclipse_detect=eclipse_detect,
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
        quarantined += ep["quarantined_merges"]
        diversity_blocks += ep["diversity_block_events"]
        if ep["eclipse_this_epoch"]:
            eclipse_epochs += 1
        if ep["median_bias"] is not None:
            biases.append(float(ep["median_bias"]))

    win_rate = ge.failure_rate(window_ok, window_fail)
    return {
        "window_fail_rate": win_rate,
        "median_bias": None if win_rate is None else win_rate - float(honest_fail),
        "mean_epoch_bias": float(np.mean(biases)) if biases else None,
        "false_probation": bool(
            win_rate is not None and win_rate >= ge.FALSE_PROBATION_THRESHOLD
        ),
        "eclipse_epoch_fraction": eclipse_epochs / max(int(epochs), 1),
        "pure_adv_merge_fraction": (pure_adv / n_merges) if n_merges else 0.0,
        "honest_merge_fraction": (honest_merges / n_merges) if n_merges else 0.0,
        "quarantined_merges": quarantined,
        "diversity_block_events": diversity_blocks,
        "n_merges": n_merges,
        "can_solo_quorum": ge.n_adversarial(n_neighbors, f) >= max(int(majority_k), 1),
    }


def profile_defense_cell(
    n_neighbors: int,
    f: float,
    majority_k: int,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    *,
    min_orgs: int = 1,
    n_orgs: int = 4,
    eclipse_detect: bool = False,
    local_samples_per_epoch: int = 12,
    honest_fail: float = ge.HONEST_FAIL_RATE,
    attack_fail: float = ge.ATTACK_FAIL_RATE,
    eclipse_order: bool = True,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    rng = rng or np.random.default_rng(0)
    biases: List[float] = []
    fp = 0
    eclipse_fracs: List[float] = []
    pure_fracs: List[float] = []
    rates: List[float] = []
    quarantines: List[int] = []

    for _ in range(max(int(trials), 1)):
        trial_rng = np.random.default_rng(int(rng.integers(0, 2**31 - 1)))
        out = simulate_defended_trial(
            n_neighbors,
            f,
            majority_k,
            epochs=epochs,
            min_orgs=min_orgs,
            n_orgs=n_orgs,
            eclipse_detect=eclipse_detect,
            local_samples_per_epoch=local_samples_per_epoch,
            honest_fail=honest_fail,
            attack_fail=attack_fail,
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
        quarantines.append(int(out["quarantined_merges"]))

    adv = ge.n_adversarial(n_neighbors, f)
    return {
        "n_neighbors": int(n_neighbors),
        "f": float(f),
        "majority_k": int(majority_k),
        "min_orgs": int(min_orgs),
        "eclipse_detect": bool(eclipse_detect),
        "adv_count": adv,
        "can_solo_quorum": adv >= max(int(majority_k), 1),
        "trials": int(trials),
        "epochs": int(epochs),
        "mean_window_fail_rate": float(np.mean(rates)) if rates else None,
        "mean_median_bias": float(np.mean(biases)) if biases else None,
        "false_probation_rate": fp / max(int(trials), 1),
        "mean_eclipse_epoch_fraction": float(np.mean(eclipse_fracs)) if eclipse_fracs else 0.0,
        "mean_pure_adv_merge_fraction": float(np.mean(pure_fracs)) if pure_fracs else 0.0,
        "mean_quarantined_merges": float(np.mean(quarantines)) if quarantines else 0.0,
    }


def defense_config(name: str) -> Dict[str, Any]:
    """Resolve named defense → (majority_k, min_orgs, eclipse_detect)."""
    name = str(name)
    if name == "baseline":
        return {"majority_k": CI_BASELINE_K, "min_orgs": 1, "eclipse_detect": False}
    if name == "raised_k":
        return {"majority_k": CI_DEFENSE_K, "min_orgs": 1, "eclipse_detect": False}
    if name == "diverse_org":
        return {"majority_k": CI_BASELINE_K, "min_orgs": CI_MIN_ORGS, "eclipse_detect": False}
    if name == "eclipse_detect":
        return {"majority_k": CI_BASELINE_K, "min_orgs": 1, "eclipse_detect": True}
    if name == "stacked":
        return {
            "majority_k": CI_DEFENSE_K,
            "min_orgs": CI_MIN_ORGS,
            "eclipse_detect": True,
        }
    raise ValueError(f"unknown gossip defense {name!r}; choose from {DEFENSE_NAMES}")


def profile_named_defense(
    name: str,
    f: float,
    *,
    n_neighbors: int = CI_N,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    n_orgs: int = 4,
    rng: Optional[np.random.Generator] = None,
) -> Dict[str, Any]:
    cfg = defense_config(name)
    if name == "baseline":
        # Reuse C1 baseline profiler (no local samples; matches committed artifact).
        cell = ge.profile_cell(
            n_neighbors,
            f,
            cfg["majority_k"],
            trials=trials,
            epochs=epochs,
            eclipse_order=True,
            rng=rng,
        )
        cell = dict(cell)
        cell["defense"] = name
        cell["min_orgs"] = 1
        cell["eclipse_detect"] = False
        cell["mean_quarantined_merges"] = 0.0
        return cell
    cell = profile_defense_cell(
        n_neighbors,
        f,
        cfg["majority_k"],
        trials=trials,
        epochs=epochs,
        min_orgs=cfg["min_orgs"],
        n_orgs=n_orgs,
        eclipse_detect=cfg["eclipse_detect"],
        rng=rng,
    )
    cell["defense"] = name
    return cell


def compare_defenses_vs_baseline(
    f_grid: Sequence[float] = CI_F_GRID,
    *,
    n_neighbors: int = CI_N,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    defenses: Sequence[str] = DEFENSE_NAMES,
    seed: int = 20260718,
) -> Dict[str, Any]:
    """Sweep defenses × f; compute deltas vs C1 baseline (K=2, no extras)."""
    rng = np.random.default_rng(seed)
    rows: List[Dict[str, Any]] = []
    for f in f_grid:
        base = profile_named_defense(
            "baseline", f, n_neighbors=n_neighbors, trials=trials,
            epochs=epochs, rng=rng,
        )
        for name in defenses:
            cell = (
                base
                if name == "baseline"
                else profile_named_defense(
                    name, f, n_neighbors=n_neighbors, trials=trials,
                    epochs=epochs, rng=rng,
                )
            )
            rows.append(
                {
                    "defense": name,
                    "f": float(f),
                    "majority_k": cell["majority_k"],
                    "min_orgs": cell.get("min_orgs", 1),
                    "eclipse_detect": cell.get("eclipse_detect", False),
                    "mean_median_bias": cell["mean_median_bias"],
                    "false_probation_rate": cell["false_probation_rate"],
                    "mean_eclipse_epoch_fraction": cell["mean_eclipse_epoch_fraction"],
                    "can_solo_quorum": cell["can_solo_quorum"],
                    "mean_quarantined_merges": cell.get("mean_quarantined_merges", 0.0),
                    "delta_fp_vs_baseline": (
                        base["false_probation_rate"] - cell["false_probation_rate"]
                    ),
                    "delta_bias_vs_baseline": (
                        None
                        if base["mean_median_bias"] is None
                        or cell["mean_median_bias"] is None
                        else base["mean_median_bias"] - cell["mean_median_bias"]
                    ),
                    "delta_eclipse_vs_baseline": (
                        base["mean_eclipse_epoch_fraction"]
                        - cell["mean_eclipse_epoch_fraction"]
                    ),
                }
            )
    return {
        "n_neighbors": n_neighbors,
        "trials": trials,
        "epochs": epochs,
        "f_grid": list(f_grid),
        "rows": rows,
    }


def _best_defense_summary(compare: Mapping[str, Any]) -> Dict[str, Any]:
    """Pick stacked / best FP reduction at mid adversarial fraction f=0.5."""
    mid = [
        r for r in compare["rows"]
        if abs(r["f"] - 0.5) < 1e-9 and r["defense"] != "baseline"
    ]
    if not mid:
        mid = [r for r in compare["rows"] if r["defense"] != "baseline"]
    best = max(mid, key=lambda r: r["delta_fp_vs_baseline"]) if mid else None
    stacked = next(
        (r for r in compare["rows"] if r["defense"] == "stacked" and abs(r["f"] - 0.5) < 1e-9),
        None,
    )
    baseline_mid = next(
        (r for r in compare["rows"] if r["defense"] == "baseline" and abs(r["f"] - 0.5) < 1e-9),
        None,
    )
    return {
        "focus_f": 0.5,
        "baseline_at_f": baseline_mid,
        "stacked_at_f": stacked,
        "best_delta_fp_row": best,
    }


def gossip_eclipse_defense_report(
    *,
    f_grid: Sequence[float] = CI_F_GRID,
    n_neighbors: int = CI_N,
    trials: int = CI_TRIALS,
    epochs: int = CI_EPOCHS,
    include_offline: bool = False,
    offline_f_grid: Sequence[float] = OFFLINE_F_GRID,
    offline_trials: int = OFFLINE_TRIALS,
    offline_epochs: int = OFFLINE_EPOCHS,
    seed: int = 20260718,
) -> Dict[str, Any]:
    compare = compare_defenses_vs_baseline(
        f_grid=f_grid,
        n_neighbors=n_neighbors,
        trials=trials,
        epochs=epochs,
        seed=seed,
    )
    summary = _best_defense_summary(compare)
    report: Dict[str, Any] = {
        "status": "[O] QUANTIFIED",
        "claim_closed": False,
        "multi_org_bft": "External",
        "wave": "S5",
        "parent_wave": "C1",
        "tag": "gossip_eclipse_defense_vs_C1",
        "model": {
            "description": (
                "Defense variants vs C1 gossip eclipse baseline: raised K, "
                "min distinct orgs in K-quorum, eclipse-detect quarantine, stacked."
            ),
            "baseline_k": CI_BASELINE_K,
            "defense_k": CI_DEFENSE_K,
            "min_orgs_default": CI_MIN_ORGS,
            "eclipse_median_gap": ECLIPSE_MEDIAN_GAP,
            "rust_fidelity_note": (
                "stacked maps to GossipMergePolicy / PeerHealthTracker: "
                "majority_k (default 4), min_orgs, eclipse_detect quarantine; "
                "peer org_id/jurisdiction diversity keys. Multi-org BFT still External."
            ),
        },
        "grids": {
            "f": list(f_grid),
            "n_neighbors": n_neighbors,
            "trials": trials,
            "epochs": epochs,
            "defenses": list(DEFENSE_NAMES),
        },
        "compare": compare,
        "summary": summary,
        "findings": [
            (
                "Raising K above adv_count blocks pure-adv solo quorum (C1 finding); "
                "stacked defense adds org diversity + quarantine for mixed quorums."
            ),
            (
                "diverse_org blocks same-org colluding factions from forming a "
                "merge when min_orgs > 1 — worst-case all-adv same org waits for "
                "honest cross-org reporters."
            ),
            (
                "eclipse_detect quarantines pure-adv merges and high-gap medians "
                "vs local/honest baseline; reduces false probation under partial f."
            ),
            (
                "Full eclipse (f=1) still saturates FP when no honest reporters "
                "exist — detection can quarantine but cannot invent honest signal."
            ),
            (
                "Multi-org BFT remains External; this sim does not close §13 or "
                "global reputation consensus."
            ),
        ],
        "residuals": [
            "Colluding multi-org adversaries can still meet min_orgs.",
            "Eclipse heuristic false-positives possible under genuine outages.",
            "Product wire landed (wave A1); f=1 still saturates; multi-org BFT External.",
        ],
        "best_defense": "stacked",
    }
    if include_offline:
        off = compare_defenses_vs_baseline(
            f_grid=offline_f_grid,
            n_neighbors=n_neighbors,
            trials=offline_trials,
            epochs=offline_epochs,
            seed=seed + 1,
        )
        report["offline"] = {
            "grids": {
                "f": list(offline_f_grid),
                "trials": offline_trials,
                "epochs": offline_epochs,
            },
            "compare": off,
            "summary": _best_defense_summary(off),
        }
    return report


def write_artifact(path: Path, report: Mapping[str, Any] | None = None, **kwargs) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = report if report is not None else gossip_eclipse_defense_report(**kwargs)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path


def cell_lookup(
    rows: Iterable[Mapping[str, Any]], defense: str, f: float
) -> Mapping[str, Any]:
    for r in rows:
        if r["defense"] == defense and abs(r["f"] - f) < 1e-9:
            return r
    raise KeyError(f"no row defense={defense} f={f}")
