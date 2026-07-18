"""
Coarse metrics scrape side-channel profiling (partial, lab model).

Models an observer with access to exported ``RelayCoarseStats`` and
``IngressRateLimitStats`` counters (not ``RelayDebugStats``). Quantifies how
much attack **volume** and coarse **timing** leak through scrape *deltas* under
flood vs paced baseline — honest correlation / KS metrics, not info-theoretic
mutual information bounds.

Maps to Rust:
  - ``aegis_relay::node::RelayCoarseStats``
  - ``aegis_relay::net::IngressRateLimitStats``
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np

from aegis_sim.cover_timing import SPHINX_FRAGMENT_COUNT

# Match aegis-relay Mode-1 defaults (net.rs).
MODE1_TAU_SECS = 0.35
DEFAULT_INGRESS_MAX_CELLS_PER_SEC = 1.0 / MODE1_TAU_SECS
DEFAULT_INGRESS_BURST = 4
DEFAULT_EXPECTED_INGRESS_CLIENTS = 8.0
DEFAULT_GLOBAL_MAX_CELLS_PER_SEC = DEFAULT_EXPECTED_INGRESS_CLIENTS / MODE1_TAU_SECS

Scenario = Literal["baseline_paced", "flood_attack", "cover_bulk_round"]

DISCLAIMER = (
    "Partial scrape side-channel characterization — not an info-theoretic "
    "leakage bound. Models coarse RelayCoarseStats + IngressRateLimitStats "
    "deltas under lab flood/cover; debug_stats assumed not exported."
)


@dataclass
class RelayCoarseStats:
    """Mirrors exported coarse relay counters."""

    processed_ok: int = 0
    processed_fail: int = 0
    cover_emitted: int = 0
    queue_dropped: int = 0

    def failure_rate(self) -> float | None:
        total = self.processed_ok + self.processed_fail
        if total == 0:
            return None
        return self.processed_fail / total


@dataclass
class IngressRateLimitStats:
    """Mirrors coarse ingress drop counter."""

    dropped_frames: int = 0


@dataclass
class TokenBucket:
    rate: float
    burst: float
    tokens: float
    last_t: float

    def allow(self, t: float, n: float = 1.0) -> bool:
        if self.rate <= 0:
            return True
        dt = max(0.0, t - self.last_t)
        self.tokens = min(self.burst, self.tokens + dt * self.rate)
        self.last_t = t
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


def _pearson(a: np.ndarray, b: np.ndarray) -> float:
    if a.size < 2 or b.size < 2 or a.size != b.size:
        return float("nan")
    sa, sb = float(a.std()), float(b.std())
    if sa < 1e-15 or sb < 1e-15:
        return float("nan")
    return float(np.corrcoef(a, b)[0, 1])


def _ks_distance(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return float("nan")
    a_sorted = np.sort(a)
    b_sorted = np.sort(b)
    all_vals = np.sort(np.concatenate([a_sorted, b_sorted]))
    cdf_a = np.searchsorted(a_sorted, all_vals, side="right") / a.size
    cdf_b = np.searchsorted(b_sorted, all_vals, side="right") / b.size
    return float(np.max(np.abs(cdf_a - cdf_b)))


def _try_admit(
    t: float,
    n_cells: int,
    local: TokenBucket,
    global_bucket: TokenBucket | None,
) -> tuple[int, int]:
    """Return (accepted, dropped) for n_cells attempts on one connection."""
    accepted = 0
    dropped = 0
    for _ in range(n_cells):
        if not local.allow(t, 1.0):
            dropped += 1
            continue
        if global_bucket is not None and global_bucket.rate > 0:
            if not global_bucket.allow(t, 1.0):
                # Local token already consumed; count as drop (silent shed).
                dropped += 1
                continue
        accepted += 1
    return accepted, dropped


def simulate_scrape_series(
    scenario: Scenario = "flood_attack",
    *,
    duration_secs: float = 30.0,
    scrape_interval_secs: float = 1.0,
    slot_secs: float = 0.05,
    tau_secs: float = MODE1_TAU_SECS,
    paced_clients: int = 2,
    attack_cells_per_sec: float = 40.0,
    cover_flows_per_sec: float = 0.0,
    max_cells_per_sec: float = DEFAULT_INGRESS_MAX_CELLS_PER_SEC,
    burst: int = DEFAULT_INGRESS_BURST,
    global_max_cells_per_sec: float = DEFAULT_GLOBAL_MAX_CELLS_PER_SEC,
    queue_capacity_packets_per_sec: float = 50.0,
    fail_fraction_baseline: float = 0.01,
    fail_fraction_under_flood: float = 0.08,
    seed: int = 11,
) -> dict[str, Any]:
    """
    Discrete-time lab model of ingress + coarse counters + periodic scrapes.

    Ground truth (not exported): offered attack cells / cover flows per slot.
    Observer sees only scrape deltas of coarse counters.
    """
    if scenario not in ("baseline_paced", "flood_attack", "cover_bulk_round"):
        raise ValueError(f"unknown scenario {scenario!r}")
    if scrape_interval_secs <= 0 or slot_secs <= 0 or duration_secs <= 0:
        raise ValueError("duration/scrape/slot must be positive")

    rng = np.random.default_rng(seed)
    n_slots = int(round(duration_secs / slot_secs))
    n_scrapes = max(1, int(round(duration_secs / scrape_interval_secs)))

    if scenario == "baseline_paced":
        attack_cells_per_sec = 0.0
        cover_flows_per_sec = 0.0
    elif scenario == "cover_bulk_round":
        attack_cells_per_sec = 0.0
        if cover_flows_per_sec <= 0:
            cover_flows_per_sec = 2.0
    elif scenario == "flood_attack" and attack_cells_per_sec <= 0:
        attack_cells_per_sec = 40.0

    has_attacker = attack_cells_per_sec > 0
    n_conn = paced_clients + (1 if has_attacker else 0)
    per_conn = [
        TokenBucket(
            rate=max_cells_per_sec,
            burst=float(burst),
            tokens=float(burst),
            last_t=0.0,
        )
        for _ in range(max(1, n_conn))
    ]
    global_bucket = TokenBucket(
        rate=global_max_cells_per_sec if global_max_cells_per_sec > 0 else 0.0,
        burst=max(float(burst) * max(1, n_conn), global_max_cells_per_sec * 0.5)
        if global_max_cells_per_sec > 0
        else 0.0,
        tokens=max(float(burst) * max(1, n_conn), global_max_cells_per_sec * 0.5)
        if global_max_cells_per_sec > 0
        else 0.0,
        last_t=0.0,
    )
    g_ref = global_bucket if global_bucket.rate > 0 else None

    offered_attack = np.zeros(n_slots, dtype=float)
    offered_paced = np.zeros(n_slots, dtype=float)
    offered_cover = np.zeros(n_slots, dtype=float)
    accepted = np.zeros(n_slots, dtype=float)
    dropped = np.zeros(n_slots, dtype=float)
    slot_ok = np.zeros(n_slots, dtype=float)
    slot_fail = np.zeros(n_slots, dtype=float)
    slot_queue = np.zeros(n_slots, dtype=float)
    slot_cover = np.zeros(n_slots, dtype=float)

    attack_start = 0.25 * duration_secs
    attack_end = 0.75 * duration_secs

    for i in range(n_slots):
        t = i * slot_secs
        # Expected paced cells this slot (~1/τ per client).
        paced_rate = paced_clients / tau_secs
        paced_offer = paced_rate * slot_secs
        offered_paced[i] = paced_offer

        atk = 0.0
        if has_attacker and attack_start <= t < attack_end:
            atk = attack_cells_per_sec * slot_secs
        offered_attack[i] = atk

        cov = cover_flows_per_sec * slot_secs
        offered_cover[i] = cov
        slot_cover[i] = cov

        adm = 0
        drop = 0

        # Paced clients: Poisson offers around mean.
        for c in range(paced_clients):
            mean_c = paced_offer / max(paced_clients, 1)
            n_try = int(rng.poisson(mean_c))
            a, d = _try_admit(t, n_try, per_conn[c], g_ref)
            adm += a
            drop += d

        if has_attacker:
            n_try = int(rng.poisson(atk))
            a, d = _try_admit(t, n_try, per_conn[paced_clients], g_ref)
            adm += a
            drop += d

        accepted[i] = adm
        dropped[i] = drop

        approx_packets = adm / float(SPHINX_FRAGMENT_COUNT)
        queue_room = queue_capacity_packets_per_sec * slot_secs
        q_drop = max(0.0, approx_packets - queue_room)
        processed = max(0.0, approx_packets - q_drop)
        fail_frac = (
            fail_fraction_under_flood if atk > 0 else fail_fraction_baseline
        )
        fail = min(processed, processed * fail_frac)
        slot_ok[i] = processed - fail
        slot_fail[i] = fail
        slot_queue[i] = q_drop

    cum_ok = np.cumsum(slot_ok)
    cum_fail = np.cumsum(slot_fail)
    cum_queue = np.cumsum(slot_queue)
    cum_cover = np.cumsum(slot_cover)
    cum_drop = np.cumsum(dropped)
    cum_atk = np.cumsum(offered_attack)
    cum_cov_gt = np.cumsum(offered_cover)

    scrape_times: list[float] = []
    delta_dropped: list[float] = []
    delta_ok: list[float] = []
    delta_fail: list[float] = []
    delta_cover: list[float] = []
    delta_queue: list[float] = []
    gt_attack_in_window: list[float] = []
    gt_cover_in_window: list[float] = []

    prev = dict(dropped=0.0, ok=0.0, fail=0.0, cover=0.0, queue=0.0, atk=0.0, cov=0.0)
    for s in range(n_scrapes):
        t_end = min(duration_secs, (s + 1) * scrape_interval_secs)
        idx = min(n_slots - 1, max(0, int(round(t_end / slot_secs)) - 1))
        cur = dict(
            dropped=float(cum_drop[idx]),
            ok=float(cum_ok[idx]),
            fail=float(cum_fail[idx]),
            cover=float(cum_cover[idx]),
            queue=float(cum_queue[idx]),
            atk=float(cum_atk[idx]),
            cov=float(cum_cov_gt[idx]),
        )
        scrape_times.append(t_end)
        delta_dropped.append(cur["dropped"] - prev["dropped"])
        delta_ok.append(cur["ok"] - prev["ok"])
        delta_fail.append(cur["fail"] - prev["fail"])
        delta_cover.append(cur["cover"] - prev["cover"])
        delta_queue.append(cur["queue"] - prev["queue"])
        gt_attack_in_window.append(cur["atk"] - prev["atk"])
        gt_cover_in_window.append(cur["cov"] - prev["cov"])
        prev = cur

    coarse = RelayCoarseStats(
        processed_ok=int(round(float(cum_ok[-1]))),
        processed_fail=int(round(float(cum_fail[-1]))),
        cover_emitted=int(round(float(cum_cover[-1]))),
        queue_dropped=int(round(float(cum_queue[-1]))),
    )
    ingress = IngressRateLimitStats(dropped_frames=int(round(float(cum_drop[-1]))))
    load_proxy = (
        np.asarray(delta_dropped, dtype=float)
        + np.asarray(delta_fail, dtype=float)
        + np.asarray(delta_queue, dtype=float)
    )

    return {
        "scenario": scenario,
        "duration_secs": duration_secs,
        "scrape_interval_secs": scrape_interval_secs,
        "tau_secs": tau_secs,
        "rate_limit": {
            "max_cells_per_sec": max_cells_per_sec,
            "burst": burst,
            "global_max_cells_per_sec": global_max_cells_per_sec,
        },
        "final_coarse": asdict(coarse),
        "final_ingress": asdict(ingress),
        "scrape_times": scrape_times,
        "deltas": {
            "dropped_frames": delta_dropped,
            "processed_ok": delta_ok,
            "processed_fail": delta_fail,
            "cover_emitted": delta_cover,
            "queue_dropped": delta_queue,
            "load_proxy": load_proxy.tolist(),
        },
        "ground_truth_windows": {
            "attack_cells": gt_attack_in_window,
            "cover_flows": gt_cover_in_window,
        },
        "totals": {
            "offered_attack_cells": float(offered_attack.sum()),
            "offered_paced_cells": float(offered_paced.sum()),
            "offered_cover_flows": float(offered_cover.sum()),
            "accepted_cells": float(accepted.sum()),
            "dropped_cells": float(dropped.sum()),
        },
    }


def leakage_metrics(series: dict[str, Any]) -> dict[str, Any]:
    """Honest volume/timing leakage scores from one scrape series."""
    d_drop = np.asarray(series["deltas"]["dropped_frames"], dtype=float)
    d_fail = np.asarray(series["deltas"]["processed_fail"], dtype=float)
    d_queue = np.asarray(series["deltas"]["queue_dropped"], dtype=float)
    d_cover = np.asarray(series["deltas"]["cover_emitted"], dtype=float)
    load = np.asarray(series["deltas"]["load_proxy"], dtype=float)
    gt_atk = np.asarray(series["ground_truth_windows"]["attack_cells"], dtype=float)
    gt_cov = np.asarray(series["ground_truth_windows"]["cover_flows"], dtype=float)

    offered_atk = float(series["totals"]["offered_attack_cells"])
    dropped_total = float(series["totals"]["dropped_cells"])
    recoverable = dropped_total / offered_atk if offered_atk > 1e-9 else 0.0

    return {
        "pearson_dropped_vs_attack": _pearson(d_drop, gt_atk),
        "pearson_load_proxy_vs_attack": _pearson(load, gt_atk),
        "pearson_fail_vs_attack": _pearson(d_fail, gt_atk),
        "pearson_queue_vs_attack": _pearson(d_queue, gt_atk),
        "pearson_cover_vs_cover_gt": _pearson(d_cover, gt_cov),
        "attack_volume_recoverable_via_drops": min(1.0, max(0.0, recoverable)),
        "mean_scrape_delta_dropped": float(d_drop.mean()) if d_drop.size else 0.0,
        "mean_scrape_delta_load_proxy": float(load.mean()) if load.size else 0.0,
        "max_scrape_delta_dropped": float(d_drop.max()) if d_drop.size else 0.0,
        "timing_leak_note": (
            "Pearson on scrape-window deltas vs ground-truth attack windows; "
            "high |r| ⇒ coarse timing of floods leaks via counters."
        ),
    }


def compare_scrape_scenarios(
    *,
    duration_secs: float = 30.0,
    scrape_interval_secs: float = 1.0,
    attack_cells_per_sec: float = 40.0,
    seed: int = 11,
) -> dict[str, Any]:
    """Baseline vs flood vs cover-round scrape leakage comparison."""
    baseline = simulate_scrape_series(
        "baseline_paced",
        duration_secs=duration_secs,
        scrape_interval_secs=scrape_interval_secs,
        seed=seed,
    )
    flood = simulate_scrape_series(
        "flood_attack",
        duration_secs=duration_secs,
        scrape_interval_secs=scrape_interval_secs,
        attack_cells_per_sec=attack_cells_per_sec,
        seed=seed,
    )
    cover = simulate_scrape_series(
        "cover_bulk_round",
        duration_secs=duration_secs,
        scrape_interval_secs=scrape_interval_secs,
        cover_flows_per_sec=2.0,
        seed=seed,
    )

    base_leak = leakage_metrics(baseline)
    flood_leak = leakage_metrics(flood)
    cover_leak = leakage_metrics(cover)

    base_load = np.asarray(baseline["deltas"]["load_proxy"], dtype=float)
    flood_load = np.asarray(flood["deltas"]["load_proxy"], dtype=float)
    base_drop = np.asarray(baseline["deltas"]["dropped_frames"], dtype=float)
    flood_drop = np.asarray(flood["deltas"]["dropped_frames"], dtype=float)

    return {
        "disclaimer": DISCLAIMER,
        "characterization": "partial_metrics_scrape_sidechannel",
        "claims_info_theoretic_leakage_bound": False,
        "debug_stats_exported": False,
        "duration_secs": duration_secs,
        "scrape_interval_secs": scrape_interval_secs,
        "baseline_paced": {
            "final_coarse": baseline["final_coarse"],
            "final_ingress": baseline["final_ingress"],
            "totals": baseline["totals"],
            "leakage": base_leak,
        },
        "flood_attack": {
            "final_coarse": flood["final_coarse"],
            "final_ingress": flood["final_ingress"],
            "totals": flood["totals"],
            "leakage": flood_leak,
        },
        "cover_bulk_round": {
            "final_coarse": cover["final_coarse"],
            "final_ingress": cover["final_ingress"],
            "totals": cover["totals"],
            "leakage": cover_leak,
        },
        "delta": {
            "ks_load_proxy_flood_vs_baseline": _ks_distance(flood_load, base_load),
            "ks_dropped_flood_vs_baseline": _ks_distance(flood_drop, base_drop),
            "flood_drop_total_minus_baseline": (
                flood["final_ingress"]["dropped_frames"]
                - baseline["final_ingress"]["dropped_frames"]
            ),
            "flood_cover_emitted_minus_baseline": (
                flood["final_coarse"]["cover_emitted"]
                - baseline["final_coarse"]["cover_emitted"]
            ),
            "cover_round_cover_emitted_minus_baseline": (
                cover["final_coarse"]["cover_emitted"]
                - baseline["final_coarse"]["cover_emitted"]
            ),
            "flood_attack_volume_recoverable_via_drops": flood_leak[
                "attack_volume_recoverable_via_drops"
            ],
            "flood_pearson_dropped_vs_attack": flood_leak["pearson_dropped_vs_attack"],
            "flood_pearson_load_proxy_vs_attack": flood_leak[
                "pearson_load_proxy_vs_attack"
            ],
            "note": (
                "IngressRateLimitStats.dropped_frames confirms excess attack volume "
                "to a metrics-capable observer; RelayCoarseStats load/fail/queue "
                "deltas provide a coarse timing envelope of the flood window."
            ),
        },
    }


def scrape_interval_sweep(
    intervals: tuple[float, ...] = (0.5, 1.0, 2.0, 5.0),
    *,
    duration_secs: float = 30.0,
    attack_cells_per_sec: float = 40.0,
    seed: int = 11,
) -> dict[str, Any]:
    """How scrape cadence trades timing resolution for still-usable volume leakage."""
    rows = []
    for iv in intervals:
        cmp_ = compare_scrape_scenarios(
            duration_secs=duration_secs,
            scrape_interval_secs=iv,
            attack_cells_per_sec=attack_cells_per_sec,
            seed=seed,
        )
        rows.append(
            {
                "scrape_interval_secs": iv,
                "ks_dropped_flood_vs_baseline": cmp_["delta"][
                    "ks_dropped_flood_vs_baseline"
                ],
                "attack_volume_recoverable_via_drops": cmp_["delta"][
                    "flood_attack_volume_recoverable_via_drops"
                ],
                "pearson_dropped_vs_attack": cmp_["delta"][
                    "flood_pearson_dropped_vs_attack"
                ],
                "pearson_load_proxy_vs_attack": cmp_["delta"][
                    "flood_pearson_load_proxy_vs_attack"
                ],
            }
        )
    return {
        "disclaimer": DISCLAIMER,
        "characterization": "scrape_interval_sweep",
        "claims_info_theoretic_leakage_bound": False,
        "rows": rows,
    }


def full_sidechannel_characterization_bundle(
    *,
    duration_secs: float = 30.0,
    scrape_interval_secs: float = 1.0,
    attack_cells_per_sec: float = 40.0,
    seed: int = 11,
) -> dict[str, Any]:
    primary = compare_scrape_scenarios(
        duration_secs=duration_secs,
        scrape_interval_secs=scrape_interval_secs,
        attack_cells_per_sec=attack_cells_per_sec,
        seed=seed,
    )
    sweep = scrape_interval_sweep(
        duration_secs=duration_secs,
        attack_cells_per_sec=attack_cells_per_sec,
        seed=seed,
    )
    return {
        "disclaimer": DISCLAIMER,
        "claims_info_theoretic_leakage_bound": False,
        "debug_stats_exported": False,
        "primary": primary,
        "scrape_interval_sweep": sweep,
        "delta": primary["delta"],
        "baseline_paced": primary["baseline_paced"],
        "flood_attack": primary["flood_attack"],
        "cover_bulk_round": primary["cover_bulk_round"],
    }


def _json_sanitize(obj: Any) -> Any:
    """Replace NaN/Inf with null for stricter JSON consumers (CI / other langs)."""
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return None
        return obj
    if isinstance(obj, dict):
        return {k: _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_sanitize(v) for v in obj]
    return obj


def write_sidechannel_artifact(path: Path, bundle: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_json_sanitize(bundle), indent=2) + "\n", encoding="utf-8"
    )
