"""
Partial GPA timing characterization: paced bulk vs paced + τ-cover.

Models observable cell emission times at a wire vantage (client egress or relay
post-forward). Uses the same τ slot semantics as Mode-1 (`aegis-client` emitter
and relay cover dispatcher) — this is **not** an info-theoretic indistinguishability
proof; it quantifies inter-cell gap statistics only.

See `docs/ops/RESEARCH_OPS_STATUS.md` item #5 (Cover-burst timing: Partial).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import numpy as np

# Matches `aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT`.
SPHINX_FRAGMENT_COUNT = 18

Mode = Literal["paced_bulk_only", "paced_plus_tau_cover"]


@dataclass(frozen=True)
class GpaTimingReport:
    """Observable inter-cell timing summary for one emission mode."""

    mode: Mode
    tau_secs: float
    n_sends: int
    n_cells: int
    n_gaps: int
    gap_mean_secs: float
    gap_std_secs: float
    gap_cv: float
    gap_p95_secs: float
    gap_max_secs: float
    fraction_near_tau: float
    cover_secs: float
    relay_cover_bursts_per_send: int
    disclaimer: str = (
        "Partial characterization of inter-cell gaps — not info-theoretic "
        "indistinguishability or a formal Sphinx proof."
    )


def _inter_cell_gaps(timestamps: list[float]) -> np.ndarray:
    if len(timestamps) < 2:
        return np.array([], dtype=float)
    t = np.asarray(sorted(timestamps), dtype=float)
    return np.diff(t)


def _kolmogorov_smirnov_distance(a: np.ndarray, b: np.ndarray) -> float:
    """Two-sample KS D statistic (partial distributional comparison, not a proof)."""
    if a.size == 0 or b.size == 0:
        return float("nan")
    a_sorted = np.sort(a)
    b_sorted = np.sort(b)
    all_vals = np.sort(np.concatenate([a_sorted, b_sorted]))
    cdf_a = np.searchsorted(a_sorted, all_vals, side="right") / a.size
    cdf_b = np.searchsorted(b_sorted, all_vals, side="right") / b.size
    return float(np.max(np.abs(cdf_a - cdf_b)))


def _gap_stats(gaps: np.ndarray, tau: float) -> dict:
    if gaps.size == 0:
        return dict(
            n_gaps=0,
            gap_mean_secs=0.0,
            gap_std_secs=0.0,
            gap_cv=0.0,
            gap_p95_secs=0.0,
            gap_max_secs=0.0,
            fraction_near_tau=0.0,
        )
    mean = float(gaps.mean())
    std = float(gaps.std())
    cv = float(std / (mean + 1e-12))
    tol = max(tau * 0.25, 1e-6)
    near = float(np.mean(np.abs(gaps - tau) <= tol))
    return dict(
        n_gaps=int(gaps.size),
        gap_mean_secs=mean,
        gap_std_secs=std,
        gap_cv=cv,
        gap_p95_secs=float(np.percentile(gaps, 95)),
        gap_max_secs=float(gaps.max()),
        fraction_near_tau=near,
    )


def simulate_cell_timestamps(
    mode: Mode,
    *,
    tau_secs: float = 0.35,
    n_sends: int = 4,
    fragments_per_send: int = SPHINX_FRAGMENT_COUNT,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_send: int = 0,
    cells_per_cover_burst: int = SPHINX_FRAGMENT_COUNT,
    inter_send_idle_secs: float = 0.5,
) -> list[float]:
    """Return sorted cell emission timestamps for one scenario."""
    if tau_secs <= 0:
        raise ValueError("tau_secs must be positive")
    if n_sends <= 0:
        raise ValueError("n_sends must be positive")
    if mode not in ("paced_bulk_only", "paced_plus_tau_cover"):
        raise ValueError(f"unknown mode {mode!r}")

    stamps: list[float] = []
    t = 0.0
    for send_idx in range(n_sends):
        if send_idx > 0:
            t += inter_send_idle_secs
        # Real bulk fragments at constant τ.
        for i in range(fragments_per_send):
            stamps.append(t + i * tau_secs)
        t += (fragments_per_send - 1) * tau_secs + tau_secs

        if mode == "paced_plus_tau_cover" and cover_secs > 0:
            n_cover = int(cover_secs / tau_secs)
            for j in range(n_cover):
                stamps.append(t + j * tau_secs)
            t += max(0, n_cover - 1) * tau_secs + (tau_secs if n_cover else 0)

        if mode == "paced_plus_tau_cover" and relay_cover_bursts_per_send > 0:
            for _ in range(relay_cover_bursts_per_send):
                for k in range(cells_per_cover_burst):
                    stamps.append(t + k * tau_secs)
                t += (cells_per_cover_burst - 1) * tau_secs + tau_secs

    return stamps


def characterize_gpa_timing(
    mode: Mode,
    *,
    tau_secs: float = 0.35,
    n_sends: int = 4,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_send: int = 1,
    **kwargs,
) -> GpaTimingReport:
    """Build a timing report for one mode (partial GPA characterization)."""
    if mode == "paced_bulk_only":
        cover_secs = 0.0
        relay_cover_bursts_per_send = 0

    stamps = simulate_cell_timestamps(
        mode,
        tau_secs=tau_secs,
        n_sends=n_sends,
        cover_secs=cover_secs,
        relay_cover_bursts_per_send=relay_cover_bursts_per_send,
        **kwargs,
    )
    stats = _gap_stats(_inter_cell_gaps(stamps), tau_secs)
    return GpaTimingReport(
        mode=mode,
        tau_secs=tau_secs,
        n_sends=n_sends,
        n_cells=len(stamps),
        cover_secs=cover_secs,
        relay_cover_bursts_per_send=relay_cover_bursts_per_send,
        **stats,
    )


def compare_cover_modes(
    *,
    tau_secs: float = 0.35,
    n_sends: int = 4,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_send: int = 1,
    **kwargs,
) -> dict:
    """Side-by-side partial characterization (bulk-only vs paced + τ-cover)."""
    bulk = characterize_gpa_timing(
        "paced_bulk_only",
        tau_secs=tau_secs,
        n_sends=n_sends,
        **kwargs,
    )
    cover = characterize_gpa_timing(
        "paced_plus_tau_cover",
        tau_secs=tau_secs,
        n_sends=n_sends,
        cover_secs=cover_secs,
        relay_cover_bursts_per_send=relay_cover_bursts_per_send,
        **kwargs,
    )
    bulk_gaps = _inter_cell_gaps(
        simulate_cell_timestamps("paced_bulk_only", tau_secs=tau_secs, n_sends=n_sends, **kwargs)
    )
    cover_gaps = _inter_cell_gaps(
        simulate_cell_timestamps(
            "paced_plus_tau_cover",
            tau_secs=tau_secs,
            n_sends=n_sends,
            cover_secs=cover_secs,
            relay_cover_bursts_per_send=relay_cover_bursts_per_send,
            **kwargs,
        )
    )
    return {
        "disclaimer": bulk.disclaimer,
        "tau_secs": tau_secs,
        "n_sends": n_sends,
        "paced_bulk_only": asdict(bulk),
        "paced_plus_tau_cover": asdict(cover),
        "delta": {
            "extra_cells": cover.n_cells - bulk.n_cells,
            "gap_cv_ratio_cover_over_bulk": (
                cover.gap_cv / bulk.gap_cv if bulk.gap_cv > 1e-9 else float("nan")
            ),
            "gap_ks_distance_cover_vs_bulk": _kolmogorov_smirnov_distance(cover_gaps, bulk_gaps),
        },
    }


def compare_cover_modes_under_burst(
    *,
    tau_secs: float = 0.35,
    n_sends: int = 6,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_send: int = 3,
    **kwargs,
) -> dict:
    """Burst-heavy partial GPA comparison (paced-only vs paced+cover under relay bursts)."""
    bulk = characterize_gpa_timing(
        "paced_bulk_only",
        tau_secs=tau_secs,
        n_sends=n_sends,
        relay_cover_bursts_per_send=relay_cover_bursts_per_send,
        **kwargs,
    )
    cover = characterize_gpa_timing(
        "paced_plus_tau_cover",
        tau_secs=tau_secs,
        n_sends=n_sends,
        cover_secs=cover_secs,
        relay_cover_bursts_per_send=relay_cover_bursts_per_send,
        **kwargs,
    )
    bulk_gaps = _inter_cell_gaps(
        simulate_cell_timestamps(
            "paced_bulk_only",
            tau_secs=tau_secs,
            n_sends=n_sends,
            relay_cover_bursts_per_send=relay_cover_bursts_per_send,
            **kwargs,
        )
    )
    cover_gaps = _inter_cell_gaps(
        simulate_cell_timestamps(
            "paced_plus_tau_cover",
            tau_secs=tau_secs,
            n_sends=n_sends,
            cover_secs=cover_secs,
            relay_cover_bursts_per_send=relay_cover_bursts_per_send,
            **kwargs,
        )
    )
    return {
        "disclaimer": bulk.disclaimer,
        "scenario": "burst_heavy",
        "tau_secs": tau_secs,
        "n_sends": n_sends,
        "relay_cover_bursts_per_send": relay_cover_bursts_per_send,
        "paced_bulk_only": asdict(bulk),
        "paced_plus_tau_cover": asdict(cover),
        "delta": {
            "gap_cv_bulk": bulk.gap_cv,
            "gap_cv_cover": cover.gap_cv,
            "gap_cv_ratio_cover_over_bulk": (
                cover.gap_cv / bulk.gap_cv if bulk.gap_cv > 1e-9 else float("nan")
            ),
            "gap_ks_distance_cover_vs_bulk": _kolmogorov_smirnov_distance(cover_gaps, bulk_gaps),
        },
    }


def write_characterization_artifact(path: Path, comparison: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
