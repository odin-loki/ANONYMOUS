"""
Multi-hop cover semantic-gap characterization (GPA, partial).

Wire cover cells are τ-paced and AEAD-sealed like Sphinx fragments, but the next
hop discards them via `COVER_FRAGMENT_RESERVED` before reassembly — they never
become valid onion forwards. Real Sphinx packets peel and continue. A GPA that
sees two or more hops can therefore exploit **volume / timing / semantic**
asymmetry between hops even when single-hop gap CV looks cover-like.

Imports timing primitives from `cover_timing` (does not rewrite that core).
This is **not** info-theoretic indistinguishability.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import numpy as np

from aegis_sim import cover_timing

SPHINX_FRAGMENT_COUNT = cover_timing.SPHINX_FRAGMENT_COUNT

Scenario = Literal["sphinx_only", "sphinx_plus_cover", "sphinx_plus_invalid"]

DISCLAIMER = (
    "Partial multi-hop semantic-gap characterization — not info-theoretic "
    "cover indistinguishability. Models discarded cover / invalid onion vs "
    "Sphinx forward continuity across hops."
)


@dataclass
class HopObservation:
    """GPA-visible counters and timestamps at one hop link."""

    hop_index: int
    n_wire_cells: int
    n_sphinx_fragments: int
    n_cover_discarded: int
    n_invalid_onion_cells: int
    n_packets_forwarded: int
    wire_timestamps: list[float] = field(default_factory=list)
    forward_timestamps: list[float] = field(default_factory=list)


@dataclass(frozen=True)
class MultihopGapReport:
    """Aggregate distinguishability features for one multi-hop scenario."""

    scenario: Scenario
    n_hops: int
    tau_secs: float
    n_sends: int
    mean_discard_fraction: float
    mean_forward_yield: float
    mean_implied_packet_continuity: float
    hop_volume_l1: float
    forward_continuity: float
    gap_ks_hop0_vs_hop1: float
    semantic_gap_score: float
    hops: list[dict[str, Any]] = field(default_factory=list)
    disclaimer: str = DISCLAIMER


def _mixing_delay(rng: np.random.Generator, mean_secs: float) -> float:
    if mean_secs <= 0:
        return 0.0
    # Exp(μ) mixing delay — matches relay delay family; lab model only.
    return float(rng.exponential(mean_secs))


def simulate_multihop_path(
    scenario: Scenario = "sphinx_plus_cover",
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    cells_per_cover_burst: int = SPHINX_FRAGMENT_COUNT,
    invalid_packets_per_send: int = 0,
    mixing_delay_mean_secs: float = 0.05,
    inter_send_idle_secs: float = 0.5,
    seed: int = 7,
) -> list[HopObservation]:
    """
    Simulate per-hop wire / discard / forward events on an L-hop path.

    - ``sphinx_only``: paced bulk Sphinx fragments only; each hop forwards.
    - ``sphinx_plus_cover``: same Sphinx plus local τ-cover discarded at next hop.
    - ``sphinx_plus_invalid``: Sphinx plus invalid-onion cells (fail peel, no forward).
    """
    if scenario not in ("sphinx_only", "sphinx_plus_cover", "sphinx_plus_invalid"):
        raise ValueError(f"unknown scenario {scenario!r}")
    if n_hops < 2:
        raise ValueError("n_hops must be >= 2 for multi-hop gap")
    if tau_secs <= 0:
        raise ValueError("tau_secs must be positive")

    rng = np.random.default_rng(seed)
    hops = [
        HopObservation(
            hop_index=i,
            n_wire_cells=0,
            n_sphinx_fragments=0,
            n_cover_discarded=0,
            n_invalid_onion_cells=0,
            n_packets_forwarded=0,
        )
        for i in range(n_hops)
    ]

    # Absolute time when the next Sphinx packet becomes available at hop 0 ingress.
    t_client = 0.0
    # Per-hop "ready" time for the next Sphinx packet arrival (post prior hop forward).
    hop_ready = [0.0] * n_hops

    cover_mode = scenario == "sphinx_plus_cover"
    invalid_mode = scenario == "sphinx_plus_invalid"
    n_invalid = invalid_packets_per_send if invalid_mode else 0
    if scenario == "sphinx_plus_invalid" and n_invalid <= 0:
        n_invalid = 1

    for send_idx in range(n_sends):
        if send_idx > 0:
            t_client += inter_send_idle_secs

        # --- Real Sphinx: emit fragments at each hop, then forward one packet ---
        arrival = t_client
        for h in range(n_hops):
            emit_t = max(arrival, hop_ready[h])
            for k in range(SPHINX_FRAGMENT_COUNT):
                ts = emit_t + k * tau_secs
                hops[h].wire_timestamps.append(ts)
                hops[h].n_wire_cells += 1
                hops[h].n_sphinx_fragments += 1
            emit_end = emit_t + (SPHINX_FRAGMENT_COUNT - 1) * tau_secs
            # Peel + mixing delay, then forward to next hop (if any).
            delay = _mixing_delay(rng, mixing_delay_mean_secs)
            forward_t = emit_end + tau_secs + delay
            hops[h].forward_timestamps.append(forward_t)
            hops[h].n_packets_forwarded += 1
            hop_ready[h] = forward_t
            arrival = forward_t  # next hop ingress

        t_client = max(t_client, hops[0].wire_timestamps[-1] + tau_secs)

        # --- Local cover bursts: wire volume that does not continue ---
        if cover_mode:
            for h in range(n_hops):
                base = hop_ready[h]
                n_cover = int(cover_secs / tau_secs) if cover_secs > 0 else 0
                for j in range(n_cover):
                    ts = base + j * tau_secs
                    hops[h].wire_timestamps.append(ts)
                    hops[h].n_wire_cells += 1
                    hops[h].n_cover_discarded += 1
                t_cursor = base + max(0, n_cover) * tau_secs
                for _ in range(relay_cover_bursts_per_hop):
                    for k in range(cells_per_cover_burst):
                        ts = t_cursor + k * tau_secs
                        hops[h].wire_timestamps.append(ts)
                        hops[h].n_wire_cells += 1
                        hops[h].n_cover_discarded += 1
                    t_cursor += cells_per_cover_burst * tau_secs
                hop_ready[h] = max(hop_ready[h], t_cursor)

        # --- Invalid onion: reassembled cells that fail peel (no forward) ---
        if n_invalid > 0:
            for h in range(n_hops):
                base = hop_ready[h]
                for p in range(n_invalid):
                    for k in range(SPHINX_FRAGMENT_COUNT):
                        ts = base + (p * SPHINX_FRAGMENT_COUNT + k) * tau_secs
                        hops[h].wire_timestamps.append(ts)
                        hops[h].n_wire_cells += 1
                        hops[h].n_invalid_onion_cells += 1
                hop_ready[h] = base + n_invalid * SPHINX_FRAGMENT_COUNT * tau_secs

    for h in hops:
        h.wire_timestamps.sort()
        h.forward_timestamps.sort()
    return hops


def _discard_fraction(hop: HopObservation) -> float:
    if hop.n_wire_cells <= 0:
        return 0.0
    discarded = hop.n_cover_discarded + hop.n_invalid_onion_cells
    return discarded / hop.n_wire_cells


def _forward_yield(hop: HopObservation) -> float:
    """Sphinx packets forwarded per wire cell (semantic continuity proxy)."""
    if hop.n_wire_cells <= 0:
        return 0.0
    return hop.n_packets_forwarded / hop.n_wire_cells


def _implied_packet_continuity(hop: HopObservation) -> float:
    """
    Forwarded packets / (wire_cells / SPHINX_FRAGMENT_COUNT).

    Near 1.0 when every wire cell belongs to a continuing Sphinx packet;
    much less than 1.0 when cover/invalid inflate wire volume without forwards.
    """
    if hop.n_wire_cells <= 0:
        return 0.0
    implied = hop.n_wire_cells / float(SPHINX_FRAGMENT_COUNT)
    if implied <= 0:
        return 0.0
    return hop.n_packets_forwarded / implied


def hop_volume_l1(hops: list[HopObservation]) -> float:
    """L1 distance of per-hop wire-cell fractions from uniform (asymmetry)."""
    counts = np.asarray([h.n_wire_cells for h in hops], dtype=float)
    total = float(counts.sum())
    if total <= 0 or len(hops) == 0:
        return float("nan")
    frac = counts / total
    uniform = np.full_like(frac, 1.0 / len(hops))
    return float(np.sum(np.abs(frac - uniform)))


def forward_continuity(hops: list[HopObservation]) -> float:
    """
    Mean ratio of successive-hop Sphinx forward counts.

    Ideal Sphinx path ≈ 1.0; cover/invalid inflate wire without matching forwards
    but continuity of *forwards* stays ~1 — the gap is wire vs forward, not
    forward vs forward. We therefore also expose discard/yield separately.
    """
    if len(hops) < 2:
        return float("nan")
    ratios = []
    for i in range(len(hops) - 1):
        a = hops[i].n_packets_forwarded
        b = hops[i + 1].n_packets_forwarded
        if a <= 0:
            continue
        ratios.append(b / a)
    return float(np.mean(ratios)) if ratios else float("nan")


def wire_vs_forward_gap(hops: list[HopObservation]) -> float:
    """Mean (wire_cells - sphinx_fragments) / wire — cover/invalid semantic residue."""
    vals = []
    for h in hops:
        if h.n_wire_cells <= 0:
            continue
        vals.append((h.n_wire_cells - h.n_sphinx_fragments) / h.n_wire_cells)
    return float(np.mean(vals)) if vals else 0.0


def gap_ks_adjacent_hops(hops: list[HopObservation]) -> float:
    """KS distance between inter-cell gap distributions on hop 0 vs hop 1."""
    if len(hops) < 2:
        return float("nan")
    g0 = cover_timing._inter_cell_gaps(hops[0].wire_timestamps)
    g1 = cover_timing._inter_cell_gaps(hops[1].wire_timestamps)
    return cover_timing._kolmogorov_smirnov_distance(g0, g1)


def semantic_gap_score(hops: list[HopObservation]) -> float:
    """
    Composite [0, ~3] score: discard fraction + wire/forward residue + hop volume L1.

    Higher ⇒ more multi-hop semantic distinguishability in this lab model.
    """
    disc = float(np.mean([_discard_fraction(h) for h in hops])) if hops else 0.0
    residue = wire_vs_forward_gap(hops)
    vol = hop_volume_l1(hops)
    if vol != vol:  # NaN
        vol = 0.0
    return disc + residue + vol


def characterize_multihop(
    scenario: Scenario,
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    invalid_packets_per_send: int = 0,
    mixing_delay_mean_secs: float = 0.05,
    seed: int = 7,
) -> MultihopGapReport:
    hops = simulate_multihop_path(
        scenario,
        n_hops=n_hops,
        n_sends=n_sends,
        tau_secs=tau_secs,
        cover_secs=cover_secs,
        relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
        invalid_packets_per_send=invalid_packets_per_send,
        mixing_delay_mean_secs=mixing_delay_mean_secs,
        seed=seed,
    )
    hop_dicts = []
    for h in hops:
        gaps = cover_timing._inter_cell_gaps(h.wire_timestamps)
        stats = cover_timing._gap_stats(gaps, tau_secs) if gaps.size else {
            "n_gaps": 0,
            "gap_cv": 0.0,
            "fraction_near_tau": 0.0,
            "gap_histogram": cover_timing.gap_histogram(gaps, tau_secs),
        }
        hop_dicts.append(
            {
                "hop_index": h.hop_index,
                "n_wire_cells": h.n_wire_cells,
                "n_sphinx_fragments": h.n_sphinx_fragments,
                "n_cover_discarded": h.n_cover_discarded,
                "n_invalid_onion_cells": h.n_invalid_onion_cells,
                "n_packets_forwarded": h.n_packets_forwarded,
                "discard_fraction": _discard_fraction(h),
                "forward_yield": _forward_yield(h),
                "implied_packet_continuity": _implied_packet_continuity(h),
                "gap_cv": stats["gap_cv"],
                "fraction_near_tau": stats["fraction_near_tau"],
                "gap_histogram": stats["gap_histogram"],
            }
        )
    return MultihopGapReport(
        scenario=scenario,
        n_hops=n_hops,
        tau_secs=tau_secs,
        n_sends=n_sends,
        mean_discard_fraction=float(np.mean([d["discard_fraction"] for d in hop_dicts])),
        mean_forward_yield=float(np.mean([d["forward_yield"] for d in hop_dicts])),
        mean_implied_packet_continuity=float(
            np.mean([d["implied_packet_continuity"] for d in hop_dicts])
        ),
        hop_volume_l1=hop_volume_l1(hops),
        forward_continuity=forward_continuity(hops),
        gap_ks_hop0_vs_hop1=gap_ks_adjacent_hops(hops),
        semantic_gap_score=semantic_gap_score(hops),
        hops=hop_dicts,
    )


def compare_multihop_scenarios(
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    invalid_packets_per_send: int = 1,
    mixing_delay_mean_secs: float = 0.05,
    seed: int = 7,
) -> dict[str, Any]:
    """Side-by-side sphinx_only vs cover vs invalid-onion multi-hop features."""
    sphinx = characterize_multihop(
        "sphinx_only",
        n_hops=n_hops,
        n_sends=n_sends,
        tau_secs=tau_secs,
        cover_secs=0.0,
        relay_cover_bursts_per_hop=0,
        mixing_delay_mean_secs=mixing_delay_mean_secs,
        seed=seed,
    )
    cover = characterize_multihop(
        "sphinx_plus_cover",
        n_hops=n_hops,
        n_sends=n_sends,
        tau_secs=tau_secs,
        cover_secs=cover_secs,
        relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
        mixing_delay_mean_secs=mixing_delay_mean_secs,
        seed=seed,
    )
    invalid = characterize_multihop(
        "sphinx_plus_invalid",
        n_hops=n_hops,
        n_sends=n_sends,
        tau_secs=tau_secs,
        cover_secs=0.0,
        relay_cover_bursts_per_hop=0,
        invalid_packets_per_send=invalid_packets_per_send,
        mixing_delay_mean_secs=mixing_delay_mean_secs,
        seed=seed,
    )

    def _asdict(r: MultihopGapReport) -> dict:
        d = asdict(r)
        return d

    return {
        "disclaimer": DISCLAIMER,
        "characterization": "partial_multihop_semantic_gap",
        "claims_info_theoretic_indistinguishability": False,
        "n_hops": n_hops,
        "tau_secs": tau_secs,
        "n_sends": n_sends,
        "sphinx_only": _asdict(sphinx),
        "sphinx_plus_cover": _asdict(cover),
        "sphinx_plus_invalid": _asdict(invalid),
        "delta": {
            "cover_minus_sphinx_semantic_gap_score": (
                cover.semantic_gap_score - sphinx.semantic_gap_score
            ),
            "invalid_minus_sphinx_semantic_gap_score": (
                invalid.semantic_gap_score - sphinx.semantic_gap_score
            ),
            "cover_discard_fraction": cover.mean_discard_fraction,
            "sphinx_discard_fraction": sphinx.mean_discard_fraction,
            "cover_forward_yield": cover.mean_forward_yield,
            "sphinx_forward_yield": sphinx.mean_forward_yield,
            "forward_yield_ratio_cover_over_sphinx": (
                cover.mean_forward_yield / sphinx.mean_forward_yield
                if sphinx.mean_forward_yield > 1e-12
                else float("nan")
            ),
            "cover_implied_packet_continuity": cover.mean_implied_packet_continuity,
            "sphinx_implied_packet_continuity": sphinx.mean_implied_packet_continuity,
            "continuity_ratio_cover_over_sphinx": (
                cover.mean_implied_packet_continuity
                / sphinx.mean_implied_packet_continuity
                if sphinx.mean_implied_packet_continuity > 1e-12
                else float("nan")
            ),
            "cover_gap_ks_hop0_vs_hop1": cover.gap_ks_hop0_vs_hop1,
            "sphinx_gap_ks_hop0_vs_hop1": sphinx.gap_ks_hop0_vs_hop1,
            "single_hop_timing_still_partial": True,
            "note": (
                "Cover can keep single-hop gap CV near τ (see cover_timing) while "
                "lowering implied_packet_continuity / forward_yield and raising "
                "discard_fraction — the multi-hop semantic gap."
            ),
        },
        # Cross-link to single-hop timing model (additive; no schema break).
        "single_hop_timing_ref": {
            "module": "aegis_sim.cover_timing",
            "artifact": "sim/data/cover_burst_gpa_characterization.json",
        },
    }


def full_multihop_characterization_bundle(
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    invalid_packets_per_send: int = 1,
    burst_n_sends: int = 6,
    burst_relay_cover_bursts: int = 3,
) -> dict[str, Any]:
    """Baseline + burst-heavy multi-hop bundle for the committed artifact."""
    baseline = compare_multihop_scenarios(
        n_hops=n_hops,
        n_sends=n_sends,
        tau_secs=tau_secs,
        cover_secs=cover_secs,
        relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
        invalid_packets_per_send=invalid_packets_per_send,
    )
    burst = compare_multihop_scenarios(
        n_hops=n_hops,
        n_sends=burst_n_sends,
        tau_secs=tau_secs,
        cover_secs=cover_secs,
        relay_cover_bursts_per_hop=burst_relay_cover_bursts,
        invalid_packets_per_send=invalid_packets_per_send,
    )
    burst["scenario"] = "burst_heavy"
    return {
        "disclaimer": DISCLAIMER,
        "claims_info_theoretic_indistinguishability": False,
        "baseline": baseline,
        "burst_heavy": burst,
        "n_hops": baseline["n_hops"],
        "tau_secs": baseline["tau_secs"],
        "n_sends": baseline["n_sends"],
        "sphinx_only": baseline["sphinx_only"],
        "sphinx_plus_cover": baseline["sphinx_plus_cover"],
        "sphinx_plus_invalid": baseline["sphinx_plus_invalid"],
        "delta": baseline["delta"],
        "single_hop_timing_ref": baseline["single_hop_timing_ref"],
    }


def write_multihop_artifact(path: Path, bundle: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
