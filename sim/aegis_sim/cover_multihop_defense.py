"""
Multi-hop cover defenses (research wave S4 / coverage C5 extension).

Tag: [O] QUANTIFIED — ranks synthetic cover policies that raise
`implied_packet_continuity` toward Sphinx-only; not info-theoretic
indistinguishability.

Imports public APIs / metrics from `cover_multihop` (does not rewrite that core).
Local discard cover (today's `COVER_FRAGMENT_RESERVED` path) is the baseline;
defenses explore cover onions and matched discard schedules in-sim.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

import numpy as np

from aegis_sim import cover_multihop as cm
from aegis_sim import cover_timing

SPHINX_FRAGMENT_COUNT = cm.SPHINX_FRAGMENT_COUNT

DefenseScheme = Literal[
    "baseline_local_discard",
    "matched_local_discard",
    "cover_onions",
    "cover_onions_plus_matched",
    "sphinx_only_reference",
]

CI_SCHEMES: tuple[DefenseScheme, ...] = (
    "baseline_local_discard",
    "matched_local_discard",
    "cover_onions",
    "cover_onions_plus_matched",
    "sphinx_only_reference",
)

DISCLAIMER = (
    "Partial multi-hop cover *defense* ranking — not info-theoretic cover "
    "indistinguishability. Sim cover onions model full-path continuity; product "
    "opt-in cover_onions is terminal peel-then-sink (not client exit); scaffold "
    "and COVER_FRAGMENT_RESERVED remain local-discard."
)


def _mixing_delay(rng: np.random.Generator, mean_secs: float) -> float:
    if mean_secs <= 0:
        return 0.0
    return float(rng.exponential(mean_secs))


def simulate_defense_path(
    scheme: DefenseScheme = "baseline_local_discard",
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    cells_per_cover_burst: int = SPHINX_FRAGMENT_COUNT,
    cover_onion_packets_per_send: int = 2,
    mixing_delay_mean_secs: float = 0.05,
    inter_send_idle_secs: float = 0.5,
    seed: int = 7,
) -> list[cm.HopObservation]:
    """
    Simulate per-hop wire/discard/forward under a cover defense policy.

    - ``baseline_local_discard``: same semantics as ``sphinx_plus_cover``
      (delegates to public ``simulate_multihop_path``).
    - ``matched_local_discard``: identical local cover schedule on every hop
      (symmetric discard; lowers hop volume L1).
    - ``cover_onions``: additional cover packets that peel/forward like Sphinx
      for all hops then terminate (raise implied_packet_continuity).
    - ``cover_onions_plus_matched``: cover onions + matched local discard.
    - ``sphinx_only_reference``: no cover (upper bound continuity).
    """
    if scheme not in CI_SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}")
    if n_hops < 2:
        raise ValueError("n_hops must be >= 2")
    if tau_secs <= 0:
        raise ValueError("tau_secs must be positive")

    if scheme == "baseline_local_discard":
        return cm.simulate_multihop_path(
            "sphinx_plus_cover",
            n_hops=n_hops,
            n_sends=n_sends,
            tau_secs=tau_secs,
            cover_secs=cover_secs,
            relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
            cells_per_cover_burst=cells_per_cover_burst,
            mixing_delay_mean_secs=mixing_delay_mean_secs,
            inter_send_idle_secs=inter_send_idle_secs,
            seed=seed,
        )
    if scheme == "sphinx_only_reference":
        return cm.simulate_multihop_path(
            "sphinx_only",
            n_hops=n_hops,
            n_sends=n_sends,
            tau_secs=tau_secs,
            cover_secs=0.0,
            relay_cover_bursts_per_hop=0,
            mixing_delay_mean_secs=mixing_delay_mean_secs,
            inter_send_idle_secs=inter_send_idle_secs,
            seed=seed,
        )

    rng = np.random.default_rng(seed)
    hops = [
        cm.HopObservation(
            hop_index=i,
            n_wire_cells=0,
            n_sphinx_fragments=0,
            n_cover_discarded=0,
            n_invalid_onion_cells=0,
            n_packets_forwarded=0,
        )
        for i in range(n_hops)
    ]
    t_client = 0.0
    hop_ready = [0.0] * n_hops
    use_onions = scheme in ("cover_onions", "cover_onions_plus_matched")
    use_matched = scheme in ("matched_local_discard", "cover_onions_plus_matched")
    n_onions = int(cover_onion_packets_per_send) if use_onions else 0
    local_cover = scheme != "cover_onions"  # onions-only skips local discard
    if scheme == "cover_onions_plus_matched":
        local_cover = True

    for send_idx in range(n_sends):
        if send_idx > 0:
            t_client += inter_send_idle_secs

        # Real Sphinx path (unchanged semantics).
        arrival = t_client
        for h in range(n_hops):
            emit_t = max(arrival, hop_ready[h])
            for k in range(SPHINX_FRAGMENT_COUNT):
                ts = emit_t + k * tau_secs
                hops[h].wire_timestamps.append(ts)
                hops[h].n_wire_cells += 1
                hops[h].n_sphinx_fragments += 1
            emit_end = emit_t + (SPHINX_FRAGMENT_COUNT - 1) * tau_secs
            delay = _mixing_delay(rng, mixing_delay_mean_secs)
            forward_t = emit_end + tau_secs + delay
            hops[h].forward_timestamps.append(forward_t)
            hops[h].n_packets_forwarded += 1
            hop_ready[h] = forward_t
            arrival = forward_t
        t_client = max(t_client, hops[0].wire_timestamps[-1] + tau_secs)

        # Cover onions: wire + forward on every hop (Sphinx-like continuity).
        for _ in range(n_onions):
            arrival = max(hop_ready[0], t_client)
            for h in range(n_hops):
                emit_t = max(arrival, hop_ready[h])
                for k in range(SPHINX_FRAGMENT_COUNT):
                    ts = emit_t + k * tau_secs
                    hops[h].wire_timestamps.append(ts)
                    hops[h].n_wire_cells += 1
                    # Counted as sphinx-shaped continuing cells for continuity.
                    hops[h].n_sphinx_fragments += 1
                emit_end = emit_t + (SPHINX_FRAGMENT_COUNT - 1) * tau_secs
                delay = _mixing_delay(rng, mixing_delay_mean_secs)
                forward_t = emit_end + tau_secs + delay
                hops[h].forward_timestamps.append(forward_t)
                hops[h].n_packets_forwarded += 1
                hop_ready[h] = forward_t
                arrival = forward_t
            # Terminal hop "delivers" to a sink / discards payload — still a
            # forward event at the last hop in this lab model (continuity≈1).

        # Local discard cover (matched schedule across hops when requested).
        if local_cover or use_matched:
            # Build one shared cover timeline length, apply identically per hop.
            n_cover = int(cover_secs / tau_secs) if cover_secs > 0 else 0
            burst_cells = relay_cover_bursts_per_hop * cells_per_cover_burst
            total_local = n_cover + burst_cells
            if total_local > 0:
                # Matched: same offsets from each hop's ready time.
                for h in range(n_hops):
                    base = hop_ready[h]
                    for j in range(total_local):
                        ts = base + j * tau_secs
                        hops[h].wire_timestamps.append(ts)
                        hops[h].n_wire_cells += 1
                        hops[h].n_cover_discarded += 1
                    hop_ready[h] = base + total_local * tau_secs

    for h in hops:
        h.wire_timestamps.sort()
        h.forward_timestamps.sort()
    return hops


def characterize_defense(
    scheme: DefenseScheme,
    **kwargs: Any,
) -> cm.MultihopGapReport:
    """Run defense path sim and score with cover_multihop public metrics."""
    hops = simulate_defense_path(scheme, **kwargs)
    # Reuse characterize_multihop scoring by building hop dicts the same way.
    n_hops = kwargs.get("n_hops", 3)
    n_sends = kwargs.get("n_sends", 4)
    tau_secs = kwargs.get("tau_secs", 0.35)
    hop_dicts = []
    for h in hops:
        gaps = cover_timing._inter_cell_gaps(h.wire_timestamps)
        stats = cover_timing._gap_stats(gaps, tau_secs) if gaps.size else {
            "n_gaps": 0,
            "gap_cv": 0.0,
            "fraction_near_tau": 0.0,
            "gap_histogram": cover_timing.gap_histogram(gaps, tau_secs),
        }
        discarded = h.n_cover_discarded + h.n_invalid_onion_cells
        disc_frac = discarded / h.n_wire_cells if h.n_wire_cells else 0.0
        fwd_yield = (
            h.n_packets_forwarded / h.n_wire_cells if h.n_wire_cells else 0.0
        )
        implied = h.n_wire_cells / float(SPHINX_FRAGMENT_COUNT)
        cont = h.n_packets_forwarded / implied if implied > 0 else 0.0
        hop_dicts.append(
            {
                "hop_index": h.hop_index,
                "n_wire_cells": h.n_wire_cells,
                "n_sphinx_fragments": h.n_sphinx_fragments,
                "n_cover_discarded": h.n_cover_discarded,
                "n_invalid_onion_cells": h.n_invalid_onion_cells,
                "n_packets_forwarded": h.n_packets_forwarded,
                "discard_fraction": disc_frac,
                "forward_yield": fwd_yield,
                "implied_packet_continuity": cont,
                "gap_cv": stats["gap_cv"],
                "fraction_near_tau": stats["fraction_near_tau"],
                "gap_histogram": stats["gap_histogram"],
            }
        )
    return cm.MultihopGapReport(
        scenario=scheme,  # type: ignore[arg-type]
        n_hops=n_hops,
        tau_secs=tau_secs,
        n_sends=n_sends,
        mean_discard_fraction=float(np.mean([d["discard_fraction"] for d in hop_dicts])),
        mean_forward_yield=float(np.mean([d["forward_yield"] for d in hop_dicts])),
        mean_implied_packet_continuity=float(
            np.mean([d["implied_packet_continuity"] for d in hop_dicts])
        ),
        hop_volume_l1=cm.hop_volume_l1(hops),
        forward_continuity=cm.forward_continuity(hops),
        gap_ks_hop0_vs_hop1=cm.gap_ks_adjacent_hops(hops),
        semantic_gap_score=cm.semantic_gap_score(hops),
        hops=hop_dicts,
        disclaimer=DISCLAIMER,
    )


def _rank_schemes(reports: dict[str, cm.MultihopGapReport]) -> list[dict[str, Any]]:
    base = reports["baseline_local_discard"]
    ranking = []
    for name, r in reports.items():
        ranking.append({
            "scheme": name,
            "mean_implied_packet_continuity": round(r.mean_implied_packet_continuity, 6),
            "semantic_gap_score": round(r.semantic_gap_score, 6),
            "mean_discard_fraction": round(r.mean_discard_fraction, 6),
            "hop_volume_l1": round(r.hop_volume_l1, 6),
            "continuity_gain_vs_baseline": round(
                r.mean_implied_packet_continuity - base.mean_implied_packet_continuity, 6
            ),
            "gap_reduction_vs_baseline": round(
                base.semantic_gap_score - r.semantic_gap_score, 6
            ),
            "is_reference": name == "sphinx_only_reference",
        })
    # Rank by continuity (desc), then semantic gap (asc); reference last for ops.
    ranking.sort(key=lambda row: (
        1 if row["is_reference"] else 0,
        -row["mean_implied_packet_continuity"],
        row["semantic_gap_score"],
        row["scheme"],
    ))
    return ranking


def _recommend(ranking: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [
        r for r in ranking
        if not r["is_reference"] and r["scheme"] != "baseline_local_discard"
    ]
    prefer = (
        "cover_onions",
        "cover_onions_plus_matched",
        "matched_local_discard",
    )
    by = {r["scheme"]: r for r in ranking}
    for name in prefer:
        row = by.get(name)
        if row is None:
            continue
        if row["continuity_gain_vs_baseline"] > 0.05 or row["gap_reduction_vs_baseline"] > 0.05:
            return {
                "scheme": name,
                "mean_implied_packet_continuity": row["mean_implied_packet_continuity"],
                "semantic_gap_score": row["semantic_gap_score"],
                "note": (
                    f"Recommend `{name}` in-sim: raises implied_packet_continuity "
                    "and/or lowers semantic_gap_score vs local-discard baseline. "
                    "Product still needs real peelable cover onions — not shipped."
                ),
            }
    if candidates:
        best = max(candidates, key=lambda r: r["mean_implied_packet_continuity"])
        return {
            "scheme": best["scheme"],
            "mean_implied_packet_continuity": best["mean_implied_packet_continuity"],
            "semantic_gap_score": best["semantic_gap_score"],
            "note": "Best continuity among non-reference defenses in this run.",
        }
    return {
        "scheme": "baseline_local_discard",
        "note": "No defense improved continuity materially in this run.",
    }


def cover_multihop_defense_report(
    *,
    n_hops: int = 3,
    n_sends: int = 4,
    tau_secs: float = 0.35,
    cover_secs: float = 2.0,
    relay_cover_bursts_per_hop: int = 1,
    cover_onion_packets_per_send: int = 2,
    schemes: tuple[DefenseScheme, ...] = CI_SCHEMES,
    seed: int = 7,
    include_baseline_c5: bool = True,
) -> dict[str, Any]:
    """Rank multi-hop cover defenses; CI-safe deterministic defaults."""
    reports: dict[str, cm.MultihopGapReport] = {}
    for sch in schemes:
        reports[sch] = characterize_defense(
            sch,
            n_hops=n_hops,
            n_sends=n_sends,
            tau_secs=tau_secs,
            cover_secs=cover_secs,
            relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
            cover_onion_packets_per_send=cover_onion_packets_per_send,
            seed=seed,
        )
    ranking = _rank_schemes(reports)
    recommended = _recommend(ranking)
    sphinx_cont = reports.get("sphinx_only_reference")
    base = reports["baseline_local_discard"]
    out: dict[str, Any] = {
        "tag": "wave_S4_cover_multihop_defense",
        "extends": "coverage_C5_cover_multihop",
        "disclaimer": DISCLAIMER,
        "claims_info_theoretic_indistinguishability": False,
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "n_hops": n_hops,
        "n_sends": n_sends,
        "tau_secs": tau_secs,
        "cover_secs": cover_secs,
        "relay_cover_bursts_per_hop": relay_cover_bursts_per_hop,
        "cover_onion_packets_per_send": cover_onion_packets_per_send,
        "schemes_evaluated": list(schemes),
        "by_scheme": {name: asdict(r) for name, r in reports.items()},
        "defense_ranking": ranking,
        "recommended": recommended,
        "delta_vs_baseline": {
            "baseline_continuity": base.mean_implied_packet_continuity,
            "baseline_semantic_gap_score": base.semantic_gap_score,
            "sphinx_reference_continuity": (
                sphinx_cont.mean_implied_packet_continuity if sphinx_cont else None
            ),
            "recommended_continuity": (
                reports[recommended["scheme"]].mean_implied_packet_continuity
                if recommended["scheme"] in reports
                else None
            ),
            "continuity_ratio_recommended_over_sphinx": (
                (
                    reports[recommended["scheme"]].mean_implied_packet_continuity
                    / sphinx_cont.mean_implied_packet_continuity
                )
                if sphinx_cont is not None
                and recommended["scheme"] in reports
                and sphinx_cont.mean_implied_packet_continuity > 1e-12
                else None
            ),
        },
        "honest_residuals": [
            "Cover onions in this lab forward like Sphinx on the path; product "
            "cover still uses COVER_FRAGMENT_RESERVED local discard.",
            "Matched discard lowers hop volume L1 but alone cannot restore "
            "implied_packet_continuity when cover never forwards.",
            "Valid Sphinx ciphertext / peel MAC still differ from synthetic "
            "cover onions — GPA with crypto vantage is out of scope here.",
            "Not info-theoretic indistinguishability; single-hop gap CV may "
            "still look τ-like under all schemes.",
        ],
        "sim_to_product": {
            "baseline_local_discard": (
                "Default: cover_flow.rs COVER_FRAGMENT_RESERVED discard before peel"
            ),
            "matched_local_discard": (
                "Product A3 (opt-in): [cover] multihop_defense = "
                "\"matched_local_discard\" + matched_cover_flows — fixed cover "
                "volume independent of local real count (peer-aligned discard)"
            ),
            "cover_onions": (
                "Product A3 scaffold: cover_onions_scaffold + "
                "COVER_ONION_SCAFFOLD_RESERVED — still discarded; peelable "
                "forward-then-sink onions not shipped (no continuity claim)"
            ),
            "mapping_doc": "docs/ops/cover_multihop_defense.md",
        },
        "c5_public_api_ref": {
            "module": "aegis_sim.cover_multihop",
            "artifact": "sim/data/cover_multihop_characterization.json",
            "simulate": "simulate_multihop_path",
            "characterize": "characterize_multihop",
        },
    }
    if include_baseline_c5:
        # Cross-check: public C5 sphinx_plus_cover continuity matches baseline.
        c5 = cm.characterize_multihop(
            "sphinx_plus_cover",
            n_hops=n_hops,
            n_sends=n_sends,
            tau_secs=tau_secs,
            cover_secs=cover_secs,
            relay_cover_bursts_per_hop=relay_cover_bursts_per_hop,
            seed=seed,
        )
        out["c5_cross_check"] = {
            "c5_continuity": c5.mean_implied_packet_continuity,
            "s4_baseline_continuity": base.mean_implied_packet_continuity,
            "match": abs(
                c5.mean_implied_packet_continuity - base.mean_implied_packet_continuity
            ) < 1e-9,
        }
    return out


def write_cover_multihop_defense_artifact(path: Path, report: dict[str, Any] | None = None,
                                          **kwargs: Any) -> dict[str, Any]:
    report = report if report is not None else cover_multihop_defense_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
