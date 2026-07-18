#!/usr/bin/env python3
"""Emit cover-burst GPA timing artifact under sim/data/ (partial; not a proof)."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import cover_timing

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "cover_burst_gpa_characterization.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Partial GPA timing characterization with CV/KS/gap histograms "
            "(not info-theoretic indistinguishability)."
        )
    )
    p.add_argument("--tau-secs", type=float, default=0.35)
    p.add_argument("--n-sends", type=int, default=4)
    p.add_argument("--cover-secs", type=float, default=2.0)
    p.add_argument("--relay-cover-bursts", type=int, default=1)
    p.add_argument("--burst-n-sends", type=int, default=6)
    p.add_argument("--burst-relay-cover-bursts", type=int, default=3)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    comparison = cover_timing.full_characterization_bundle(
        tau_secs=args.tau_secs,
        n_sends=args.n_sends,
        cover_secs=args.cover_secs,
        relay_cover_bursts_per_send=args.relay_cover_bursts,
        burst_n_sends=args.burst_n_sends,
        burst_relay_cover_bursts=args.burst_relay_cover_bursts,
    )
    cover_timing.write_characterization_artifact(args.output, comparison)
    d = comparison["delta"]
    print(f"wrote {args.output}")
    print(
        f"  baseline gap_cv_ratio={d['gap_cv_ratio_cover_over_bulk']:.4f} "
        f"ks={d['gap_ks_distance_cover_vs_bulk']:.4f} "
        f"hist_l1={d['histogram_l1_distance']:.4f}"
    )
    print("  claims_info_theoretic_indistinguishability=false")


if __name__ == "__main__":
    main()
