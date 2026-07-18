#!/usr/bin/env python3
"""Emit metrics scrape side-channel artifact under sim/data/ (partial; not a bound)."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import metrics_sidechannel

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "metrics_sidechannel_characterization.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Partial RelayCoarseStats / IngressRateLimitStats scrape leakage "
            "characterization (not an info-theoretic bound)."
        )
    )
    p.add_argument("--duration-secs", type=float, default=30.0)
    p.add_argument("--scrape-interval-secs", type=float, default=1.0)
    p.add_argument("--attack-cells-per-sec", type=float, default=40.0)
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    bundle = metrics_sidechannel.full_sidechannel_characterization_bundle(
        duration_secs=args.duration_secs,
        scrape_interval_secs=args.scrape_interval_secs,
        attack_cells_per_sec=args.attack_cells_per_sec,
        seed=args.seed,
    )
    metrics_sidechannel.write_sidechannel_artifact(args.output, bundle)
    d = bundle["delta"]
    print(f"wrote {args.output}")
    print(
        f"  drop_delta={d['flood_drop_total_minus_baseline']} "
        f"recoverable={d['flood_attack_volume_recoverable_via_drops']:.4f} "
        f"pearson_drop={d['flood_pearson_dropped_vs_attack']:.4f} "
        f"ks_drop={d['ks_dropped_flood_vs_baseline']:.4f}"
    )
    print("  claims_info_theoretic_leakage_bound=false")


if __name__ == "__main__":
    main()
