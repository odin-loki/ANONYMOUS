#!/usr/bin/env python3
"""Emit metrics scrape defense ranking artifact under sim/data/ (wave A4/A5)."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import metrics_scrape_defense as msd

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "metrics_scrape_defense.analysis.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Partial metrics-scrape defense ranking "
            "(cadence / quantize / suppress drops vs C5 baseline Pearson)."
        )
    )
    p.add_argument("--quantize-bucket", type=int, default=msd.DEFAULT_QUANTIZE_BUCKET)
    p.add_argument("--attack-cells-per-sec", type=float, default=40.0)
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    report = msd.metrics_scrape_defense_report(
        quantize_bucket=args.quantize_bucket,
        attack_cells_per_sec=args.attack_cells_per_sec,
        seed=args.seed,
    )
    msd.write_metrics_scrape_defense_artifact(args.output, report=report)
    rec = report["recommended"]
    d = report["delta_vs_c5_baseline"]
    print(f"wrote {args.output}")
    print(
        f"  recommended={rec['scheme']} "
        f"fine_held={rec.get('fine_held_pearson_load_vs_attack')} "
        f"vol={rec.get('attack_volume_recoverable_via_drops')} "
        f"(c5_pearson={d['baseline_pearson_dropped_vs_attack']:.4f})"
    )
    print("  claims_info_theoretic_leakage_bound=false")


if __name__ == "__main__":
    main()
