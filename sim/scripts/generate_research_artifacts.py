#!/usr/bin/env python3
"""Regenerate spec §13 research JSON artifacts under sim/data/.

By default regenerates both adaptive-guard and combined-attack artifacts.
Use `--only combined` to avoid rewriting adaptive_guard ownership files.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import adversaries as adv  # noqa: E402
from aegis_sim.combined_active_intersection import (  # noqa: E402
    combined_attack_defense_report,
)

DATA = ROOT / "data"


def write_adaptive():
    # 15k trials: includes v3 curve; still CI-regenerable offline (~minutes, not hours).
    adaptive = adv.adaptive_guard_exposure_curve(
        c=0.015, g=3,
        epoch_grid=(5, 20, 50, 100, 200, 500, 800, 2000),
        trials=15000,
    )
    path = DATA / "adaptive_guard_exposure.analysis.json"
    path.write_text(json.dumps(adaptive, indent=2) + "\n", encoding="utf-8")
    print("Wrote", path)


def write_combined():
    # Full ranking + sensitivity + offline long horizon (still [O] QUANTIFIED).
    combined = combined_attack_defense_report(
        M=30, s_rate=3.0, bg=8.0, Q=25, probe_frac=0.5,
        epoch_grid=(50, 100, 200, 400, 800, 1600),
        trials=200,
        include_sensitivity=True,
        include_offline=True,
        sensitivity_trials=80,
        offline_trials=100,
    )
    path = DATA / "combined_active_intersection.analysis.json"
    path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")
    print("Wrote", path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        choices=("all", "combined", "adaptive"),
        default="all",
        help="Which artifact(s) to regenerate (default: all).",
    )
    args = parser.parse_args(argv)
    DATA.mkdir(parents=True, exist_ok=True)
    if args.only in ("all", "adaptive"):
        write_adaptive()
    if args.only in ("all", "combined"):
        write_combined()


if __name__ == "__main__":
    main()
