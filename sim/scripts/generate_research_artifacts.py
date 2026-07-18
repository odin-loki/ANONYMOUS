#!/usr/bin/env python3
"""Regenerate spec §13 research JSON artifacts under sim/data/."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import adversaries as adv  # noqa: E402

DATA = ROOT / "data"


def main():
    adaptive = adv.adaptive_guard_exposure_curve(
        c=0.015, g=3,
        epoch_grid=(5, 20, 50, 100, 200, 500, 800, 2000),
        trials=20000,
    )
    combined = adv.combined_attack_report(
        M=30, s_rate=3.0, bg=8.0, Q=25, probe_frac=0.5,
        epoch_grid=(50, 100, 200, 400, 800, 1600),
        trials=200,
    )
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "adaptive_guard_exposure.analysis.json").write_text(
        json.dumps(adaptive, indent=2) + "\n", encoding="utf-8",
    )
    (DATA / "combined_active_intersection.analysis.json").write_text(
        json.dumps(combined, indent=2) + "\n", encoding="utf-8",
    )
    print("Wrote", DATA / "adaptive_guard_exposure.analysis.json")
    print("Wrote", DATA / "combined_active_intersection.analysis.json")


if __name__ == "__main__":
    main()
