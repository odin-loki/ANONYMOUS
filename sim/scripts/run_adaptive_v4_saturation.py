#!/usr/bin/env python3
"""Document adaptive_v4 vs v3 at E=200 / E=2000 (wave S5). Never claims §13 closed.

  cd sim && PYTHONPATH=. python scripts/run_adaptive_v4_saturation.py
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import adversaries as adv  # noqa: E402

DATA = ROOT / "data"
OUT = DATA / "adaptive_v4_saturation.analysis.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=4000,
                    help="Trials per (mode, E) point (CI-safe default 4000)")
    args = ap.parse_args()

    c, g = 0.015, 3
    grid = (200, 800, 2000)
    t0 = time.time()
    by_epochs = {}
    for e in grid:
        by_epochs[str(e)] = {
            "adaptive": adv.adaptive_guard_exposure(
                c, g, epochs=e, mode="adaptive", trials=args.trials,
            ),
            "mitigated_v3": adv.adaptive_guard_exposure(
                c, g, epochs=e, mode="mitigated_v3", trials=args.trials,
            ),
            "mitigated_v4": adv.adaptive_guard_exposure(
                c, g, epochs=e, mode="mitigated_v4", trials=args.trials,
            ),
        }
        row = by_epochs[str(e)]
        row["v4_improvement_vs_v3"] = row["mitigated_v3"] - row["mitigated_v4"]

    report = {
        "tag": "adaptive_v4_saturation_S5",
        "status": "[O] QUANTIFIED",
        "claim_closed": False,
        "characterizes_not_closes": True,
        "mitigation_partial_not_closed": True,
        "best_mitigation_preset": "adaptive_v4",
        "c": c,
        "g": g,
        "trials": args.trials,
        "epoch_grid": list(grid),
        "by_epochs": by_epochs,
        "mitigation_params_v3": adv._MITIGATION_V3,
        "mitigation_params_v4": adv._MITIGATION_V4,
        "metrics_vs_prior": {
            "focus": "E=2000 saturation residual",
            "v3_at_2000": by_epochs["2000"]["mitigated_v3"],
            "v4_at_2000": by_epochs["2000"]["mitigated_v4"],
            "v4_pp_gain_vs_v3_at_2000": by_epochs["2000"]["v4_improvement_vs_v3"],
            "v3_at_200": by_epochs["200"]["mitigated_v3"],
            "v4_at_200": by_epochs["200"]["mitigated_v4"],
        },
        "honest_limit": (
            "v4 lowers E=2000 exposure vs v3 in sim but does not close §13; "
            "field recompromise rates unmeasured."
        ),
        "elapsed_s": round(time.time() - t0, 2),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Wrote", OUT)
    m = report["metrics_vs_prior"]
    print(
        f"  E=2000 v3={m['v3_at_2000']:.4f} v4={m['v4_at_2000']:.4f} "
        f"gain={m['v4_pp_gain_vs_v3_at_2000']:.4f} "
        f"(§13 still open)"
    )


if __name__ == "__main__":
    main()
