#!/usr/bin/env python3
"""Generate gossip eclipse defense artifact (wave S5 / C1).

  cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse_defense.py
  cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse_defense.py --offline
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import gossip_eclipse_defense as ged  # noqa: E402

DATA = ROOT / "data"
CI_OUT = DATA / "gossip_eclipse_defense.analysis.json"
OFFLINE_OUT = DATA / "gossip_eclipse_defense_offline.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--offline", action="store_true",
                    help="Also write longer offline compare")
    ap.add_argument("--trials", type=int, default=ged.CI_TRIALS)
    ap.add_argument("--epochs", type=int, default=ged.CI_EPOCHS)
    args = ap.parse_args()

    report = ged.gossip_eclipse_defense_report(
        trials=args.trials,
        epochs=args.epochs,
        include_offline=False,
    )
    ged.write_artifact(CI_OUT, report=report)
    print("Wrote", CI_OUT)
    s = report.get("summary", {})
    stacked = s.get("stacked_at_f") or {}
    print(
        f"  best={report['best_defense']} "
        f"stacked_fp@0.5={stacked.get('false_probation_rate')} "
        f"delta_fp={stacked.get('delta_fp_vs_baseline')} "
        f"claim_closed={report['claim_closed']}"
    )

    if args.offline:
        off = ged.gossip_eclipse_defense_report(
            f_grid=ged.OFFLINE_F_GRID,
            trials=ged.OFFLINE_TRIALS,
            epochs=ged.OFFLINE_EPOCHS,
            include_offline=True,
        )
        ged.write_artifact(OFFLINE_OUT, report=off)
        print("Wrote", OFFLINE_OUT)


if __name__ == "__main__":
    main()
