#!/usr/bin/env python3
"""Generate fused/adaptive_v4 defense artifact (wave S5 / C2).

  cd sim && PYTHONPATH=. python scripts/run_fused_defense.py
  cd sim && PYTHONPATH=. python scripts/run_fused_defense.py --offline
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import fused_defense as fd  # noqa: E402

DATA = ROOT / "data"
CI_OUT = DATA / "fused_defense.analysis.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--offline", action="store_true",
                    help="Include offline E≤3200 fused defense curves")
    ap.add_argument("--trials", type=int, default=fd.CI_LONG_TRIALS)
    args = ap.parse_args()

    report = fd.fused_defense_report(
        trials=args.trials,
        include_offline=args.offline,
    )
    fd.write_fused_defense_artifact(CI_OUT, report=report)
    print("Wrote", CI_OUT)
    s = report["summary_at_long_horizon"]
    print(
        f"  E={s['E']} best={report['best_defense']} "
        f"mode1_reduction={s.get('mode1_confirm_reduction_vs_undefended')} "
        f"claim_closed={report['claim_closed']}"
    )


if __name__ == "__main__":
    main()
