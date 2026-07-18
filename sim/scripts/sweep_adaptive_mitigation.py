#!/usr/bin/env python3
"""CI + offline characterization sweeps for adaptive guard mitigation (spec §13).

Does not regenerate combined_active_intersection artifacts.
Writes:
  sim/data/adaptive_mitigation_sweep.json
  sim/data/adaptive_mitigation_offline.json  (unless --ci-only)

Runtime: CI grid ~seconds; offline characterization typically <10 min.
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ci-only", action="store_true",
                    help="Only run the bounded CI param sweep (skip offline curve)")
    ap.add_argument("--offline-trials", type=int, default=6000,
                    help="Trials per offline epoch point (default 6000)")
    ap.add_argument("--ci-trials", type=int, default=2000,
                    help="Trials for CI sweep / CI-scale curve (default 2000)")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    sweep = adv.adaptive_mitigation_param_sweep(
        c=0.015, g=3, epochs=200, trials=args.ci_trials,
    )
    sweep_path = DATA / "adaptive_mitigation_sweep.json"
    sweep_path.write_text(json.dumps(sweep, indent=2) + "\n", encoding="utf-8")
    print("Wrote", sweep_path)
    print(
        f"  v2={sweep['v2_baseline']:.4f} v3={sweep['v3_default']:.4f} "
        f"best_grid={sweep['points'][0]['exposure']:.4f}"
    )

    if not args.ci_only:
        offline = adv.adaptive_mitigation_offline_characterization(
            c=0.015, g=3,
            epoch_grid=(50, 100, 200, 500, 800, 2000),
            trials_ci=min(2000, args.ci_trials),
            trials_offline=args.offline_trials,
        )
        offline_path = DATA / "adaptive_mitigation_offline.json"
        offline_path.write_text(json.dumps(offline, indent=2) + "\n", encoding="utf-8")
        print("Wrote", offline_path)
        s = offline["summary_at_200"]
        print(
            f"  offline E=200 adaptive={s['adaptive']:.4f} "
            f"v2={s['mitigated_v2']:.4f} v3={s['mitigated_v3']:.4f} "
            f"v2-v3={s['v3_improvement_vs_v2']:.4f}"
        )

    print(f"Done in {time.time() - t0:.1f}s - spec 13 still [O] (saturation residual)")


if __name__ == "__main__":
    main()
