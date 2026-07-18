#!/usr/bin/env python3
"""Regenerate gossip eclipse / majority_k artifacts under sim/data/ (wave C1).

CI artifact is always written. Pass --offline for the denser characterization grid.

Examples:
  cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse.py
  cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse.py --offline
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import gossip_eclipse as ge  # noqa: E402

DATA = ROOT / "data"
CI_OUT = DATA / "gossip_eclipse.analysis.json"
OFFLINE_OUT = DATA / "gossip_eclipse_offline.json"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--offline",
        action="store_true",
        help="Also write denser offline characterization JSON.",
    )
    p.add_argument(
        "--ci-trials",
        type=int,
        default=ge.CI_TRIALS,
        help=f"Trials per CI cell (default {ge.CI_TRIALS}).",
    )
    p.add_argument(
        "--offline-trials",
        type=int,
        default=ge.OFFLINE_TRIALS,
        help=f"Trials per offline cell (default {ge.OFFLINE_TRIALS}).",
    )
    args = p.parse_args(argv)

    DATA.mkdir(parents=True, exist_ok=True)

    ci = ge.gossip_eclipse_report(
        trials=args.ci_trials,
        include_offline=False,
    )
    ge.write_artifact(CI_OUT, ci)
    _print_highlights("CI", ci)
    print(f"Wrote {CI_OUT}")

    if args.offline:
        off = ge.gossip_eclipse_report(
            f_grid=ge.OFFLINE_F_GRID,
            k_grid=ge.OFFLINE_K_GRID,
            n_grid=ge.OFFLINE_N_GRID,
            trials=args.offline_trials,
            epochs=ge.OFFLINE_EPOCHS,
            include_offline=False,
        )
        # Keep a dedicated offline file; status stays QUANTIFIED Partial.
        ge.write_artifact(OFFLINE_OUT, off)
        _print_highlights("offline", off)
        print(f"Wrote {OFFLINE_OUT}")

    print("status=[O] QUANTIFIED claim_closed=false multi_org_bft=External")
    return 0


def _print_highlights(label: str, report: dict) -> None:
    print(f"--- {label} highlights ---")
    for h in report.get("summary", {}).get("highlights", []):
        bias = h.get("mean_median_bias")
        fp = h.get("false_probation_rate")
        ecl = h.get("mean_eclipse_epoch_fraction")
        print(
            f"  N={h['n_neighbors']} f={h['f']} K={h['majority_k']}: "
            f"bias={bias:.3f} fp={fp:.3f} eclipse={ecl:.3f} "
            f"solo={h['can_solo_quorum']} — {h['note']}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
