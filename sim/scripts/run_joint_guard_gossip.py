#!/usr/bin/env python3
"""Generate joint adaptive-guard × gossip-eclipse artifact (leftovers B3).

Reuses committed adaptive/gossip artifacts when present; live baselines via
public APIs. Use --offline for longer horizons. Does not close §13.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import joint_guard_gossip as jgg  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "joint_guard_gossip.analysis.json"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    p.add_argument("--trials", type=int, default=200)
    p.add_argument("--f", type=float, default=0.125, dest="f",
                   help="Peer-table adversary fraction (default 0.125 = boost-sensitive).")
    p.add_argument("--majority-k", type=int, default=2)
    p.add_argument("--ci", action="store_true",
                   help="Skip live baselines + defense + offline (fast).")
    p.add_argument("--offline", action="store_true",
                   help="Include offline E≤800 joint curves.")
    p.add_argument("--no-defense", action="store_true",
                   help="Skip stacked+v4 joint defense curve.")
    p.add_argument("--no-committed", action="store_true",
                   help="Do not embed committed baseline artifact numbers.")
    args = p.parse_args(argv)

    include_offline = bool(args.offline) and not args.ci
    include_live = not args.ci
    include_defense = (not args.no_defense) and not args.ci
    report = jgg.joint_guard_gossip_report(
        f=args.f,
        majority_k=args.majority_k,
        trials=args.trials,
        include_live_baselines=include_live,
        include_committed_baselines=not args.no_committed,
        include_joint_defense=include_defense,
        include_offline=include_offline,
        offline_trials=80 if include_offline else 0,
        data_dir=ROOT / "data",
    )
    jgg.write_joint_guard_gossip_artifact(args.output, report=report)
    cmp_ = report["comparison_at_long_horizon"]
    print(f"wrote {args.output}")
    print(
        f"  E={cmp_['E']} joint_union={cmp_['joint_p_union_success']:.3f} "
        f"gossip={cmp_['joint_p_gossip_success']:.3f} "
        f"adaptive_exp={cmp_['joint_p_adaptive_exposed']:.3f} "
        f"eclipse={cmp_['joint_p_eclipse_any']:.3f}"
    )
    print("  section_13_closed=false characterizes_not_closes=true field_residual=yes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
