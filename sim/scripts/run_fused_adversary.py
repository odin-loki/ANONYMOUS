#!/usr/bin/env python3
"""Generate fused adaptive∩active/intersection artifact (coverage C2).

Reuses committed adaptive/combined artifacts when present; live baselines via
public APIs. Use --offline for longer horizons (~5–10 min). Not WAN closed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import fused_adversary as fa  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "fused_adversary.analysis.json"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    p.add_argument("--trials", type=int, default=200)
    p.add_argument("--leaky-scheme", choices=("constant_only", "pad_up"),
                   default="constant_only")
    p.add_argument("--ci", action="store_true",
                   help="Skip live baselines + offline (fast).")
    p.add_argument("--offline", action="store_true",
                   help="Include offline E≤3200 fused curves.")
    p.add_argument("--no-committed", action="store_true",
                   help="Do not embed committed baseline artifact numbers.")
    args = p.parse_args(argv)

    include_offline = bool(args.offline) and not args.ci
    include_live = not args.ci
    report = fa.fused_adversary_report(
        leaky_scheme=args.leaky_scheme,
        trials=args.trials,
        include_live_baselines=include_live,
        include_committed_baselines=not args.no_committed,
        include_offline=include_offline,
        offline_trials=100 if include_offline else 0,
        data_dir=ROOT / "data",
    )
    fa.write_fused_adversary_artifact(args.output, report=report)
    cmp_ = report["comparison_at_long_horizon"]
    print(f"wrote {args.output}")
    print(
        f"  E={cmp_['E']} fused_union={cmp_['fused_p_union_success']:.3f} "
        f"fused_confirm={cmp_['fused_p_mode1_confirm']:.3f} "
        f"adaptive_exp={cmp_['fused_p_adaptive_exposed']:.3f}"
    )
    print("  wan_closed=false characterizes_not_closes=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
