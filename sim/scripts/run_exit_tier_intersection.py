#!/usr/bin/env python3
"""Generate exit-tier anonymity-set / intersection artifact (coverage C2).

CI-safe default is short; use --offline for ~5–10 min characterization.
Not WAN closed; clearnet residual remains by design.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import exit_tier_intersection as eti  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "exit_tier_intersection.analysis.json"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    p.add_argument("--trials", type=int, default=200)
    p.add_argument("--n-clients", type=int, default=40)
    p.add_argument("--p-active", type=float, default=0.25)
    p.add_argument("--ci", action="store_true",
                   help="Skip sensitivity/offline (fast CI regenerate).")
    p.add_argument("--offline", action="store_true",
                   help="Include offline E≤3200 (slower; ~minutes).")
    args = p.parse_args(argv)

    include_offline = bool(args.offline) and not args.ci
    include_sensitivity = not args.ci
    report = eti.exit_tier_report(
        n_clients=args.n_clients,
        p_active=args.p_active,
        trials=args.trials,
        include_sensitivity=include_sensitivity,
        include_offline=include_offline,
        offline_trials=100 if include_offline else 0,
    )
    eti.write_exit_tier_artifact(args.output, report=report)
    long = report["summary_at_long_horizon"]
    mid = report["curves"].get("50") or report["curves"].get(
        str(min(report["epoch_grid"]))
    )
    print(f"wrote {args.output}")
    print(
        f"  E={long['E']} mean_aset={long['mean_anonymity_set']:.3f} "
        f"p_singleton={long['p_intersection_singleton']:.3f} "
        f"p_vol_top={long['p_volume_rank_top']:.3f}"
    )
    if mid:
        print(
            f"  mid E=50 mean_iset={mid.get('mean_intersection_size')} "
            f"p_singleton={mid.get('p_intersection_singleton')}"
        )
    print("  wan_closed=false characterizes_not_closes=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
