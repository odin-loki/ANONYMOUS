#!/usr/bin/env python3
"""Generate exit-tier defense ranking artifact (wave S4 / C2 extension).

CI-safe default is short; use --offline for longer horizons.
Not WAN closed; clearnet residual remains by design.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import exit_tier_defense as etd  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "exit_tier_defense.analysis.json"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    p.add_argument("--trials", type=int, default=120)
    p.add_argument("--n-clients", type=int, default=40)
    p.add_argument("--p-active", type=float, default=0.25)
    p.add_argument("--ci", action="store_true",
                   help="Skip offline section (fast CI regenerate).")
    p.add_argument("--offline", action="store_true",
                   help="Include offline E≤3200 (slower).")
    args = p.parse_args(argv)

    include_offline = bool(args.offline) and not args.ci
    report = etd.exit_tier_defense_report(
        n_clients=args.n_clients,
        p_active=args.p_active,
        trials=args.trials,
        include_curves=True,
        include_offline=include_offline,
    )
    etd.write_exit_tier_defense_artifact(args.output, report=report)
    rec = report["recommended"]
    base = report["metrics_at_decision_horizon"]["baseline"]
    long = report["metrics_at_long_horizon"]["baseline"]
    print(f"wrote {args.output}")
    print(
        f"  recommended={rec['scheme']} @E={report['decision_horizon']} "
        f"composite={rec.get('composite_risk', 'n/a')} "
        f"(baseline composite={base['composite_risk']})"
    )
    print(
        f"  decision p_sing={base['p_intersection_singleton']} "
        f"p_vol={base['p_volume_rank_top']}; "
        f"long E residual p_sing={long['p_intersection_singleton']}"
    )
    print("  wan_closed=false characterizes_not_closes=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
