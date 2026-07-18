#!/usr/bin/env python3
"""Emit faction/Sybil jurisdiction-skew artifact under sim/data/ (wave C3).

Does not close consortium governance. Legal vetting remains External.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis_sim import faction_sybil_skew as fss  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "faction_sybil_skew.json"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--ci-only",
        action="store_true",
        help="Bounded CI grid (default behavior; kept for symmetry with other sweeps)",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--client-seeds", type=int, default=200)
    p.add_argument("--path-trials", type=int, default=200)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    report = fss.ci_sweep(
        seed=args.seed,
        client_seeds=args.client_seeds,
        path_trials=args.path_trials,
    )
    out = fss.write_artifact(args.output, report)
    s = report.summary
    print(f"wrote {out}")
    print(
        f"  points={s['n_points']} "
        f"sybil_ok|faction>=M={s['mean_sybil_success_when_faction_ge_m']:.3f} "
        f"sybil_ok|faction<M={s['mean_sybil_success_when_faction_lt_m']:.3f}"
    )
    print("  claims_governance_closed=false legal_vetting=External")


if __name__ == "__main__":
    main()
