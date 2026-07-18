#!/usr/bin/env python3
"""Emit optional cover-burst GPA timing artifact under sim/data/."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import cover_timing

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "cover_burst_gpa_characterization.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Partial GPA timing characterization (not indistinguishability proof)."
    )
    p.add_argument("--tau-secs", type=float, default=0.35)
    p.add_argument("--n-sends", type=int, default=4)
    p.add_argument("--cover-secs", type=float, default=2.0)
    p.add_argument("--relay-cover-bursts", type=int, default=1)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    comparison = cover_timing.compare_cover_modes(
        tau_secs=args.tau_secs,
        n_sends=args.n_sends,
        cover_secs=args.cover_secs,
        relay_cover_bursts_per_send=args.relay_cover_bursts,
    )
    cover_timing.write_characterization_artifact(args.output, comparison)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
