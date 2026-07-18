#!/usr/bin/env python3
"""Emit multi-hop cover defense ranking artifact under sim/data/ (wave S4)."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import cover_multihop_defense as cmd

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "cover_multihop_defense.analysis.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Partial multi-hop cover defense ranking "
            "(cover onions / matched discard vs local discard baseline)."
        )
    )
    p.add_argument("--n-hops", type=int, default=3)
    p.add_argument("--n-sends", type=int, default=4)
    p.add_argument("--tau-secs", type=float, default=0.35)
    p.add_argument("--cover-secs", type=float, default=2.0)
    p.add_argument("--relay-cover-bursts", type=int, default=1)
    p.add_argument("--cover-onion-packets", type=int, default=2)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    report = cmd.cover_multihop_defense_report(
        n_hops=args.n_hops,
        n_sends=args.n_sends,
        tau_secs=args.tau_secs,
        cover_secs=args.cover_secs,
        relay_cover_bursts_per_hop=args.relay_cover_bursts,
        cover_onion_packets_per_send=args.cover_onion_packets,
    )
    cmd.write_cover_multihop_defense_artifact(args.output, report=report)
    rec = report["recommended"]
    d = report["delta_vs_baseline"]
    print(f"wrote {args.output}")
    print(
        f"  recommended={rec['scheme']} "
        f"continuity={rec.get('mean_implied_packet_continuity')} "
        f"(baseline={d['baseline_continuity']:.4f}, "
        f"sphinx_ref={d['sphinx_reference_continuity']})"
    )
    print("  claims_info_theoretic_indistinguishability=false")


if __name__ == "__main__":
    main()
